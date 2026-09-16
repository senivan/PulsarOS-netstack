#!/usr/bin/env python3
"""Run in an isolated Linux network namespace/container with CAP_NET_ADMIN."""
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from scapy.all import ARP, ICMP, IP, UDP, Ether, Raw


def ip(*args):
    subprocess.run(["ip", *args], check=True, capture_output=True)


def receive(sock, predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if readable:
            packet = Ether(sock.recv(65535))
            if predicate(packet):
                return packet
    raise AssertionError("timed out waiting for reply")


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "/build/netstack-dp"
    test_udp = "--udp" in sys.argv
    host_mac, peer_mac = "02:00:00:00:00:02", "02:00:00:00:00:01"
    process = None
    ip("link", "add", "ns-host", "type", "veth", "peer", "name", "ns-peer")
    try:
        for name, mac in (("ns-host", host_mac), ("ns-peer", peer_mac)):
            ip("link", "set", name, "address", mac)
            ip("link", "set", name, "up")
        with tempfile.TemporaryDirectory(prefix="netstack-smoke-") as tmp:
            config = Path(tmp) / "stack.conf"
            config.write_text(f"lcore={min(os.sched_getaffinity(0))}\npmd=af_packet\n"
                              "device=ns-host\nip=192.0.2.2/24\nno_huge=1\n")
            log_path = Path(tmp) / "stack.log"
            with log_path.open("w+") as log, socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                                         socket.htons(3)) as sock:
                sock.bind(("ns-peer", 0))
                process = subprocess.Popen([binary, str(config)], stdout=log, stderr=log)
                deadline = time.monotonic() + 15
                while "entering host input loop" not in log_path.read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(log_path.read_text())
                    time.sleep(0.05)
                sock.send(bytes(Ether(src=peer_mac, dst="ff:ff:ff:ff:ff:ff") /
                                ARP(op=1, hwsrc=peer_mac, psrc="192.0.2.1", pdst="192.0.2.2")))
                reply = receive(sock, lambda p: ARP in p and p[ARP].op == 2)
                assert reply.src == host_mac and reply.dst == peer_mac
                assert reply[ARP].psrc == "192.0.2.2" and reply[ARP].pdst == "192.0.2.1"
                payload = b"PulsarOS echo payload"  # odd-length checksum coverage
                request = (Ether(src=peer_mac, dst=host_mac) /
                           IP(src="192.0.2.1", dst="192.0.2.2", ttl=1) /
                           ICMP(type=8, id=123, seq=456) / Raw(payload))
                sock.send(bytes(request))
                reply = receive(sock, lambda p: ICMP in p and p[ICMP].type == 0)
                assert reply.src == host_mac and reply.dst == peer_mac
                assert reply[IP].src == "192.0.2.2" and reply[IP].dst == "192.0.2.1"
                assert reply[IP].ttl == 64 and reply[ICMP].id == 123 and reply[ICMP].seq == 456
                assert bytes(reply[ICMP].payload) == payload
                rebuilt = reply[IP].copy()
                del rebuilt.chksum
                del rebuilt[ICMP].chksum
                rebuilt = IP(bytes(rebuilt))
                assert rebuilt.chksum == reply[IP].chksum
                assert rebuilt[ICMP].chksum == reply[ICMP].chksum
                request[IP].chksum = 0x1234
                sock.send(bytes(request))
                try:
                    receive(sock, lambda p: ICMP in p and p[ICMP].type == 0, timeout=0.3)
                except AssertionError:
                    pass
                else:
                    raise AssertionError("replied to corrupt IPv4 checksum")
                sent = 2
                if test_udp:
                    for data in (b"", b"hello-netstack", bytes(range(256))):
                        datagram = (Ether(src=peer_mac, dst=host_mac) /
                                    IP(src="192.0.2.1", dst="192.0.2.2", id=50000) /
                                    UDP(sport=50001, dport=9000) / Raw(data))
                        sock.send(bytes(datagram))
                        reply = receive(sock, lambda p: UDP in p and p[UDP].sport == 9000)
                        assert reply.src == host_mac and reply.dst == peer_mac
                        assert reply[IP].src == "192.0.2.2" and reply[IP].dst == "192.0.2.1"
                        assert reply[IP].id != 50000 and reply[IP].ttl == 64
                        assert reply[UDP].dport == 50001 and reply[UDP].len == 8 + len(data)
                        assert bytes(reply[UDP])[8:reply[UDP].len] == data
                        rebuilt = IP(bytes(reply[IP])[:reply[IP].len])
                        del rebuilt.chksum
                        del rebuilt[UDP].chksum
                        rebuilt = IP(bytes(rebuilt))
                        assert rebuilt.chksum == reply[IP].chksum
                        assert rebuilt[UDP].chksum == reply[UDP].chksum != 0
                        sent += 1
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=5) == 0
                output = log_path.read_text()
                assert "invalid_ipv4" in output and f"transmitted packets: {sent}" in output, output
                print(output)
                print("AF_PACKET startup, ARP, ICMP, invalid IPv4 and shutdown smoke passed")
                if test_udp:
                    print("native UDP echo, empty datagram and software checksums passed")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        ip("link", "del", "ns-host")


if __name__ == "__main__":
    main()
