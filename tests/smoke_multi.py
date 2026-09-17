#!/usr/bin/env python3
"""Run with udp-echo in an isolated Linux network namespace with CAP_NET_ADMIN."""
import os
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from scapy.all import ARP, ICMP, IP, UDP, Ether, Raw
from smoke import ip, receive


def no_reply(sockets, predicate):
    deadline = time.monotonic() + 0.3
    while time.monotonic() < deadline:
        readable, _, _ = select.select(sockets, [], [], max(0, deadline - time.monotonic()))
        for sock in readable:
            packet = Ether(sock.recv(65535))
            assert not predicate(packet), packet.summary()


def main():
    binary = sys.argv[1]
    local_ips = ["192.0.2.2", "198.51.100.2"]
    peer_ips = ["192.0.2.1", "198.51.100.1"]
    local_macs = ["02:00:00:00:00:02", "02:00:00:00:01:02"]
    peer_macs = ["02:00:00:00:00:01", "02:00:00:00:01:01"]
    created = []
    process = None
    try:
        with ExitStack() as resources, tempfile.TemporaryDirectory(prefix="netstack-multi-") as tmp:
            sockets = []
            for p in range(2):
                host, peer = f"ms-host{p}", f"ms-peer{p}"
                ip("link", "add", host, "type", "veth", "peer", "name", peer)
                created.append(host)
                for name, mac in ((host, local_macs[p]), (peer, peer_macs[p])):
                    ip("link", "set", name, "address", mac)
                    ip("link", "set", name, "up")
                sock = resources.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
                sock.bind((peer, 0))
                sockets.append(sock)
            config = Path(tmp) / "stack.conf"
            config.write_text(f"lcore={min(os.sched_getaffinity(0))}\nno_huge=1\n" + "".join(
                f"[interface]\npmd=af_packet\ndevice=ms-host{p}\nip={local_ips[p]}/24\n" for p in range(2)))
            log_path = Path(tmp) / "stack.log"
            log = resources.enter_context(log_path.open("w+"))
            process = subprocess.Popen([binary, str(config)], stdout=log, stderr=log)
            deadline = time.monotonic() + 15
            while "entering host input loop" not in log_path.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(log_path.read_text())
                time.sleep(0.05)
            assert "initialized 2 DPDK ports" in log_path.read_text()
            for p, sock in enumerate(sockets):
                sock.send(bytes(Ether(src=peer_macs[p], dst="ff:ff:ff:ff:ff:ff") /
                                ARP(op=1, hwsrc=peer_macs[p], psrc=peer_ips[p], pdst=local_ips[p])))
                reply = receive(sock, lambda packet: ARP in packet and packet[ARP].op == 2)
                assert reply.src == reply[ARP].hwsrc == local_macs[p]
                assert reply.dst == peer_macs[p]
                assert reply[ARP].psrc == local_ips[p] and reply[ARP].pdst == peer_ips[p]
                sock.send(bytes(Ether(src=peer_macs[p], dst="ff:ff:ff:ff:ff:ff") /
                                ARP(op=1, hwsrc=peer_macs[p], psrc=peer_ips[p], pdst=local_ips[1-p])))
                no_reply(sockets, lambda packet: ARP in packet and packet[ARP].op == 2)
                for target in (local_ips[p], local_ips[1-p]):
                    sock.send(bytes(Ether(src=peer_macs[p], dst=local_macs[p]) /
                                    IP(src=peer_ips[p], dst=target, ttl=1) / ICMP(id=100+p) / Raw(b"multi-icmp")))
                    reply = receive(sock, lambda packet: ICMP in packet and packet[ICMP].type == 0)
                    assert reply.src == local_macs[p] and reply.dst == peer_macs[p]
                    assert reply[IP].src == target and reply[IP].dst == peer_ips[p]
                    assert reply[ICMP].id == 100+p
                    assert bytes(reply[ICMP])[8:reply[IP].len-20] == b"multi-icmp"
                    rebuilt = IP(bytes(reply[IP])[:reply[IP].len])
                    del rebuilt.chksum
                    del rebuilt[ICMP].chksum
                    rebuilt = IP(bytes(rebuilt))
                    assert rebuilt.chksum == reply[IP].chksum
                    assert rebuilt[ICMP].chksum == reply[ICMP].chksum
                sock.send(bytes(Ether(src=peer_macs[p], dst=local_macs[1-p]) /
                                IP(src=peer_ips[p], dst=local_ips[p]) / ICMP()))
                no_reply(sockets, lambda packet: ICMP in packet and packet[ICMP].type == 0)
                for protocol in (ICMP(id=333), UDP(sport=50001, dport=9000)):
                    sock.send(bytes(Ether(src=peer_macs[p], dst=local_macs[p]) /
                                    IP(src=peer_ips[p], dst=peer_ips[1-p]) / protocol / Raw(b"no-forward")))
                    no_reply(sockets, lambda packet: IP in packet and packet.src in local_macs)

            for payload in (b"", b"multi-interface", bytes(range(256)), bytes(1472)):
                for p, sock in enumerate(sockets):
                    sock.send(bytes(Ether(src=peer_macs[p], dst=local_macs[p]) /
                                    IP(src=peer_ips[p], dst=local_ips[p], id=50000) /
                                    UDP(sport=50001+p, dport=9000) / Raw(payload)))
                for p, sock in enumerate(sockets):
                    reply = receive(sock, lambda packet: UDP in packet and packet[UDP].sport == 9000)
                    assert reply.src == local_macs[p] and reply.dst == peer_macs[p]
                    assert reply[IP].src == local_ips[p] and reply[IP].dst == peer_ips[p]
                    assert reply[IP].id != 50000 and reply[IP].ttl == 64
                    assert reply[UDP].dport == 50001+p
                    assert reply[UDP].len == 8 + len(payload)
                    assert bytes(reply[UDP])[8:reply[UDP].len] == payload
                    rebuilt = IP(bytes(reply[IP])[:reply[IP].len])
                    del rebuilt.chksum
                    del rebuilt[UDP].chksum
                    rebuilt = IP(bytes(rebuilt))
                    assert rebuilt.chksum == reply[IP].chksum
                    assert rebuilt[UDP].chksum == reply[UDP].chksum != 0
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0
            output = log_path.read_text()
            assert re.search(r"^\s+forwarding_disabled\s+4$", output, re.MULTILINE), output
            assert "transmitted packets: 14" in output, output
            for p in range(2):
                assert f"interface {p} (DPDK {p}):" in output, output
            print(output)
            print("two-interface ARP, ICMP, UDP, route selection and forwarding rejection passed")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for name in created:
            ip("link", "del", name)


if __name__ == "__main__":
    main()
