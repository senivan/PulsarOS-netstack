#!/usr/bin/env python3
"""Active ARP from a native UDP sender; run in an isolated Linux network namespace."""
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from scapy.all import ARP, IP, UDP, Ether, Raw
from smoke import ip


def main():
    local_ips = ["192.0.2.2", "198.51.100.2"]
    local_macs = ["02:00:00:00:00:02", "02:00:00:00:01:02"]
    peer_mac, peer_ip = "02:00:00:00:01:01", "198.51.100.1"
    process = None
    links = []
    try:
        with ExitStack() as resources, tempfile.TemporaryDirectory(prefix="netstack-arp-") as tmp:
            sockets = []
            for p in range(2):
                host, peer = f"ar-host{p}", f"ar-peer{p}"
                ip("link", "add", host, "type", "veth", "peer", "name", peer)
                links.append(host)
                for name, mac in ((host, local_macs[p]), (peer, peer_mac if p else "02:00:00:00:00:01")):
                    ip("link", "set", name, "addrgenmode", "none")
                    ip("link", "set", name, "address", mac)
                    ip("link", "set", name, "up")
                sock = resources.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
                sock.bind((peer, 0))
                sockets.append(sock)
            config = Path(tmp) / "stack.conf"
            config.write_text(f"lcore={min(os.sched_getaffinity(0))}\nno_huge=1\n" + "".join(
                f"[interface]\npmd=af_packet\ndevice=ar-host{p}\nip={local_ips[p]}/24\n" for p in range(2)))
            log_path = Path(tmp) / "stack.log"
            log = resources.enter_context(log_path.open("w+"))
            process = subprocess.Popen([sys.argv[1], str(config), peer_ip], stdout=log, stderr=log)
            sequence = []
            deadline = time.monotonic() + 15
            received = False
            while time.monotonic() < deadline and not received:
                readable, _, _ = select.select(sockets, [], [], 0.2)
                if not readable and process.poll() is not None:
                    raise AssertionError(log_path.read_text())
                for sock in readable:
                    packet = Ether(sock.recv(65535))
                    if packet.src not in local_macs:
                        continue
                    assert sock is sockets[1], "stack emitted on the wrong interface"
                    assert packet.src == local_macs[1]
                    if ARP in packet:
                        assert not sequence, "duplicate initial ARP request"
                        arp = packet[ARP]
                        assert packet.dst == "ff:ff:ff:ff:ff:ff"
                        assert arp.hwtype == 1 and arp.ptype == 0x800 and arp.hwlen == 6 and arp.plen == 4
                        assert arp.op == 1 and arp.hwsrc == local_macs[1]
                        assert arp.psrc == local_ips[1] and arp.pdst == peer_ip
                        assert arp.hwdst == "00:00:00:00:00:00"
                        sequence.append("ARP request")
                        sock.send(bytes(Ether(src=peer_mac, dst=local_macs[1]) /
                                        ARP(op=2, hwsrc=peer_mac, psrc=peer_ip,
                                            hwdst=local_macs[1], pdst=local_ips[1])))
                        sequence.append("ARP reply")
                    elif UDP in packet:
                        assert sequence == ["ARP request", "ARP reply"]
                        assert packet.dst == peer_mac and packet.type == 0x800
                        assert packet[IP].src == local_ips[1] and packet[IP].dst == peer_ip
                        assert packet[UDP].sport == 9000 and packet[UDP].dport == 9001
                        assert packet[UDP].len == 18
                        assert bytes(packet[UDP])[8:18] == b"active-arp"
                        rebuilt = IP(bytes(packet[IP])[:packet[IP].len])
                        del rebuilt.chksum
                        del rebuilt[UDP].chksum
                        rebuilt = IP(bytes(rebuilt))
                        assert rebuilt.chksum == packet[IP].chksum
                        assert rebuilt[UDP].chksum == packet[UDP].chksum != 0
                        sequence.append("UDP packet")
                        sock.send(bytes(Ether(src=peer_mac, dst=local_macs[1]) /
                                        IP(src=peer_ip, dst=local_ips[1]) /
                                        UDP(sport=9001, dport=9000) / Raw(b"active-arp")))
                        received = True
                    else:
                        raise AssertionError(packet.summary())
            assert received, log_path.read_text()
            assert process.wait(timeout=5) == 0, log_path.read_text()
            output = log_path.read_text()
            assert "transmitted packets: 2" in output, output
            print(output)
            print("silent peer: " + " -> ".join(sequence) + "; active ARP smoke passed")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for name in links:
            ip("link", "del", name)


if __name__ == "__main__":
    main()
