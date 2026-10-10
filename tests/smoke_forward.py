#!/usr/bin/env python3
"""Run in an isolated Linux network namespace with CAP_NET_ADMIN and CAP_SYS_ADMIN."""
import argparse
import os
import re
import select
import signal
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.utils import checksum


SERVER = r"""
import select, socket
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.bind(('0.0.0.0', 9000))
tcp.bind(('0.0.0.0', 9000))
tcp.listen(4)
print('ready', flush=True)
while True:
    readable, _, _ = select.select([udp, tcp], [], [])
    for sock in readable:
        if sock is udp:
            data, peer = udp.recvfrom(2048)
            udp.sendto(data, peer)
        else:
            conn, _ = tcp.accept()
            with conn:
                conn.settimeout(5)
                while True:
                    data = conn.recv(2048)
                    if not data: break
                    conn.sendall(data)
"""

CLIENT = r"""
import socket, struct, sys, time
destination, protocol = sys.argv[1:]
payload = b'namespace-forwarding-' + protocol.encode() + bytes(range(128))
if protocol == 'icmp':
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    request = struct.pack('!BBHHH', 8, 0, 0, 4242, 1) + payload
    padded = request + bytes(len(request) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(padded) // 2), padded))
    while total >> 16: total = (total & 65535) + (total >> 16)
    request = request[:2] + struct.pack('!H', (~total) & 65535) + request[4:]
    sock.settimeout(5)
    sock.sendto(request, (destination, 0))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        data, peer = sock.recvfrom(2048)
        offset = (data[0] & 15) * 4
        if peer[0] == destination and data[offset] == 0 and data[offset + 4:offset + 8] == request[4:8]:
            assert data[offset + 8:] == payload
            break
    else: raise AssertionError('no ICMP echo reply')
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((destination, 9000))
    sock.sendall(payload)
    response = b''
    while len(response) < len(payload):
        data = sock.recv(2048)
        assert data
        response += data
    assert response == payload
sock.close()
"""

CAPTURE = r"""
import socket, sys
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((sys.argv[1], 0))
print('ready', flush=True)
while True:
    print(sock.recv(65535).hex(), flush=True)
"""

A_IP, P_A = "192.0.2.1", "192.0.2.2"
LINK_PEER, P_B = "198.51.100.1", "198.51.100.2"
REMOTE_IP, G_B = "203.0.113.1", "203.0.113.2"
P_MACS = ["02:00:00:00:00:02", "02:00:00:00:01:02"]
PEER_MACS = ["02:00:00:00:00:01", "02:00:00:00:01:01"]


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class Namespace:
    def __init__(self, resources):
        self.process = subprocess.Popen(["unshare", "--net", "sleep", "infinity"])
        resources.callback(stop, self.process)
        self.path = f"/proc/{self.process.pid}/ns/net"
        deadline = time.monotonic() + 5
        while os.readlink(self.path) == os.readlink("/proc/self/ns/net"):
            assert self.process.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        self.run("ip", "link", "set", "lo", "up")
        self.run("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
        self.run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")

    def command(self, *args):
        return ["nsenter", f"--net={self.path}", *args]

    def run(self, *args):
        return run(*self.command(*args))

    def link(self, name, mac, address):
        self.run("ethtool", "-K", name, "tx", "off", "tso", "off", "gso", "off", "gro", "off")
        self.run("ip", "link", "set", name, "address", mac)
        self.run("ip", "link", "set", name, "up")
        self.run("ip", "addr", "add", address, "dev", name)


def wait_ready(process, log, marker):
    deadline = time.monotonic() + 15
    while marker not in log.read_text():
        assert process.poll() is None and time.monotonic() < deadline, log.read_text()
        time.sleep(0.05)


def verify_transit(packets, destination):
    inputs = {}
    outputs = []
    for interface, packet in packets:
        if IP not in packet or packet[IP].src not in (A_IP, destination) or packet[IP].dst not in (A_IP, destination):
            continue
        ip = packet[IP]
        raw = bytes(ip)[:ip.len]
        key = (ip.src, ip.dst, ip.id, ip.proto, raw[ip.ihl * 4:])
        if packet.src == P_MACS[interface]:
            outputs.append((interface, packet, key))
        else:
            inputs.setdefault(key, []).append((interface, packet))
    protocols = set()
    directions = set()
    for interface, packet, key in outputs:
        incoming = [(p, frame) for p, frame in inputs.get(key, []) if p != interface]
        assert incoming, packet.summary()
        before = incoming[0][1][IP]
        ip = packet[IP]
        # RFC 1812 5.3.1: one Pulsar hop, including a separate Linux gateway case.
        assert ip.ttl == before.ttl - 1 and checksum(bytes(ip)[:ip.ihl * 4]) == 0
        assert packet.dst == PEER_MACS[interface]
        assert ip.tos == before.tos and ip.flags == before.flags and ip.len == before.len
        if UDP in packet or TCP in packet:
            rebuilt = IP(bytes(ip)[:ip.len])
            layer = rebuilt[UDP] if UDP in packet else rebuilt[TCP]
            expected = layer.chksum
            del layer.chksum
            assert IP(bytes(rebuilt))[layer.__class__].chksum == expected
        elif ICMP in packet:
            assert checksum(bytes(ip)[ip.ihl * 4:ip.len]) == 0
        protocols.add(ip.proto)
        directions.add((ip.src, ip.dst))
    assert protocols == {1, 6, 17} and len(directions) == 2


def scenario(binary, name, directory):
    directory.mkdir(parents=True, exist_ok=True)
    gateway = name in ("gateway", "default")
    direct = name == "static-direct"
    failures = name == "errors"
    enabled = name != "disabled"
    destination = REMOTE_IP if gateway or direct else LINK_PEER
    packets = []
    stack = None
    log_path = directory / "stack.log"
    try:
        with ExitStack() as resources:
            run("sysctl", "-qw", "net.ipv4.ip_forward=0")
            run("sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
            a, b = Namespace(resources), Namespace(resources)
            peer = Namespace(resources) if gateway else b
            sockets = []
            for index, (namespace, endpoint) in enumerate(((a, "a0"), (peer, "g0" if gateway else "b0"))):
                host = f"fw{index}"
                run("ip", "link", "add", host, "type", "veth", "peer", "name", endpoint)
                resources.callback(subprocess.run, ["ip", "link", "del", host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                run("ip", "link", "set", endpoint, "netns", str(namespace.process.pid))
                run("ip", "link", "set", host, "addrgenmode", "none")
                run("ip", "link", "set", host, "address", P_MACS[index])
                if failures and index == 1:
                    run("ip", "link", "set", host, "mtu", "600")
                run("ip", "link", "set", host, "up")
                assert "inet " not in run("ip", "-4", "addr", "show", "dev", host).stdout
            a.link("a0", PEER_MACS[0], f"{A_IP}/24")
            a.run("ip", "route", "add", "default", "via", P_A)
            peer.link("g0" if gateway else "b0", PEER_MACS[1], f"{LINK_PEER}/24" if not direct else f"{REMOTE_IP}/32")
            if direct:
                b.run("ip", "route", "add", f"{P_B}/32", "dev", "b0")
            peer.run("ip", "route", "add", "default", "via", P_B)
            if gateway:
                run("ip", "link", "add", "g1", "type", "veth", "peer", "name", "b0")
                run("ip", "link", "set", "g1", "netns", str(peer.process.pid))
                run("ip", "link", "set", "b0", "netns", str(b.process.pid))
                peer.link("g1", "02:00:00:00:02:02", f"{G_B}/24")
                b.link("b0", "02:00:00:00:02:01", f"{REMOTE_IP}/24")
                b.run("ip", "route", "add", "default", "via", G_B)
                peer.run("sysctl", "-qw", "net.ipv4.ip_forward=1")
                peer.run("sysctl", "-qw", "net.ipv4.conf.all.send_redirects=0")
            for namespace, interface in ((a, "a0"), (peer, "g0" if gateway else "b0")):
                capture = subprocess.Popen(namespace.command("python3", "-u", "-c", CAPTURE, interface),
                                           stdout=subprocess.PIPE, bufsize=0)
                resources.callback(capture.stdout.close)
                resources.callback(stop, capture)
                assert select.select([capture.stdout], [], [], 5)[0]
                assert capture.stdout.readline() == b"ready\n"
                sockets.append(capture.stdout)
            route = ""
            if gateway:
                route = f"[route]\nprefix={'0.0.0.0/0' if name == 'default' else '203.0.113.0/24'}\ndevice=fw1\ngateway={LINK_PEER}\n"
            elif direct:
                route = "[route]\nprefix=203.0.113.0/24\ndevice=fw1\n"
            config = directory / "stack.conf"
            config.write_text(f"lcore={min(os.sched_getaffinity(0))}\nno_huge=1\nipv4_forwarding={int(enabled)}\n" + "".join(
                f"[interface]\npmd=af_packet\ndevice=fw{p}\nip={ip}/24\n" for p, ip in enumerate((P_A, P_B))) + route)
            log = resources.enter_context(log_path.open("w"))
            stack = subprocess.Popen([binary, str(config)], stdout=log, stderr=log)
            resources.callback(stop, stack)
            wait_ready(stack, log_path, "entering host input loop")

            def receive(predicate=None, timeout=0.3):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    assert stack.poll() is None, log_path.read_text()
                    ready, _, _ = select.select(sockets, [], [], min(0.1, max(0, deadline - time.monotonic())))
                    for sock in ready:
                        frame = Ether(bytes.fromhex(sock.readline().decode()))
                        packets.append((sockets.index(sock), frame))
                        if predicate and predicate(frame):
                            return frame
                assert predicate is None, log_path.read_text()

            def inject(frame):
                a.run("python3", "-c", "import socket,sys; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(('a0',0)); s.send(bytes.fromhex(sys.argv[1]))", bytes(frame).hex())

            if enabled and not failures:
                for endpoint, label in ((a, "a"), (b, "b")):
                    server_log = directory / f"{label}.log"
                    stream = resources.enter_context(server_log.open("w"))
                    server = subprocess.Popen(endpoint.command("python3", "-u", "-c", SERVER), stdout=stream, stderr=stream)
                    resources.callback(stop, server)
                    wait_ready(server, server_log, "ready")
                for endpoint, target in ((a, destination), (b, A_IP)):
                    for protocol in ("icmp", "udp", "tcp"):
                        try:
                            endpoint.run("python3", "-c", CLIENT, target, protocol)
                        finally:
                            receive()
                receive()
                verify_transit(packets, destination)
                requests = [frame[ARP] for index, frame in packets if index == 1 and ARP in frame and
                            frame.src == P_MACS[1] and frame[ARP].op == 1]
                assert requests and all(arp.pdst == (LINK_PEER if gateway else destination) for arp in requests)
                assert all(arp.psrc == P_B for arp in requests)
            elif failures:
                inject(Ether(src=PEER_MACS[0], dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=1, hwsrc=PEER_MACS[0], psrc=A_IP, pdst=P_A))
                receive(lambda frame: ARP in frame and frame[ARP].op == 2 and frame.src == P_MACS[0], 5)

                def failure(ip, type_, code, mtu=0, timeout=5):
                    sent = IP(bytes(ip))
                    inject(Ether(src=PEER_MACS[0], dst=P_MACS[0]) / sent)
                    reply = receive(lambda frame: ICMP in frame and frame[ICMP].type == type_ and
                                    frame[ICMP].code == code and frame.src == P_MACS[0], timeout)
                    assert reply[IP].src == P_A and reply[IP].dst == A_IP and reply[IP].ttl == 64
                    assert checksum(bytes(reply[IP])[:20]) == 0
                    assert checksum(bytes(reply[ICMP])[:reply[IP].len - 20]) == 0
                    quote = bytes(reply[ICMP].payload)[:reply[IP].len - 28]
                    expected = IP(bytes(sent))
                    if timeout > 5:
                        expected.ttl -= 1
                        del expected.chksum
                    assert quote == bytes(expected)[:len(quote)]
                    if mtu:
                        assert reply[ICMP].nexthopmtu == mtu
                    return sent.id

                # RFC 1812 TTL/errors; RFC 1191 reports the egress MTU for DF traffic.
                failed_ids = [failure(IP(src=A_IP, dst=destination, ttl=ttl, id=7000+ttl) / ICMP() / Raw(b"ttl"), 11, 0)
                              for ttl in (0, 1)]
                failed_ids.append(failure(IP(src=A_IP, dst="10.77.0.1", id=7002) / UDP() / Raw(b"route"), 3, 0))
                failed_ids.append(failure(IP(src=A_IP, dst=destination, flags="DF", id=7003) / UDP() / Raw(bytes(650)), 3, 4, 600))
                inject(Ether(src=PEER_MACS[0], dst=P_MACS[0]) /
                       IP(src=A_IP, dst=destination, flags=0, id=7004) / UDP() / Raw(bytes(650)))
                receive()
                failed_ids.append(7004)
                failed_ids.append(failure(IP(src=A_IP, dst="198.51.100.99", id=7005, proto=99) / Raw(b"silent"), 3, 1, timeout=8))
                receive()
                assert not any(index == 1 and IP in frame and frame.src == P_MACS[1] and
                               frame[IP].src == A_IP and frame[IP].id in failed_ids for index, frame in packets)
                requests = [frame for index, frame in packets if index == 1 and ARP in frame and
                            frame.src == P_MACS[1] and frame[ARP].pdst == "198.51.100.99"]
                assert len(requests) == 3
            else:
                inject(Ether(src=PEER_MACS[0], dst=P_MACS[0]) /
                       IP(src=A_IP, dst=destination, proto=99, id=8000) / Raw(b"disabled"))
                receive(timeout=0.5)
                assert not any(frame.src in P_MACS for _, frame in packets)
            receive()
            stack.send_signal(signal.SIGTERM)
            assert stack.wait(timeout=5) == 0, log_path.read_text()
            output = log_path.read_text()
            assert "AddressSanitizer" not in output and "runtime error:" not in output, output
            expected = {"ttl_expired": 2, "no_route": 1, "mtu": 2, "neighbour_resolution_timeout": 1} if failures else (
                {"forwarding_disabled": 1} if not enabled else {})
            for reason, count in expected.items():
                assert re.search(rf"^\s+{reason}\s+{count}$", output, re.MULTILINE), output
            if enabled and not failures:
                assert "ICMP errors: generated=0 suppressed=0 rate_limited=0 failed=0" in output, output
                for reason in ("no_route", "mtu", "ttl_expired", "forwarding_disabled", "neighbour_resolution_timeout"):
                    assert not re.search(rf"^\s+{reason}\s+", output, re.MULTILINE), output
            if failures:
                assert "mtu 600, one RX/TX queue" in output, output
                assert "ICMP errors: generated=5 suppressed=0 rate_limited=0 failed=0" in output, output
            print(f"{name}: namespace routing, packet verification and counters passed")
    finally:
        for interface in (0, 1):
            frames = [frame for p, frame in packets if p == interface]
            if frames:
                wrpcap(str(directory / f"port{interface}.pcap"), frames)
        if stack is not None and stack.returncode not in (None, 0):
            print(log_path.read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="netstack-forward-") as temporary:
        artifacts = args.artifacts or Path(temporary)
        for name in ("connected", "static-direct", "gateway", "default", "errors", "disabled"):
            scenario(str(Path(args.binary).resolve()), name, artifacts / name)
    print("IPv4 forwarding namespace smoke passed")


if __name__ == "__main__":
    main()
