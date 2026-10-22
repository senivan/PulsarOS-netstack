#!/usr/bin/env python3
"""Run in an isolated Linux network namespace with CAP_NET_ADMIN."""
import argparse
import os
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.utils import checksum
from smoke import ip

CLIENT = r"""
import socket
try:
    socket.create_connection(('192.0.2.2', 9001), timeout=15)
except ConnectionRefusedError:
    pass
else:
    raise AssertionError('closed port did not reset')
for size in (32768, 1, 5000):
    payload = bytes(i % 256 for i in range(size))
    with socket.create_connection(('192.0.2.2', 9000), timeout=15) as sock:
        sock.settimeout(15)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        response = b''
        while True:
            data = sock.recv(4096)
            if not data: break
            response += data
        assert response == payload, (len(response), len(payload))
print('Linux connect, echo, peer close and closed-port ECONNREFUSED passed', flush=True)
"""
SERVER = r"""
import socket
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('192.0.2.1', 9001))
    server.listen(1)
    print('ready', flush=True)
    conn, _ = server.accept()
    with conn:
        conn.settimeout(15)
        total = 0
        while True:
            data = conn.recv(4096)
            if not data: break
            total += len(data)
            conn.sendall(data)
        assert total == 5000, total
print('Pulsar active open, echo and local FIN passed', flush=True)
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('initiator')
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    packets, processes, links, sockets = [], [], [], []
    lost = dict(synack=0, data=0, fin=0)
    with tempfile.TemporaryDirectory(prefix='netstack-tcp-') as tmp:
        artifacts = args.artifacts or Path(tmp)
        artifacts.mkdir(parents=True, exist_ok=True)
        config = artifacts / 'stack.conf'
        config.write_text(f'lcore={min(os.sched_getaffinity(0))}\nno_huge=1\n'
                          '[interface]\npmd=af_packet\ndevice=tc-host\nip=192.0.2.2/24\n')
        try:
            for left, right in (('tc-host', 'tc-wire'), ('tc-peer', 'tc-relay')):
                ip('link', 'add', left, 'type', 'veth', 'peer', 'name', right)
                links.append(left)
                for name in (left, right):
                    ip('link', 'set', name, 'mtu', '600')
                    ip('link', 'set', name, 'up')
                    subprocess.run(['ethtool', '-K', name, 'tx', 'off', 'rx', 'off'], check=True, capture_output=True)
            ip('link', 'set', 'tc-host', 'address', '02:00:00:00:00:02')
            ip('link', 'set', 'tc-peer', 'address', '02:00:00:00:00:01')
            ip('addr', 'add', '192.0.2.1/24', 'dev', 'tc-peer')
            for name in ('tc-wire', 'tc-relay'):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                sock.bind((name, 0))
                sockets.append(sock)

            def pump(deadline, drop):
                if time.monotonic() > deadline:
                    raise AssertionError('TCP smoke timed out')
                readable, _, _ = select.select(sockets, [], [], 0.02)
                for sock in readable:
                    raw, address = sock.recvfrom(65535)
                    if address[2] == socket.PACKET_OUTGOING:
                        continue
                    frame = Ether(raw)
                    if frame.type not in (0x800, 0x806):
                        continue
                    packets.append(frame)
                    if IP in frame and TCP in frame:
                        iphdr = frame[IP]
                        tcp = frame[TCP]
                        segment = bytes(iphdr)[iphdr.ihl * 4:iphdr.len]
                        pseudo = socket.inet_aton(iphdr.src) + socket.inet_aton(iphdr.dst)
                        assert checksum(bytes(iphdr)[:iphdr.ihl * 4]) == 0
                        assert checksum(pseudo + struct.pack('!BBH', 0, 6, len(segment)) + segment) == 0
                        assert iphdr.len <= 600
                        if drop and sock is sockets[0]:
                            kind = 'synack' if tcp.flags & 0x12 == 0x12 else (
                                'data' if len(segment) > tcp.dataofs * 4 else ('fin' if tcp.flags & 1 else None))
                            if kind and not lost[kind]:
                                lost[kind] = 1
                                continue
                    sockets[1 if sock is sockets[0] else 0].send(raw)

            with (artifacts / 'server.log').open('w+') as log:
                server = subprocess.Popen([args.binary, str(config)], stdout=log, stderr=log)
                processes.append(server)
                deadline = time.monotonic() + 60
                while 'entering host input loop' not in (artifacts / 'server.log').read_text():
                    assert server.poll() is None, (artifacts / 'server.log').read_text()
                    pump(deadline, True)
                with (artifacts / 'client.log').open('w+') as client_log:
                    client = subprocess.Popen(['python3', '-c', CLIENT], stdout=client_log, stderr=client_log)
                    processes.append(client)
                    while client.poll() is None:
                        assert server.poll() is None, (artifacts / 'server.log').read_text()
                        pump(deadline, True)
                    assert client.returncode == 0, (artifacts / 'client.log').read_text()
                for _ in range(10):
                    pump(deadline, True)
                assert all(lost.values()), lost
                server.send_signal(signal.SIGTERM)
                assert server.wait(timeout=5) == 0, (artifacts / 'server.log').read_text()
                output = (artifacts / 'server.log').read_text()
                assert 'timeouts=0' in output and 'established=3' in output, output
                assert 'retransmissions=0' not in output, output

            with (artifacts / 'linux-server.log').open('w+') as linux_log:
                linux = subprocess.Popen(['python3', '-c', SERVER], stdout=linux_log, stderr=linux_log)
                processes.append(linux)
                deadline = time.monotonic() + 30
                while 'ready' not in (artifacts / 'linux-server.log').read_text():
                    assert linux.poll() is None
                    pump(deadline, False)
                with (artifacts / 'initiator.log').open('w+') as initiator_log:
                    initiator = subprocess.Popen([args.initiator, str(config), '192.0.2.1'],
                                                 stdout=initiator_log, stderr=initiator_log)
                    processes.append(initiator)
                    while initiator.poll() is None:
                        pump(deadline, False)
                    assert initiator.returncode == 0, (artifacts / 'initiator.log').read_text()
                assert linux.wait(timeout=5) == 0, (artifacts / 'linux-server.log').read_text()
            print('TCP namespace smoke passed: Linux echo, active open, RST, MTU 600, SYN+ACK/data/FIN loss')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            for sock in sockets:
                sock.close()
            for link in links:
                ip('link', 'del', link)
            if packets:
                wrpcap(str(artifacts / 'wire.pcap'), packets)


if __name__ == '__main__':
    main()
