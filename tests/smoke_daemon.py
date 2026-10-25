#!/usr/bin/env python3
"""One daemon, independent applications, real Linux peers; run with unshare --net."""
import argparse
import errno
import os
import signal
import socket
import struct
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from daemon_helpers import Daemon
from smoke import ip
from smoke_forward import Namespace, CLIENT as NETWORK_CLIENT, stop as stop_process

MAGIC, VERSION, MAX_DATA = 0x50534e53, 1, 8192


def frame(op, request_id, *, fd=0, a=0, b=0, c=0, port=0, address=0, payload=b''):
    return struct.pack('!16I', MAGIC, VERSION, op, request_id, len(payload), fd & 0xffffffff,
                       a & 0xffffffff, b & 0xffffffff, c & 0xffffffff, address, port, 0, 0, 0, 0, 0) + payload


def read_exact(sock, size):
    result = b''
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise ConnectionResetError('daemon disconnected')
        result += data
    return result


class IPC:
    def __init__(self, path, fragmented=False):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(path)
        self.request_id = 0
        try:
            assert self.call(1, fragmented=fragmented)[0] == 0
        except BaseException:
            self.sock.close()
            raise

    def call(self, op, *, fragmented=False, **kwargs):
        self.request_id += 1
        data = frame(op, self.request_id, **kwargs)
        if fragmented:
            for offset in range(0, len(data), 7):
                self.sock.sendall(data[offset:offset + 7])
        else:
            self.sock.sendall(data)
        header = read_exact(self.sock, 64)
        words = struct.unpack('!16I', header)
        assert words[:4] == (MAGIC, VERSION, op, self.request_id)
        assert words[4] <= MAX_DATA
        result = struct.unpack('!i', header[44:48])[0]
        payload = read_exact(self.sock, words[4])
        return result, payload

    def create(self, kind=2):
        return self.call(2, a=2, b=kind)[0]

    def bind(self, fd, port):
        return self.call(3, fd=fd, port=port)[0]

    def close(self):
        self.sock.close()


def udp_echo(port):
    payload = bytes(range(256)) * 4 + b'ipc-udp'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(5)
        peer.connect(('192.0.2.2', port))
        peer.send(payload)
        assert peer.recv(2048) == payload


def tcp_echo(port):
    payload = bytes(range(256)) * 64
    with socket.create_connection(('192.0.2.2', port), timeout=10) as peer:
        peer.settimeout(10)
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        response = b''
        while True:
            data = peer.recv(4096)
            if not data:
                break
            response += data
        assert response == payload


def wait_rebind(path, port):
    probe = IPC(path)
    try:
        fd = probe.create()
        deadline = time.monotonic() + 5
        while True:
            result = probe.bind(fd, port)
            if not result:
                break
            assert result == -errno.EADDRINUSE and time.monotonic() < deadline, result
            time.sleep(0.01)
        assert probe.call(11, fd=fd)[0] == 0
    finally:
        probe.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    with tempfile.TemporaryDirectory(prefix='pulsaros-daemon-') as tmp, ExitStack() as resources:
        directory = args.artifacts or Path(tmp)
        directory.mkdir(parents=True, exist_ok=True)
        subprocess.run(['sysctl', '-qw', 'net.ipv4.ip_forward=0'], check=True)
        subprocess.run(['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1'], check=True)
        remote = Namespace(resources)
        for i in range(2):
            host, peer = f'dm-host{i}', f'dm-peer{i}'
            ip('link', 'add', host, 'type', 'veth', 'peer', 'name', peer)
            resources.callback(subprocess.run, ['ip', 'link', 'del', host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ip('link', 'set', host, 'addrgenmode', 'none')
            ip('link', 'set', host, 'up')
            if i:
                ip('link', 'set', peer, 'netns', str(remote.process.pid))
                remote.link(peer, '02:00:00:00:01:01', '198.51.100.1/24')
                remote.run('ip', 'route', 'add', '192.0.2.0/24', 'via', '198.51.100.2')
            else:
                ip('link', 'set', peer, 'addrgenmode', 'none')
                ip('link', 'set', peer, 'up')
                ip('addr', 'add', '192.0.2.1/24', 'dev', peer)
                subprocess.run(['ethtool', '-K', peer, 'tx', 'off', 'rx', 'off'], check=True, capture_output=True)
                ip('route', 'add', '198.51.100.0/24', 'via', '192.0.2.2')
        config = directory / 'stack.conf'
        config.write_text(f'lcore={min(os.sched_getaffinity(0))}\nno_huge=1\nipv4_forwarding=1\n' + ''.join(
            f'[interface]\npmd=af_packet\ndevice=dm-host{i}\nip={address}/24\n'
            for i, address in enumerate(('192.0.2.2', '198.51.100.2'))))
        log = resources.enter_context((directory / 'daemon.log').open('w+'))
        daemon = Daemon(build / 'pulsarosd', config, log)
        resources.callback(daemon.stop, False)
        original_pid = daemon.process.pid
        first = daemon.client(build / 'udp-echo', 9000)
        second = daemon.client(build / 'udp-echo', 9001)
        tcp = daemon.client(build / 'tcp-echo', 8000)

        def forwarding():
            subprocess.run(['python3', '-c', NETWORK_CLIENT, '198.51.100.1', 'icmp'], check=True, capture_output=True, timeout=10)
            assert daemon.process.pid == original_pid and daemon.process.poll() is None

        udp_echo(9000)
        udp_echo(9001)
        tcp_echo(8000)
        load_code = r"""
import socket, sys
kind, port = sys.argv[1], int(sys.argv[2])
payload = str(port).encode() + bytes(range(256)) * (100 if kind == 'tcp' else 4)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM) as sock:
    sock.settimeout(15)
    sock.connect(('192.0.2.2', port))
    for _ in range(1 if kind == 'tcp' else 20):
        sock.sendall(payload)
        response = b''
        while len(response) < len(payload):
            part = sock.recv(32768)
            assert part
            response += part
        assert response == payload
"""
        loads = []
        for kind, port in (('udp', 9000), ('udp', 9001), ('tcp', 8000)):
            load = subprocess.Popen(['python3', '-c', load_code, kind, str(port)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            resources.callback(stop_process, load)
            resources.callback(load.stdout.close)
            loads.append(load)
        for load in loads:
            output, _ = load.communicate(timeout=30)
            assert load.returncode == 0, output.decode()
        forwarding()
        conflict = subprocess.run([str(build / 'udp-echo'), '--socket', daemon.path, '--port', '9000'],
                                  capture_output=True, text=True, timeout=10)
        (directory / 'bind-conflict.log').write_text(conflict.stdout + conflict.stderr)
        assert conflict.returncode == 1 and 'bind:' in conflict.stderr and '(-98)' in conflict.stderr, conflict.stderr
        duplicate = subprocess.run([str(build / 'pulsarosd'), str(config), '--socket', daemon.path],
                                   capture_output=True, text=True, timeout=10)
        (directory / 'duplicate-startup.log').write_text(duplicate.stdout + duplicate.stderr)
        assert duplicate.returncode == 1 and 'IPC startup failed' in duplicate.stderr
        sentinel = directory / 'not-a-socket'
        sentinel.write_text('preserve this file')
        ordinary = subprocess.run([str(build / 'pulsarosd'), str(config), '--socket', str(sentinel)],
                                  capture_output=True, text=True, timeout=10)
        assert ordinary.returncode == 1 and sentinel.read_text() == 'preserve this file'
        udp_echo(9001)

        a, b = IPC(daemon.path, fragmented=True), IPC(daemon.path)
        try:
            a1, b1, a2 = a.create(), b.create(), a.create()
            assert a1 == b1 == 1 and a2 == 2
            assert a.bind(a1, 9100) == 0 and b.bind(b1, 9101) == 0
            assert b.call(11, fd=a2)[0] == -errno.EBADF
            assert b.bind(999999, 9000) == -errno.EBADF
            assert a.bind(a2, 9102) == 0
            for _ in range(40):
                assert a.create() > 0
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind(('192.0.2.1', 9200))
                receiver.settimeout(5)
                payload = bytes(range(256)) * 5 + b'fragmented IPC payload'
                result, _ = a.call(9, fd=a1, address=0xc0000201, port=9200, payload=payload, fragmented=True)
                assert result == len(payload) and receiver.recv(2048) == payload
        finally:
            a.close()
            b.close()
        wait_rebind(daemon.path, 9100)

        for mutation in ('version', 'oversized', 'reserved', 'opcode'):
            bad = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            bad.settimeout(3)
            bad.connect(daemon.path)
            data = bytearray(frame(1, 1))
            offset, value = {'version': (4, 99), 'oversized': (16, MAX_DATA + 1),
                             'reserved': (48, 1), 'opcode': (8, 65535)}[mutation]
            data[offset:offset + 4] = struct.pack('!I', value)
            bad.sendall(data)
            try:
                assert bad.recv(1) == b''
            except ConnectionResetError:
                pass
            bad.close()
            udp_echo(9001)
        filtered = IPC(daemon.path)
        assert filtered.bind(filtered.create(), 9400) == 0
        filtered.sock.sendall(frame(65535, filtered.request_id + 1))
        try:
            assert filtered.sock.recv(1) == b''
        except ConnectionResetError:
            pass
        filtered.close()
        wait_rebind(daemon.path, 9400)
        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.connect(daemon.path)
        slow.sendall(frame(1, 1)[:17])
        udp_echo(9001)
        forwarding()
        slow.close()

        first.kill()
        assert first.wait(timeout=5) == -signal.SIGKILL
        daemon.clients.remove(first)
        udp_echo(9001)
        tcp_echo(8000)
        forwarding()
        wait_rebind(daemon.path, 9000)
        replacement = daemon.client(build / 'udp-echo', 9000)
        udp_echo(9000)
        with socket.create_connection(('192.0.2.2', 8000), timeout=5) as live:
            live.settimeout(5)
            live.sendall(b'accepted-before-crash')
            response = b''
            while len(response) < len(b'accepted-before-crash'):
                response += live.recv(64)
            assert response == b'accepted-before-crash'
            tcp.kill()
            assert tcp.wait(timeout=5) == -signal.SIGKILL
            daemon.clients.remove(tcp)
            assert live.recv(64) == b''
        udp_echo(9000)
        udp_echo(9001)
        forwarding()
        remaining_tcp = daemon.client(build / 'tcp-echo', 8001)
        tcp_echo(8001)

        daemon.process.send_signal(signal.SIGTERM)
        assert daemon.process.wait(timeout=8) == 0, daemon.log.read_text()
        for client in (replacement, second, remaining_tcp):
            assert client.wait(timeout=6) != 0
        assert 'Connection reset by peer' in ''.join(p.read_text() for p in directory.glob('client-*.log'))
        daemon.stop(check=False)
        assert not Path(daemon.path).exists()

        bad_config = directory / 'bad.conf'
        bad_config.write_text(config.read_text().replace('dm-host0', 'missing0'))
        failed = subprocess.run([str(build / 'pulsarosd'), str(bad_config), '--socket', daemon.path],
                                capture_output=True, text=True, timeout=20)
        (directory / 'startup-failure.log').write_text(failed.stdout + failed.stderr)
        assert failed.returncode != 0 and not Path(daemon.path).exists()
        assert 'AddressSanitizer' not in failed.stderr and 'runtime error:' not in failed.stderr, failed.stderr
        restart_log = resources.enter_context((directory / 'restart.log').open('w+'))
        recovered = Daemon(build / 'pulsarosd', config, restart_log)
        resources.callback(recovered.stop, False)
        connection = IPC(recovered.path)
        assert connection.bind(connection.create(), 9300) == 0
        recovered.process.kill()
        assert recovered.process.wait(timeout=5) == -signal.SIGKILL
        try:
            connection.call(2, a=2, b=2)
        except (ConnectionResetError, BrokenPipeError):
            pass
        else:
            raise AssertionError('daemon crash did not disconnect IPC')
        connection.close()
        assert Path(recovered.path).exists()
        capacity_log = resources.enter_context((directory / 'capacity.log').open('w+'))
        final = Daemon(build / 'pulsarosd', config, capacity_log,
                       options=('--max-sockets', '2', '--max-clients', '2'))
        resources.callback(final.stop, False)
        x, y = IPC(final.path), IPC(final.path)
        assert x.create() == 1 and y.create() == 1
        assert x.create() == -errno.EMFILE
        try:
            IPC(final.path)
        except (ConnectionResetError, BrokenPipeError):
            pass
        else:
            raise AssertionError('max-clients limit was not enforced')
        x.close()
        y.close()
        final.process.send_signal(signal.SIGINT)
        assert final.process.wait(timeout=8) == 0
        final.stop()
        output = daemon.log.read_text()
        assert output.count('entering host input loop') == 1
        assert 'AddressSanitizer' not in output and 'runtime error:' not in output, output
        for artifact in directory.glob('*.log'):
            text = artifact.read_text()
            assert not any(marker in text for marker in ('AddressSanitizer', 'LeakSanitizer', 'runtime error:')), text
        print('multi-application daemon: concurrent UDP/TCP, isolation, capacity, SIGKILL, rebind, forwarding, malformed IPC, shutdown and recovery passed')


if __name__ == '__main__':
    main()
