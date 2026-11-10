#!/usr/bin/env python3
"""Byte-verified Linux echo transfers; run with unshare --net as root."""
import argparse
import errno
import concurrent.futures
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from daemon_helpers import Daemon
from smoke import ip


def transfer(size, constrained=False):
    block = bytes((i * 17 + 42) & 255 for i in range(65536))
    with socket.create_connection(('192.0.2.2', 9000), timeout=20) as sock:
        sock.settimeout(30)
        if constrained:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        errors = []

        def send():
            try:
                for offset in range(0, size, len(block)):
                    sock.sendall(block[:min(len(block), size - offset)])
                sock.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
                sock.shutdown(socket.SHUT_RDWR)

        writer = threading.Thread(target=send)
        writer.start()
        total = 0
        deadline = time.monotonic() + 180
        try:
            if constrained:
                time.sleep(.2)
            while True:
                assert time.monotonic() < deadline, ('transfer deadline', total, size)
                data = sock.recv(65536)
                if not data:
                    break
                expected = (block + block)[total % len(block):total % len(block) + len(data)]
                assert data == expected, ('corrupt stream', total)
                total += len(data)
            assert total == size, (total, size)
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError as error:
                if error.errno != errno.ENOTCONN:
                    raise
            writer.join(timeout=35)
        assert not writer.is_alive() and not errors, errors


def active_transfer(binary, path, size):
    errors = []
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('192.0.2.1', 9001))
        listener.listen(1)
        listener.settimeout(20)

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(30)
                    total = 0
                    pattern = bytes(range(256)) * 257
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        assert data == pattern[total % 256:total % 256 + len(data)]
                        total += len(data)
                        conn.sendall(data)
                    assert total == size, (total, size)
            except BaseException as error:
                errors.append(error)

        server = threading.Thread(target=serve)
        server.start()
        try:
            subprocess.run([str(binary.parent / 'test-tcp-initiator'), path,
                            '192.0.2.1', str(size)], check=True, timeout=200)
        finally:
            server.join(timeout=35)
        assert not server.is_alive() and not errors, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    config = args.artifacts / 'bulk.conf'
    config.write_text(f'lcore={min(os.sched_getaffinity(0))}\nno_huge=1\n'
                      '[interface]\npmd=af_packet\ndevice=tb-host\nip=192.0.2.2/24\n')
    daemon = None
    ip('link', 'add', 'tb-host', 'type', 'veth', 'peer', 'name', 'tb-peer')
    try:
        for name in ('tb-host', 'tb-peer'):
            ip('link', 'set', name, 'up')
            subprocess.run(['ethtool', '-K', name, 'tx', 'off', 'rx', 'off',
                            'tso', 'off', 'gso', 'off', 'gro', 'off'], check=True, capture_output=True)
        ip('addr', 'add', '192.0.2.1/24', 'dev', 'tb-peer')
        with (args.artifacts / 'daemon.log').open('w+') as log:
            daemon = Daemon(args.binary, config, log)
            daemon.client(args.binary)
            for mib in (1, 10, 100):
                start = time.monotonic()
                transfer(mib * 1024 * 1024)
                print(f'{mib} MiB passive verified in {time.monotonic() - start:.3f}s', flush=True)
                start = time.monotonic()
                active_transfer(args.binary, daemon.path, mib * 1024 * 1024)
                print(f'{mib} MiB active verified in {time.monotonic() - start:.3f}s', flush=True)
            transfer(1024 * 1024, constrained=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                futures = [pool.submit(transfer, 1024 * 1024) for _ in range(32)]
                for future in futures:
                    future.result(timeout=180)
            print('32 concurrent 1 MiB streams and constrained receive window passed', flush=True)
            daemon.stop()
            daemon = None
    finally:
        if daemon:
            daemon.stop(check=False)
        ip('link', 'del', 'tb-host')


if __name__ == '__main__':
    main()
