#!/usr/bin/env python3
"""Live administrative changes on one multi-application AF_PACKET daemon."""
import argparse
import errno
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from scapy.all import Ether, IP, UDP, ICMP, get_if_hwaddr, srp1

from daemon_helpers import Daemon
from smoke import ip
from smoke_daemon import IPC, read_exact, tcp_echo, udp_echo
from smoke_forward import CLIENT, Namespace, stop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    with tempfile.TemporaryDirectory(prefix='pulsaros-admin-') as tmp, ExitStack() as resources:
        directory = args.artifacts or Path(tmp)
        directory.mkdir(parents=True, exist_ok=True)
        # Permit an unprivileged client to reach the application IPC socket.
        os.chmod(directory, 0o755)
        subprocess.run(['sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1'], check=True)
        subprocess.run(['sysctl', '-qw', 'net.ipv4.ip_forward=0'], check=True)
        remote = Namespace(resources)
        for index in range(2):
            host, peer = f'ma-host{index}', f'ma-peer{index}'
            ip('link', 'add', host, 'type', 'veth', 'peer', 'name', peer)
            resources.callback(subprocess.run, ['ip', 'link', 'del', host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ip('link', 'set', host, 'addrgenmode', 'none')
            ip('link', 'set', host, 'up')
            if index:
                ip('link', 'set', peer, 'netns', str(remote.process.pid))
                remote.link(peer, '02:00:00:00:01:01', '198.51.100.1/24')
                remote.run('ip', 'addr', 'add', '203.0.113.9/32', 'dev', 'lo')
                remote.run('ip', 'route', 'add', 'default', 'via', '198.51.100.2')
            else:
                ip('link', 'set', peer, 'up')
                ip('addr', 'add', '192.0.2.1/24', 'dev', peer)
                ip('addr', 'add', '10.10.0.254/24', 'dev', peer)
                subprocess.run(['ethtool', '-K', peer, 'tx', 'off', 'rx', 'off'], check=True, capture_output=True)
        config = directory / 'stack.conf'
        config.write_text(f'lcore={min(os.sched_getaffinity(0))}\nno_huge=1\nipv4_forwarding=1\n' + ''.join(
            f'[interface]\npmd=af_packet\ndevice=ma-host{i}\nip={address}/24\n'
            for i, address in enumerate(('192.0.2.2', '198.51.100.2'))))
        log = resources.enter_context((directory / 'daemon.log').open('w+'))
        daemon = Daemon(build / 'pulsarosd', config, log)
        resources.callback(daemon.stop, False)
        admin = daemon.path + '.admin'

        def cli(*words, ok=True, json_output=True):
            command = [str(build / 'pulsar'), '--socket', admin]
            if json_output:
                command.append('-j')
            result = subprocess.run([*command, *map(str, words)], capture_output=True, text=True, timeout=10)
            if not ok:
                assert result.returncode != 0, result.stdout
                return result
            assert result.returncode == 0, (command, words, result.stdout, result.stderr, log.name)
            return json.loads(result.stdout) if json_output else result.stdout

        assert cli('status')['items'][0]['workers'] == 1
        assert len(cli('link', 'show')['items']) == 2
        assert cli('link', 'show', 'dev', 'ma-host0')['items'][0]['admin'] == 'UP'
        assert len(cli('addr', 'show')['items']) == 2
        monitor = subprocess.Popen([str(build / 'pulsar'), '--socket', admin, 'monitor'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        resources.callback(stop, monitor)
        time.sleep(0.1)
        cli('addr', 'add', '10.10.0.1/24', 'dev', 'ma-host0')
        cli('addr', 'add', '10.10.0.2/24', 'dev', 'ma-host0')
        assert len(cli('addr', 'show', 'dev', 'ma-host0')['items']) == 3
        connected = [r for r in cli('route', 'show')['items'] if r['destination'] == '10.10.0.0/24']
        assert len(connected) == 1
        subprocess.run(['python3', '-c', CLIENT, '10.10.0.1', 'icmp'], check=True, capture_output=True, timeout=10)
        subprocess.run(['python3', '-c', CLIENT, '10.10.0.2', 'icmp'], check=True, capture_output=True, timeout=10)
        session = IPC(daemon.path)
        resources.callback(session.close)
        fd = session.create()
        address = struct.unpack('!I', socket.inet_aton('10.10.0.2'))[0]
        assert session.call(3, fd=fd, port=7778, address=address)[0] == 0
        generation = cli('status')['generation']
        cli('addr', 'del', '10.10.0.2/24', 'dev', 'ma-host0', ok=False)
        assert cli('status')['generation'] == generation
        assert session.call(11, fd=fd)[0] == 0
        cli('addr', 'del', '10.10.0.2/24', 'dev', 'ma-host0')
        first = daemon.client(build / 'udp-echo', 9000)
        second = daemon.client(build / 'udp-echo', 9001)
        tcp = daemon.client(build / 'tcp-echo', 8000)
        assert len(cli('app', 'show')['items']) >= 3
        assert any(s['local_port'] == 8000 for s in cli('socket', 'show')['items'])
        udp_echo(9000)
        udp_echo(9001)
        tcp_echo(8000)
        # Continue unrelated UDP and TCP traffic throughout routing and ACL changes.
        load_code = r'''
import socket, sys, time
kind, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == 'udp' else socket.SOCK_STREAM)
s.settimeout(10); s.connect(('192.0.2.2', port))
for _ in range(100):
    s.sendall(b'live-config')
    data=b''
    while len(data)<11: data+=s.recv(11-len(data))
    assert data == b'live-config'
    time.sleep(.01)
s.close()
'''
        loads = []
        for kind, port in (('udp', 9001), ('tcp', 8000)):
            p = subprocess.Popen(['python3', '-c', load_code, kind, str(port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            resources.callback(stop, p)
            loads.append(p)
        cli('route', 'add', '203.0.113.0/24', 'via', '198.51.100.1', 'dev', 'ma-host1')
        ip('route', 'add', '203.0.113.0/24', 'via', '192.0.2.2')
        subprocess.run(['python3', '-c', CLIENT, '203.0.113.9', 'icmp'], check=True, capture_output=True, timeout=10)
        assert cli('route', 'get', '203.0.113.9')['items'][0]['next_hop'] == '198.51.100.1'
        cli('route', 'del', '203.0.113.0/24')
        cli('route', 'get', '203.0.113.9', ok=False)
        mac = cli('link', 'show', 'dev', 'ma-host0')['items'][0]['mac']
        for route_type, code in (('unreachable', 0), ('prohibit', 13), ('blackhole', None)):
            cli('route', 'add', route_type, '203.0.113.0/24')
            frame = Ether(src=get_if_hwaddr('ma-peer0'), dst=mac)/IP(src='192.0.2.1', dst='203.0.113.9')/UDP(sport=49000, dport=9090)
            response = srp1(frame, iface='ma-peer0', timeout=.3, verbose=False)
            if code is None:
                assert response is None
            else:
                assert response is not None and response[ICMP].type == 3 and response[ICMP].code == code
            fd = session.create()
            result, _ = session.call(9, fd=fd, address=struct.unpack('!I', socket.inet_aton('203.0.113.9'))[0], port=9090, payload=b'route-type')
            assert result == -({'unreachable': errno.ENETUNREACH, 'prohibit': errno.EACCES, 'blackhole': errno.EINVAL}[route_type])
            assert session.call(11, fd=fd)[0] == 0
            cli('route', 'del', '203.0.113.0/24')
        cli('route', 'add', 'default', 'via', '198.51.100.1', 'dev', 'ma-host1', 'table', '100')
        cli('rule', 'add', 'pref', '50', 'from', '10.10.0.0/24', 'lookup', '101')
        cli('rule', 'add', 'pref', '100', 'from', '10.10.0.0/24', 'lookup', '100')
        selected = cli('route', 'get', '203.0.113.9', 'from', '10.10.0.1')['items'][0]
        assert selected['table'] == 100 and selected['rule_pref'] == 100 and selected['dev'] == 'ma-host1'
        # Real forwarded packets exercise source-based lookup and empty-table fallthrough.
        source_ping = CLIENT.replace("sock.settimeout(5)", "sock.bind(('10.10.0.254', 0)); sock.settimeout(5)")
        subprocess.run(['python3', '-c', source_ping, '203.0.113.9', 'icmp'], check=True, capture_output=True, timeout=10)
        # Local output uses the same source-based policy and active ARP resolution.
        server_code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('203.0.113.9',7777)); print('ready',flush=True); data,p=s.recvfrom(1024); s.sendto(data,p)"
        server = subprocess.Popen(remote.command('python3', '-c', server_code), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        resources.callback(stop, server)
        assert server.stdout.readline().strip() == 'ready'
        fd = session.create()
        address = struct.unpack('!I', socket.inet_aton('10.10.0.1'))[0]
        remote_ip = struct.unpack('!I', socket.inet_aton('203.0.113.9'))[0]
        assert session.call(3, fd=fd, port=7779, address=address)[0] == 0
        assert session.call(9, fd=fd, port=7777, address=remote_ip, payload=b'policy-local')[0] == 12
        deadline = time.monotonic() + 5
        while True:
            result, payload = session.call(10, fd=fd, a=1024)
            if result >= 0:
                assert payload == b'policy-local'
                break
            assert result == -errno.EAGAIN and time.monotonic() < deadline
            time.sleep(.01)
        assert session.call(11, fd=fd)[0] == 0
        assert server.wait(timeout=5) == 0
        cli('route', 'add', 'default', 'via', '10.10.0.254', 'dev', 'ma-host0', 'table', '200')
        cli('rule', 'add', 'pref', '25', 'to', '8.8.8.8/32', 'lookup', '200')
        assert cli('route', 'get', '8.8.8.8', 'from', '10.10.0.1')['items'][0]['next_hop'] == '10.10.0.254'
        cli('route', 'replace', '198.18.0.0/16', 'dev', 'ma-host1', 'table', '100')
        cli('route', 'del', '198.18.0.0/16', 'table', '100')
        before = cli('status')['generation']
        for command in (('route', 'add', 'default', 'via', '172.16.0.1', 'dev', 'ma-host0'),
                        ('addr', 'add', '10.0.0.1/33', 'dev', 'ma-host0'),
                        ('rule', 'add', 'pref', '-1', 'lookup', '100'),
                        ('route', 'flush', 'table', 'local'),
                        ('link', 'set', 'dev', 'bad', 'up'),
                        ('acl', 'add', 'pref', '1', 'proto', 'icmp', 'dport', '22', 'action', 'drop')):
            cli(*command, ok=False)
            assert cli('status')['generation'] == before
        cli('acl', 'add', 'pref', '100', 'proto', 'udp', 'dport', '9000', 'action', 'drop')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(.3)
            peer.sendto(b'blocked', ('192.0.2.2', 9000))
            try:
                peer.recv(1024)
                raise AssertionError('ACL did not drop UDP')
            except socket.timeout:
                pass
        udp_echo(9001)
        tcp_echo(8000)
        rules = cli('acl', 'stats')['items']
        assert rules[0]['pref'] == 100 and rules[0]['packets'] >= 1
        cli('acl', 'del', 'pref', '100')
        udp_echo(9000)
        acl = directory / 'acl.conf'
        acl.write_text('# atomic reference rules\ndefault accept\n100 proto tcp dport 22 drop\n200 src 203.0.113.0/24 drop\n')
        observed, errors = [], []
        finished = threading.Event()

        def observe():
            try:
                while not finished.is_set():
                    observed.append(len(cli('acl', 'show')['items']) - 1)
            except BaseException as exc:
                errors.append(exc)
        observer = threading.Thread(target=observe)
        observer.start()
        try:
            for _ in range(8):
                cli('acl', 'apply', acl)
                cli('acl', 'flush')
        finally:
            finished.set()
            observer.join(timeout=10)
        assert not observer.is_alive() and not errors and observed and set(observed) <= {0, 2}, (observed, errors)
        cli('acl', 'apply', acl)
        generation = cli('status')['generation']
        acl.write_text('default drop\n100 proto udp dport 9001 drop\nbad malformed line\n')
        cli('acl', 'apply', acl, ok=False)
        assert cli('status')['generation'] == generation
        cli('acl', 'flush')
        udp_echo(9000)
        # Permanent neighbours survive ordinary ARP learning; deletion is scoped.
        cli('neigh', 'replace', '198.51.100.1', 'lladdr', '02:00:00:00:01:01', 'dev', 'ma-host1', 'nud', 'permanent')
        assert any(n['state'] == 'PERMANENT' for n in cli('neigh', 'show', 'dev', 'ma-host1')['items'])
        cli('neigh', 'del', '198.51.100.1', 'dev', 'ma-host1')
        cli('neigh', 'flush', 'dev', 'ma-host1')
        for p in loads:
            output, _ = p.communicate(timeout=30)
            assert p.returncode == 0, output.decode()
        # Link operations are real PMD operations; unsupported MTU changes must fail.
        result = subprocess.run([str(build/'pulsar'), '--socket', admin, 'link', 'set', 'dev', 'ma-host0', 'mtu', '1400'], capture_output=True, text=True)
        if result.returncode == 0:
            assert cli('link', 'show', 'dev', 'ma-host0')['items'][0]['mtu'] == 1400
            cli('link', 'set', 'dev', 'ma-host0', 'mtu', '1500')
        else:
            assert cli('link', 'show', 'dev', 'ma-host0')['items'][0]['mtu'] == 1500
        cli('link', 'set', 'dev', 'ma-host1', 'down')
        assert cli('link', 'show', 'dev', 'ma-host1')['items'][0]['admin'] == 'DOWN'
        cli('route', 'get', '203.0.113.9', 'from', '10.10.0.1', ok=False)
        udp_echo(9001)
        cli('link', 'set', 'dev', 'ma-host1', 'up')
        assert cli('route', 'get', '203.0.113.9', 'from', '10.10.0.1')['items'][0]['table'] == 100
        assert cli('stats', '--nodes')['items']
        assert 'name=ma-host0' in cli('link', 'show', 'dev', 'ma-host0', json_output=False)
        # Corrupt/oversized administration frames never affect the generation.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bad:
            bad.settimeout(2); bad.connect(admin)
            bad.sendall(struct.pack('!8I', 0x50534d47, 1, 1, 0xffffffff, 0, 0, 0, 0))
            assert bad.recv(1) == b''
        before = cli('status')['generation']
        # A full valid request split into single-byte writes is accepted.
        words = [1, 1, 1, 0] + [0]*16
        body = struct.pack('!20I', *words) + bytes(64)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as partial:
            partial.settimeout(5); partial.connect(admin)
            frame = struct.pack('!8I', 0x50534d47, 1, 5, len(body), 0, 0, 0, 0) + body
            for byte in frame:
                partial.sendall(bytes([byte]))
            header = struct.unpack('!8I', read_exact(partial, 32))
            assert header[4] == 0
            assert json.loads(read_exact(partial, header[3]))['generation'] == before
        if os.geteuid() == 0:
            # Filesystem authorization, then peer-credential authorization even if chmod is relaxed.
            drop_privileges = lambda: (os.setgroups([]), os.setgid(65534), os.setuid(65534))
            denied = subprocess.run([str(build/'pulsar'), '--socket', admin, 'status'], preexec_fn=drop_privileges, capture_output=True)
            assert denied.returncode != 0
            os.chmod(admin, 0o666)
            denied = subprocess.run([str(build/'pulsar'), '--socket', admin, 'status'], preexec_fn=drop_privileges, capture_output=True)
            assert denied.returncode != 0
            os.chmod(admin, 0o600)
            code = "import socket,struct; s=socket.socket(socket.AF_UNIX); s.connect(%r); s.sendall(struct.pack('!16I',0x50534e53,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0)); assert len(s.recv(64))==64" % daemon.path
            assert subprocess.run(['python3', '-c', code], preexec_fn=drop_privileges).returncode == 0
        assert daemon.process.poll() is None and all(p.poll() is None for p in (first, second, tcp))
        monitor.terminate()
        stdout, _ = monitor.communicate(timeout=5)
        events = [json.loads(line) for line in stdout.splitlines()]
        assert {2+1, 4, 5, 6, 7, 8}.issubset({e['group'] for e in events}), events
        assert all(a['sequence'] < b['sequence'] for a, b in zip(events, events[1:]))
        (directory/'events.jsonl').write_text(stdout)
        daemon.stop()
        assert not Path(admin).exists()
        assert cli('status', ok=False).returncode != 0
        print('admin: live addresses/ARP/ICMP, tables/PBR on wire, ACLs, atomic updates, concurrent apps, neighbours, links, events, JSON, permissions and malformed IPC passed')


if __name__ == '__main__':
    main()
