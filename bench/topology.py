"""Private network namespaces: no changes to the host management network."""
import os
import signal
import subprocess
import time
from pathlib import Path

MACS = {'source': '02:00:00:00:00:01', 'ingress': '02:00:00:00:00:11',
        'egress': '02:00:00:00:00:12', 'sink': '02:00:00:00:00:02'}


def run(args, **kwargs):
    p = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=20, **kwargs)
    if p.returncode:
        raise RuntimeError(f'{args}: {p.stdout}{p.stderr}')
    return p.stdout


def terminate(p):
    if p is None or p.poll() is not None:
        return
    p.send_signal(signal.SIGCONT)
    p.terminate()
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)
        raise RuntimeError(f'process {p.pid} required SIGKILL')


class Namespace:
    def __init__(self):
        self.process = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
        self.path = f'/proc/{self.process.pid}/ns/net'
        try:
            deadline = time.monotonic() + 3
            while os.readlink(self.path) == os.readlink('/proc/self/ns/net'):
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('could not create isolated network namespace')
                time.sleep(.01)
            self.run('ip', 'link', 'set', 'lo', 'up')
            for key, value in [('net.ipv4.ip_forward', 0), ('net.ipv6.conf.all.disable_ipv6', 1),
                               ('net.ipv4.conf.all.rp_filter', 0), ('net.ipv4.conf.default.rp_filter', 0)]:
                self.run('sysctl', '-qw', f'{key}={value}')
        except BaseException:
            terminate(self.process)
            raise

    def command(self, *args):
        return ['nsenter', f'--net={self.path}', *map(str, args)]

    def run(self, *args, **kwargs):
        return run(self.command(*args), **kwargs)

    def start(self, args, cpu=None, **kwargs):
        prefix = [] if cpu is None else ['taskset', '-c', str(cpu)]
        return subprocess.Popen(self.command(*prefix, *args), **kwargs)

    def close(self):
        terminate(self.process)


class Topology:
    def __init__(self, directory, direct=False):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.namespaces = []
        self.direct = direct
        self.offloads = {}
        try:
            self.source = self.namespace()
            self.router = self.namespace()
            self.sink = self.namespace()
            self.router.run('ip', 'link', 'add', 'r0', 'type', 'veth', 'peer', 'name', 'g0')
            self.router.run('ip', 'link', 'set', 'g0', 'netns', self.source.process.pid)
            if direct:
                self.router.run('ip', 'link', 'set', 'r0', 'netns', self.sink.process.pid)
                self.sink.run('ip', 'link', 'set', 'r0', 'name', 'd0')
            else:
                self.router.run('ip', 'link', 'add', 'r1', 'type', 'veth', 'peer', 'name', 'd0')
                self.router.run('ip', 'link', 'set', 'd0', 'netns', self.sink.process.pid)
                self.interface(self.router, 'r0', MACS['ingress'])
                self.interface(self.router, 'r1', MACS['egress'])
            self.interface(self.source, 'g0', MACS['source'])
            self.interface(self.sink, 'd0', MACS['sink'])
            self.source.run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'g0')
        except BaseException:
            self.close()
            raise

    def namespace(self):
        ns = Namespace()
        self.namespaces.append(ns)
        return ns

    def interface(self, ns, name, mac):
        ns.run('ip', 'link', 'set', name, 'address', mac)
        ns.run('ip', 'link', 'set', name, 'addrgenmode', 'none')
        ns.run('ip', 'link', 'set', name, 'up')
        ns.run('ethtool', '-K', name, 'tx', 'off', 'rx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off', 'lro', 'off')
        self.offloads[name] = ns.run('ethtool', '-k', name)

    def metadata(self):
        return {'direct_calibration': self.direct, 'namespaces': {name: getattr(self, name).process.pid for name in ('source', 'router', 'sink')},
                'offloads': self.offloads, 'macs': MACS,
                'source_links': self.source.run('ip', '-j', '-d', 'link', 'show'),
                'router_links': self.router.run('ip', '-j', '-d', 'link', 'show'),
                'sink_links': self.sink.run('ip', '-j', '-d', 'link', 'show'),
                'router_addresses': self.router.run('ip', '-j', 'addr', 'show'),
                'router_routes': self.router.run('ip', '-j', 'route', 'show', 'table', 'all'),
                'source_sysctls': self.source.run('sysctl', 'net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter'),
                'router_sysctls': self.router.run('sysctl', 'net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter')}

    def close(self):
        errors = []
        for ns in reversed(self.namespaces):
            try:
                ns.close()
            except Exception as exc:
                errors.append(str(exc))
        self.namespaces = []
        if errors:
            raise RuntimeError('; '.join(errors))
