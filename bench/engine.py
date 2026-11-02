import json
import ipaddress
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from topology import MACS, Topology, terminate


class Engine:
    def __init__(self, name, build, tools, case, directory, cpus):
        self.name, self.build, self.tools, self.case = name, Path(build), Path(tools), case
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.cpus = cpus
        self.process = None
        self.servers = []
        self.streams = []
        self.paused = False
        self.temporary = tempfile.TemporaryDirectory(prefix='psbench-')
        self.path = str(Path(self.temporary.name) / 'a.sock')
        self.admin = self.path + '.admin'
        self.topology = Topology(self.directory, direct=name == 'calibration')
        self.numbered = case.group == 'application' or case.addresses > 1 or case.latency or case.unresolved
        self.main_count = case.routes - (1 if case.group == 'policy' else 0)
        self.base_connected = 2 if self.numbered else 1
        self.static_count = max(0, self.main_count - self.base_connected)
        self.destination_base = '198.18.0.1' if self.static_count else '198.51.100.1'
        self.destination_count = self.static_count if case.pattern in ('multiple', 'random', 'worst') and self.static_count else 1
        self.stride = 256
        if case.neighbours > 1:
            self.destination_base, self.destination_count, self.stride = '198.51.100.1', case.neighbours, 1
        if case.group == 'application':
            self.destination_base = '192.0.2.63' if case.addresses == 64 else '192.0.2.254'
        self.flows = 2 if case.acl_pattern == 'drop' else (case.acl + 1 if case.acl_pattern == 'mixed' else 64)
        self.commands = []
        try:
            self.configure()
        except BaseException:
            self.close()
            raise

    @property
    def pulsar(self):
        return self.name in ('current', 'before')

    def cli(self, *args):
        command = [str(self.build / 'pulsar'), '--socket', self.admin, '-j', *map(str, args)]
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        self.commands.append({'argv': command, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            raise RuntimeError(f'{args}: {result.stderr}')
        return json.loads(result.stdout)

    def network(self, *args):
        if self.pulsar:
            return self.cli(*args)
        mapping = {'addr': 'addr', 'route': 'route', 'rule': 'rule', 'neigh': 'neigh'}
        return self.topology.router.run('ip', mapping[args[0]], *map(str, args[1:]))

    def configure(self):
        c, t = self.case, self.topology
        if self.name == 'calibration':
            return
        if self.pulsar:
            config = self.directory / 'stack.conf'
            config.write_text(f'lcore={self.cpus["dataplane"]}\nno_huge=1\nipv4_forwarding=1\n'
                              '[interface]\npmd=af_packet\ndevice=r0\nip=192.0.2.254/24\n'
                              '[interface]\npmd=af_packet\ndevice=r1\nip=198.51.100.254/24\n')
            log = (self.directory / 'daemon.log').open('w')
            self.streams.append(log)
            self.process = t.router.start([str(self.build / 'pulsarosd'), str(config), '--socket', self.path],
                                          cpu=f'{self.cpus["dataplane"]},{self.cpus["control"]}', stdout=log, stderr=log)
            deadline = time.monotonic() + 20
            while 'IPC listening on' not in (self.directory / 'daemon.log').read_text():
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError((self.directory / 'daemon.log').read_text())
                time.sleep(.02)
            if not self.numbered:
                self.cli('addr', 'del', '192.0.2.254/24', 'dev', 'r0')
        else:
            t.router.run('ip', 'addr', 'add', '198.51.100.254/24', 'dev', 'r1')
            if self.numbered:
                t.router.run('ip', 'addr', 'add', '192.0.2.254/24', 'dev', 'r0')
            t.router.run('sysctl', '-qw', 'net.ipv4.ip_forward=1')
        for i in range(self.static_count):
            prefix = ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.0')) + i*256)
            self.network('route', 'add', f'{prefix}/24', 'via', '198.51.100.1', 'dev', 'r1')
        if c.group == 'policy':
            self.network('route', 'add', 'default', 'via', '198.51.100.1', 'dev', 'r1', 'table', '100')
            for i in range(c.policies):
                source = '192.0.2.0/24' if c.empty_tables or i == c.policies - 1 else '203.0.113.0/24'
                self.network('rule', 'add', 'pref', str(i + 1), 'from', source, 'lookup', str(1000+i if c.empty_tables else 100))
        if c.addresses > 1:
            for i in range(2, 64):
                self.network('addr', 'add', f'192.0.2.{i}/24', 'dev', 'r0')
        self.acl()
        self.validate_configuration()
        if c.group == 'application':
            self.start_servers()
        (self.directory / 'topology.json').write_text(json.dumps(t.metadata(), indent=2))

    def acl(self):
        c = self.case
        rules = []
        for i in range(c.acl):
            source = ipaddress.IPv4Address(int(ipaddress.IPv4Address('203.0.113.1')) + i)
            match, action = f'src {source}/32', 'drop'
            if c.acl_pattern == 'early' and i == 0 or c.acl_pattern == 'late' and i == c.acl-1:
                match, action = 'proto udp', 'accept'
            if c.acl_pattern == 'mixed':
                match, action = f'proto udp dport {9000+i}', 'accept'
            if c.acl_pattern == 'drop' and i == 0:
                match, action = 'proto udp dport 9000', 'drop'
            rules.append((100+i, match, action))
        if self.pulsar:
            path = self.directory / 'acl.conf'
            path.write_text('default accept\n' + ''.join(f'{pref} {match} {action}\n' for pref, match, action in rules))
            self.cli('acl', 'apply', path)
        elif rules:
            lines = ['table ip psbench { chain ingress { type filter hook prerouting priority -150; policy accept;']
            for pref, match, action in rules:
                expression = match.replace('src ', 'ip saddr ').replace('proto udp dport ', 'udp dport ').replace('proto udp', 'ip protocol udp')
                lines.append(f'{expression} counter {action} comment "pref={pref}"')
            lines.extend(['}', '}'])
            path = self.directory / 'acl.nft'
            path.write_text('\n'.join(lines) + '\n')
            self.topology.router.run('nft', '-f', path)

    def validate_configuration(self):
        if self.pulsar:
            routes = self.cli('route', 'show', 'table', 'all')['items']
            software_routes = [r for r in routes if r['type'] != 'local']
            assert len(software_routes) == self.case.routes or self.case.group == 'application', (len(software_routes), self.case)
            destination = self.destination_base
            if self.case.pattern == 'worst' and self.static_count:
                destination = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.1')) + (self.static_count-1)*256))
            selected = self.cli('route', 'get', destination, 'from', '192.0.2.1')
            if self.case.group != 'application':
                assert selected['items'][0]['dev'] == 'r1', selected
                expected = self.case.policies if self.case.group == 'policy' and self.case.policies and not self.case.empty_tables else 32766
                assert selected['items'][0]['rule_pref'] == expected, selected
            assert len(self.cli('acl', 'show')['items']) - 1 == self.case.acl
            (self.directory / 'configuration.json').write_text(json.dumps({'routes': routes, 'selected': selected,
                'rules': self.cli('rule', 'show'), 'acl': self.cli('acl', 'show')}, indent=2))
        else:
            destination = self.destination_base
            if self.case.pattern == 'worst' and self.static_count:
                destination = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.1')) + (self.static_count-1)*256))
            selected = self.topology.router.run('ip', '-j', 'route', 'get', destination, 'from', '192.0.2.1', 'iif', 'r0')
            (self.directory / 'configuration.json').write_text(json.dumps({'selected': json.loads(selected),
                'rules': json.loads(self.topology.router.run('ip', '-j', 'rule', 'show')),
                'nft': self.topology.router.run('nft', '-j', 'list', 'ruleset')}, indent=2))
        (self.directory / 'commands.json').write_text(json.dumps(self.commands, indent=2))

    def start_servers(self):
        binary = self.tools / ('bench-pulsar-server' if self.pulsar else 'bench-linux-server')
        for i in range(self.case.services):
            log = (self.directory / f'server-{i}.log').open('w')
            self.streams.append(log)
            metric = self.directory / f'server-{i}.json'
            args = [str(binary), '--kind', self.case.kind, '--mode', 'sink' if self.case.mode == 'sink' else 'echo',
                    '--port', str(9000+i), '--output', str(metric)]
            if self.pulsar:
                args += ['--socket', self.path]
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = str(self.build) + ':' + env.get('LD_LIBRARY_PATH', '')
            process = self.topology.router.start(args, cpu=self.cpus['applications'][i % len(self.cpus['applications'])], stdout=log, stderr=log, env=env)
            self.servers.append(process)
            deadline = time.monotonic() + 10
            while not metric.exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f'server did not start: {log.name}')
                time.sleep(.01)

    def server_snapshot(self):
        result = []
        for i, process in enumerate(self.servers):
            if process.poll() is not None:
                raise RuntimeError(f'server exited: {process.returncode}')
            metric = self.directory / f'server-{i}.json'
            before = json.loads(metric.read_text())['time_ns']
            process.send_signal(signal.SIGUSR1)
            deadline = time.monotonic() + 5
            while True:
                value = json.loads(metric.read_text())
                if value['time_ns'] > before:
                    result.append(value)
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError('server snapshot timed out')
                time.sleep(.005)
        return result

    def counters(self):
        if self.name == 'calibration':
            return {}
        if self.process is not None and self.process.poll() is not None:
            raise RuntimeError('daemon exited')
        if self.pulsar:
            return {'nodes': self.cli('stats', '--nodes'), 'links': self.cli('link', 'show')['items'],
                    'link_stats': self.cli('-s', 'link', 'show')['items'], 'acl': self.cli('acl', 'show'),
                    'neighbours': self.cli('neigh', 'show'), 'sockets': self.cli('socket', 'show')}
        return {'links': json.loads(self.topology.router.run('ip', '-j', '-s', 'link', 'show')),
                'neighbours': json.loads(self.topology.router.run('ip', '-j', 'neigh', 'show')),
                'nft': json.loads(self.topology.router.run('nft', '-j', 'list', 'ruleset'))}

    def steady_neighbours(self):
        if self.name == 'calibration' or self.case.cold or self.case.unresolved or self.case.group == 'application':
            return
        for i in range(self.case.neighbours):
            self.network('neigh', 'replace', f'198.51.100.{i+1}', 'lladdr', MACS['sink'], 'dev', 'r1', 'nud', 'permanent')

    def pause(self):
        if self.process and not self.servers and not self.paused:
            self.process.send_signal(signal.SIGSTOP)
            self.paused = True

    def resume(self):
        if self.process and self.paused:
            self.process.send_signal(signal.SIGCONT)
            self.paused = False

    def close(self):
        self.resume()
        errors = []
        for p in [*self.servers, self.process]:
            try:
                terminate(p)
                if p and p.returncode != 0:
                    errors.append(f'process {p.pid} exited with {p.returncode}')
            except Exception as exc:
                errors.append(str(exc))
        for stream in self.streams:
            stream.close()
        try:
            self.topology.close()
        finally:
            self.temporary.cleanup()
        if errors:
            raise RuntimeError('; '.join(errors))
