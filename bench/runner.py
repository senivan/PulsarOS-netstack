import json
import os
import signal
import subprocess
import time
from pathlib import Path

from environment import save
from topology import MACS, terminate


def read_json(path):
    for _ in range(100):
        try:
            return json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError):
            time.sleep(.005)
    raise RuntimeError(f'incomplete metrics: {path}')


def cpu_snapshot(engine):
    result = {'time_ns': time.monotonic_ns(), 'processes': {}, 'system': Path('/proc/stat').read_text(),
              'cgroup': Path('/sys/fs/cgroup/cpu.stat').read_text() if Path('/sys/fs/cgroup/cpu.stat').exists() else ''}
    for p in ([engine.process] if engine.process else []) + engine.servers:
        if p.poll() is not None:
            continue
        process = {'threads': {}}
        for entry in Path(f'/proc/{p.pid}/task').iterdir():
            try:
                text = (entry / 'stat').read_text()
                fields = text.rsplit(') ', 1)[1].split()
                process['threads'][entry.name] = {'name': text.split('(', 1)[1].rsplit(')', 1)[0],
                    'seconds': (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
                    'cpu': int(fields[36]), 'rss_bytes': int(fields[21])*os.sysconf('SC_PAGE_SIZE'),
                    'affinity': sorted(os.sched_getaffinity(int(entry.name)))}
            except FileNotFoundError:
                continue
        result['processes'][str(p.pid)] = process
    return result


def cpu_delta(before, after):
    threads = []
    for pid, process in after['processes'].items():
        for tid, value in process['threads'].items():
            old = before['processes'].get(pid, {}).get('threads', {}).get(tid)
            if old:
                threads.append({'pid': int(pid), 'tid': int(tid), 'name': value['name'], 'cpu': value['cpu'],
                    'cpu_seconds': max(0, value['seconds']-old['seconds']), 'rss_bytes': value['rss_bytes'], 'affinity': value['affinity']})
    return {'window_seconds': (after['time_ns']-before['time_ns'])/1e9, 'threads': threads,
            'cpu_seconds': sum(t['cpu_seconds'] for t in threads)}


def packet_args(engine, run_id, duration, rate, directory, receive=False, probe=False):
    c = engine.case
    output = Path(directory) / ('rx.json' if receive else ('probe.json' if probe else 'tx.json'))
    source_mac = MACS['source']
    destination_mac = MACS['sink'] if engine.name == 'calibration' else MACS['ingress']
    ttl = 63 if receive and engine.name != 'calibration' else 64
    if receive:
        source_mac = MACS['source'] if engine.name == 'calibration' else MACS['egress']
        destination_mac = MACS['sink']
    flows = 1 if probe or c.group == 'application' else engine.flows
    args = ['--interface', 'd0' if receive else 'g0', '--output', str(output), '--src', '192.0.2.1',
            '--dst', engine.destination_base, '--src-mac', source_mac, '--dst-mac', destination_mac,
            '--size', str(c.size if c.group != 'application' else c.payload+42), '--rate', str(rate), '--duration', str(duration),
            '--flows', str(flows), '--destinations', str(1 if probe else engine.destination_count), '--stride', str(engine.stride),
            '--pattern', 'random' if c.pattern == 'random' else ('last' if c.pattern == 'worst' else 'sequential'),
            '--run', str(run_id), '--seed', '42', '--ttl', str(ttl)]
    if receive and engine.name != 'calibration' and not c.unresolved:
        args += ['--arp']
    if c.acl_pattern == 'drop' and receive:
        args += ['--drop-mod', '2', '--drop-rem', '0']
    if receive and c.latency:
        args += ['--echo', '--probe-run', str(run_id+1000000000)]
    return args


def wait_ready(p, log):
    deadline = time.monotonic() + 5
    while 'READY' not in Path(log).read_text():
        if p.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError(f'endpoint failed: {Path(log).read_text()}')
        time.sleep(.005)


def check_packet_capture(path, case, calibration=False):
    from scapy.all import IP, UDP, Ether, rdpcap
    from scapy.utils import checksum
    packets = rdpcap(str(path))
    if not packets:
        raise RuntimeError('no independently captured packets')
    for p in packets:
        assert IP in p and UDP in p and len(p) == case.size
        ip = bytes(p[IP])
        assert checksum(ip[:20]) == 0 and p[IP].ttl == (64 if calibration else 63)
        pseudo = bytes(p[IP])[12:20] + bytes([0, 17]) + len(bytes(p[UDP])).to_bytes(2, 'big')
        assert checksum(pseudo + bytes(p[UDP])) == 0
        assert p[Ether].src == (MACS['source'] if calibration else MACS['egress'])
    return {'packets_checked': len(packets), 'checksums': True, 'ttl': True, 'ethernet_rewrite': True}


def packet_sample(engine, directory, duration, rate, run_id, verify=False, profiling=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    c = engine.case
    receiver_log = (directory / 'receiver.log').open('w')
    generator_log = (directory / 'generator.log').open('w')
    rx = tx = probe = profiler = None
    before = engine.counters()
    cpu_before = cpu_snapshot(engine)
    events = []
    try:
        args = packet_args(engine, run_id, duration, rate, directory, receive=True)
        capture = directory / 'verification.pcap'
        if verify:
            args += ['--pcap', str(capture)]
        rx = engine.topology.sink.start([str(engine.tools/'bench-traffic-receiver'), *args], cpu=engine.cpus['receiver'], stdout=receiver_log, stderr=receiver_log)
        wait_ready(rx, receiver_log.name)
        measured_duration = duration + .4 if c.latency else duration
        args = packet_args(engine, run_id, measured_duration, rate, directory)
        tx = engine.topology.source.start([str(engine.tools/'bench-traffic-generator'), *args], cpu=engine.cpus['generator'], stdout=generator_log, stderr=generator_log)
        if profiling and engine.pulsar:
            profile_log = (directory/'perf.log').open('w')
            profiler = subprocess.Popen(['perf', 'record', '-e', 'cpu-clock', '-F', '199', '--call-graph', 'fp', '-p', str(engine.process.pid),
                                         '-o', str(directory/'perf.data'), '--', 'sleep', str(duration)], stdout=profile_log, stderr=profile_log)
        if c.latency:
            time.sleep(.15)
            args = packet_args(engine, run_id+1000000000, duration, 200, directory, probe=True)
            probe = engine.topology.source.start([str(engine.tools/'bench-traffic-probe'), *args], cpu=engine.cpus['probe'], stdout=generator_log, stderr=generator_log)
        if c.change:
            time.sleep(duration/2)
            engine.network('route', 'add', '198.19.0.0/24', 'via', '198.51.100.1', 'dev', 'r1')
            events.append({'event': 'route_add', 'time_ns': time.monotonic_ns()})
            engine.network('route', 'del', '198.19.0.0/24')
            events.append({'event': 'route_del', 'time_ns': time.monotonic_ns()})
        if tx.wait(timeout=measured_duration+15):
            raise RuntimeError(f'generator failed: {Path(generator_log.name).read_text()}')
        if probe and probe.wait(timeout=duration+5):
            raise RuntimeError('RTT probe validation failed')
        time.sleep(.25 if not c.unresolved else 3.2)
        terminate(rx)
        if rx.returncode:
            raise RuntimeError('receiver failed')
        cpu_after = cpu_snapshot(engine)
        after = engine.counters()
        sent, received = read_json(directory/'tx.json'), read_json(directory/'rx.json')
        assert not any(received[k] for k in ('invalid', 'duplicates', 'out_of_range', 'unexpected')), received
        assert sent['packets'] > 0
        planned = (sent['packets']+1)//2 if c.acl_pattern == 'drop' else 0
        expected = sent['packets']-planned
        assert received['unique'] <= expected
        if verify and not c.unresolved:
            assert received['unique'] == expected, (sent, received)
        end = max(sent['end_ns'], received['last_ns'])
        seconds = (end-sent['start_ns'])/1e9
        cpu = cpu_delta(cpu_before, cpu_after)
        tx_seconds = (sent['end_ns']-sent['start_ns'])/1e9
        witness = {}
        if engine.pulsar:
            old = {x['name']: x for x in before['nodes']['items'] if x.get('kind') == 'node'}
            new = {x['name']: x for x in after['nodes']['items'] if x.get('kind') == 'node'}
            witness = {name: new[name]['packets']-old[name]['packets'] for name in ('eth_input', 'ipv4_input', 'ipv4_acl', 'ipv4_forward', 'eth_output', 'tx')}
            assert witness['ipv4_forward'] >= received['unique']
            assert witness['ipv4_input'] > 0
            if c.unresolved:
                drops = {x['reason']: x['count'] for x in after['nodes']['items'] if x.get('kind') == 'drop'}
                assert drops.get('neighbour_resolution_timeout', 0) > 0
        pcap = check_packet_capture(capture, c, engine.name == 'calibration') if verify and not c.unresolved else None
        result = {'schema': 1, 'case': c.name, 'engine': engine.name, 'group': c.group, 'frame_bytes': c.size,
                  'configured_rate_pps': rate, 'offered_pps': sent['packets']/tx_seconds,
                  'delivered_pps': received['unique']/seconds, 'logical_frame_mbps': received['unique']*c.size*8/seconds/1e6,
                  'udp_payload_mbps': received['unique']*(c.size-42)*8/seconds/1e6,
                  'loss_fraction': (expected-received['unique'])/expected if expected else 0,
                  'sent': sent['packets'], 'received': received['unique'], 'intentional_drop_offered': planned,
                  'accepted_offered': expected, 'measurement_seconds': seconds, 'injection_seconds': tx_seconds,
                  'receiver_window_seconds': (received['end_ns']-received['start_ns'])/1e9,
                  'tail_seconds': max(0, received['last_ns']-sent['end_ns'])/1e9,
                  'sender_cpu_seconds': sent['user_seconds']+sent['system_seconds'],
                  'receiver_cpu_seconds': received['user_seconds']+received['system_seconds'],
                  'receiver_kernel_drops': received['kernel_drops'], 'cpu': cpu,
                  'metric_value': received['unique']/seconds, 'metric_unit': 'packets/s',
                  'valid': True, 'configuration': c.data(), 'forwarding_witness': witness, 'pcap': pcap,
                  'events': events, 'path': str(directory), 'tx': sent, 'rx': received}
        if probe:
            result['latency'] = read_json(directory/'probe.json')
        save(directory/'counters.json', {'before': before, 'after': after})
        save(directory/'cpu.json', {'before': cpu_before, 'after': cpu_after, 'delta': cpu})
        save(directory/'sample.json', result)
        if profiler:
            profiler.wait(timeout=duration+5)
            profile_log.close()
            if profiler.returncode == 0:
                report = subprocess.run(['perf', 'report', '--stdio', '--no-children', '--percent-limit', '0', '--field-separator', ';', '-i', str(directory/'perf.data')], text=True, capture_output=True)
                (directory/'perf-report.txt').write_text(report.stdout+report.stderr)
        return result
    finally:
        for p in (tx, probe, profiler, rx):
            terminate(p)
        receiver_log.close()
        generator_log.close()


def warm(engine, directory, run_id, duration):
    if engine.case.unresolved:
        return
    seconds = max(duration, engine.case.neighbours/50)
    packet_sample(engine, directory, seconds, 100, run_id, verify=True)
    engine.steady_neighbours()


def application_sample(engine, directory, duration, run_id):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    c = engine.case
    server_before = engine.server_snapshot()
    counters_before = engine.counters()
    cpu_before = cpu_snapshot(engine)
    processes, streams = [], []
    try:
        for index in range(c.services):
            output = directory/f'client-{index}.json'
            log = (directory/f'client-{index}.log').open('w')
            streams.append(log)
            if c.mode == 'sink':
                args = packet_args(engine, run_id+index, duration, c.rate, directory)
                # The native sender targets the local application; the server is the independent sink.
                output = directory/'tx.json'
                process = engine.topology.source.start([str(engine.tools/'bench-traffic-generator'), *args], cpu=engine.cpus['generator'], stdout=log, stderr=log)
            else:
                args = [str(engine.tools/'bench-socket-client'), '--kind', c.kind, '--mode', c.mode, '--port', str(9000+index),
                        '--address', engine.destination_base, '--output', str(output), '--duration', str(duration),
                        '--connections', str(c.connections), '--bytes', str(c.payload), '--run', str(run_id+index)]
                process = engine.topology.source.start(args, cpu=engine.cpus['generator'], stdout=log, stderr=log)
            processes.append((process, output))
        for process, _ in processes:
            if process.wait(timeout=duration+20):
                raise RuntimeError('application endpoint failed')
        time.sleep(.1)
        server_after = engine.server_snapshot()
        if c.mode == 'sink':
            deadline = time.monotonic()+3
            while time.monotonic()<deadline:
                previous = server_after
                time.sleep(.12)
                server_after = engine.server_snapshot()
                if [v['run_packets'] for v in previous] == [v['run_packets'] for v in server_after]:
                    break
            assert server_after[0]['current_run'] == run_id

        cpu_after = cpu_snapshot(engine)
        counters_after = engine.counters()
        values = [read_json(path) for _, path in processes]
        delta = [{key: b[key]-a[key] for key in ('packets', 'bytes', 'invalid', 'calls', 'accepted', 'unique', 'duplicates')}
                 for a, b in zip(server_before, server_after)]
        assert not sum(v['invalid']+v['duplicates'] for v in delta), delta
        assert not sum(v.get('invalid', 0) for v in values), values
        seconds = (max(v['end_ns'] for v in values)-min(v['start_ns'] for v in values))/1e9
        if c.mode == 'sink':
            delivered = sum(v['run_unique'] for v in server_after)
            sent = sum(v['packets'] for v in values)
            received_bytes = sum(v['run_bytes'] for v in server_after)
            seconds = (max(values[0]['end_ns'],server_after[0]['run_last_ns'])-values[0]['start_ns'])/1e9
            failures = 0
        else:
            delivered = sum(v['requests'] for v in values)
            sent = sum(v['submitted_bytes']//c.payload for v in values) if c.kind == 'udp' else delivered
            received_bytes = sum(v['delivered_bytes'] for v in values)
            failures = sum(v['failures'] for v in values)
        result = {'schema': 1, 'case': c.name, 'engine': engine.name, 'group': 'application', 'configuration': c.data(),
                  'valid': True, 'measurement_seconds': seconds, 'delivered_pps': delivered/seconds,
                  'application_goodput_mbps': received_bytes*8/seconds/1e6, 'received': delivered, 'sent': sent,
                  'loss_fraction': (sent-delivered)/sent if c.kind == 'udp' and sent else 0,
                  'connection_failures': failures, 'handshakes': sum(v.get('handshakes', 0) for v in values),
                  'cpu': cpu_delta(cpu_before, cpu_after), 'clients': values, 'server_delta': delta,
                  'metric_value': received_bytes*8/seconds/1e6 if c.kind == 'tcp' and c.mode == 'bulk' else delivered/seconds,
                  'metric_unit': 'Mbit/s' if c.kind == 'tcp' and c.mode == 'bulk' else ('connections/s' if c.mode == 'connect' else ('datagrams/s' if c.mode == 'sink' else 'requests/s')),
                  'path': str(directory)}
        if c.kind == 'tcp':
            result.pop('delivered_pps', None)
        if c.kind == 'udp':
            assert delivered <= sent
        save(directory/'counters.json', {'before': counters_before, 'after': counters_after})
        save(directory/'cpu.json', {'before': cpu_before, 'after': cpu_after})
        save(directory/'server-counters.json', {'before': server_before, 'after': server_after, 'delta': delta})
        save(directory/'sample.json', result)
        return result
    finally:
        for process, _ in processes:
            terminate(process)
        for stream in streams:
            stream.close()
