"""Separate instrumented runs; never pooled with throughput samples."""
import re
import json
import subprocess
from pathlib import Path

from engine import Engine
from environment import save
from runner import application_sample, packet_sample, warm
from scenarios import matrix


def collect(build, cpus, output, selector='.*'):
    output = Path(output)
    output.mkdir(exist_ok=True)
    names = ('forward_128_rate0', 'route_256_stable', 'policy_32_empty', 'acl_128_miss', 'udp_receiver', 'tcp_bulk')
    results = []
    for case in matrix('standard'):
        if case.name not in names or not re.search(selector, case.name):
            continue
        engine = None
        try:
            engine = Engine('current', build, Path(build)/'bench', case, output/case.name, cpus)
            directory = engine.directory/'profile'
            directory.mkdir(exist_ok=True)
            if case.group == 'application':
                application_sample(engine, directory/'warmup', .5, 900000)
            else:
                warm(engine, directory/'warmup', 900000, .5)
            def kernel_links():
                return {name: json.loads(getattr(engine.topology, name).run('ip', '-j', '-s', 'link', 'show'))
                        for name in ('source', 'router', 'sink')}
            links_before = kernel_links()
            with (directory/'perf.log').open('w') as log:
                perf = subprocess.Popen(['perf', 'record', '-e', 'cpu-clock', '-F', '199', '--call-graph', 'fp',
                                         '-p', str(engine.process.pid), '-o', str(directory/'perf.data'), '--', 'sleep', '4'], stdout=log, stderr=log)
                try:
                    if case.group == 'application':
                        value = application_sample(engine, directory, 4, 900001)
                    else:
                        value = packet_sample(engine, directory, 4, 0, 900001)
                finally:
                    perf.wait(timeout=10)
            report = subprocess.run(['perf', 'report', '--stdio', '--no-children', '--percent-limit', '0',
                                     '--field-separator', ';', '-i', str(directory/'perf.data')], capture_output=True, text=True)
            (directory/'perf-report.txt').write_text(report.stdout+report.stderr)
            save(directory/'kernel-links.json', {'before': links_before, 'after': kernel_links()})
            entry = {'case': case.name, 'event': 'cpu-clock', 'returncode': perf.returncode,
                     'path': str(directory), 'instrumented_metric': value['metric_value'], 'metric_unit': value['metric_unit']}
            # This is a separate, perturbed wall-time diagnostic of synchronous SDK waits.
            if case.name == 'udp_receiver':
                try:
                    with (directory/'strace.log').open('w') as log:
                        trace = subprocess.Popen(['strace', '-f', '-c', '-w', '-p', str(engine.servers[0].pid),
                                                  '-o', str(directory/'ipc-syscalls.txt')], stdout=log, stderr=log)
                        try:
                            application_sample(engine, directory/'ipc-diagnostic', 3, 900002)
                        finally:
                            trace.terminate()
                            trace.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    entry['strace_unavailable'] = str(exc)
            results.append(entry)
        except Exception as exc:
            results.append({'case': case.name, 'unavailable': str(exc)})
        finally:
            if engine:
                engine.close()
    save(output/'manifest.json', {'instrumented': True, 'not_throughput_samples': True, 'profiles': results})
