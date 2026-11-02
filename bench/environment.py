"""Read-only discovery; unavailable controls are recorded, never guessed."""
import glob
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


def command(args):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=15)
        return {'command': args, 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'command': args, 'returncode': None, 'error': str(exc)}


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError as exc:
        return {'unavailable': str(exc)}


def discover(source, build):
    result = {'schema': 1, 'platform': platform.platform(), 'machine': platform.machine(),
              'uname': list(platform.uname()), 'allowed_cpus': sorted(os.sched_getaffinity(0)),
              'clock': 'CLOCK_MONOTONIC, same Linux kernel; no time namespaces',
              'virtual_environment': 'Docker/VM' if Path('/.dockerenv').exists() else 'host/unknown',
              'cpuinfo': read('/proc/cpuinfo'), 'meminfo': read('/proc/meminfo'),
              'status': read('/proc/self/status'), 'cpu_max': read('/sys/fs/cgroup/cpu.max'),
              'cpu_stat': read('/sys/fs/cgroup/cpu.stat'), 'cpuset': read('/sys/fs/cgroup/cpuset.cpus.effective'),
              'perf_event_paranoid': read('/proc/sys/kernel/perf_event_paranoid'),
              'numa_nodes': glob.glob('/sys/devices/system/node/node[0-9]*'),
              'hugepages': glob.glob('/sys/kernel/mm/hugepages/*'),
              'cpu_governors': {p: read(p) for p in glob.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor')},
              'cpu_frequencies': {p: read(p) for p in glob.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq')},
              'pci_devices': glob.glob('/sys/bus/pci/devices/*'),
              'dpdk_pmds': glob.glob('/usr/lib/*/dpdk/pmds-*/librte_net_*.so'),
              'build_cache': read(str(build / 'CMakeCache.txt')),
              'revision': command(['git', '-C', str(source), 'rev-parse', 'HEAD']),
              'working_tree': command(['git', '-C', str(source), 'status', '--porcelain']),
              'tracked_diff': command(['git', '-C', str(source), 'diff', 'HEAD']),
              'benchmark_source_sha256': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                          for p in sorted((source/'bench').rglob('*'))
                                          if p.is_file() and p.suffix in ('.c', '.h', '.py') and 'results' not in p.parts},
              'capabilities': {}, 'notes': ['CPU pinning does not isolate physical host CPUs.',
                 'Virtual Ethernet frame sizes exclude FCS, preamble and IFG.',
                 'Linux forwarding can execute softirq work on sender CPUs; it is not a pinned userspace worker.']}
    for name, args in {'lscpu': ['lscpu'], 'compiler': ['cc', '--version'], 'dpdk': ['pkg-config', '--modversion', 'libdpdk'],
                       'interfaces': ['ip', '-j', '-d', 'link', 'show'], 'nftables': ['nft', '--version'],
                       'perf_hardware': ['perf', 'stat', '-e', 'cycles,instructions', 'true'],
                       'perf_software': ['perf', 'record', '-e', 'cpu-clock', '-o', '/tmp/pulsaros-bench-perf-probe.data', '--', 'sleep', '0.1']}.items():
        result[name] = command(args)
    result['timestamping'] = {name: command(['ethtool', '-T', name]) for name in os.listdir('/sys/class/net')}
    result['capabilities'] = {'virtual_interfaces': os.geteuid() == 0,
                              'physical_nic_benchmark': False,
                              'physical_reason': 'No dedicated physical dataplane NIC was selected; management interfaces are never reused.',
                              'hardware_cycles': result['perf_hardware']['returncode'] == 0 and '<not supported>' not in result['perf_hardware'].get('stderr', ''),
                              'software_profiling': result['perf_software']['returncode'] == 0,
                              'one_way_latency': False,
                              'round_trip_latency': True}
    return result


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
