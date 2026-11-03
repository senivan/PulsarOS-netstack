#!/usr/bin/env python3
"""Run real native traffic through isolated PulsarOS/Linux networking paths."""
import argparse
import json
import os
import random
import re
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

from engine import Engine
from environment import discover, save
from runner import application_sample, packet_sample, warm
from scenarios import eligible, matrix, unsupported

SOURCE = Path(__file__).resolve().parents[1]


def interrupted(signum, frame):
    raise KeyboardInterrupt(f'benchmark interrupted by signal {signum}')


def build_release(build, source, output):
    build = Path(build).resolve()
    with (output/'build.log').open('a') as log:
        subprocess.run(['cmake', '-S', str(source), '-B', str(build), '-DCMAKE_BUILD_TYPE=Release',
                        '-DPULSAROS_BUILD_BENCHMARKS=ON', '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -g -fno-omit-frame-pointer'],
                       check=True, stdout=log, stderr=log)
        subprocess.run(['cmake', '--build', str(build), '-j4'], check=True, stdout=log, stderr=log)
    return build


def baseline(args, output):
    if args.baseline_build:
        build = Path(args.baseline_build).resolve()
        metadata = build.parent/'baseline.json'
        if metadata.exists():
            save(output/'baseline.json', {**json.loads(metadata.read_text()), 'reused_build': True})
        else:
            save(output/'baseline.json', {'build': str(build), 'revision': args.baseline_ref,
                                        'warning': 'caller-provided build; source identity not independently recovered'})
        return build
    if not args.baseline_ref:
        return None
    revision = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', args.baseline_ref], text=True).strip()
    root = output/'baseline-source'
    root.mkdir(exist_ok=True)
    archive = subprocess.Popen(['git', '-C', str(SOURCE), 'archive', revision], stdout=subprocess.PIPE)
    subprocess.run(['tar', '-x', '-C', str(root)], stdin=archive.stdout, check=True)
    archive.stdout.close()
    if archive.wait():
        raise RuntimeError('baseline archive failed')
    if not (root/'include/admin.h').exists():
        save(output/'baseline-unavailable.json', {'revision': revision, 'reason': 'revision predates compatible daemon management API'})
        return None
    build = build_release(output/'baseline-build', root, output)
    save(output/'baseline.json', {'revision': revision, 'source': str(root), 'build': str(build), 'flags': '-O3 -DNDEBUG -g -fno-omit-frame-pointer'})
    return build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('quick', 'standard', 'full'), default='quick')
    parser.add_argument('--duration', type=float)
    parser.add_argument('--repetitions', type=int)
    parser.add_argument('--warmup', type=float)
    parser.add_argument('--output', type=Path, default=SOURCE/'bench/results'/time.strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--build', type=Path, default=SOURCE/'build-release')
    parser.add_argument('--baseline-build', type=Path)
    parser.add_argument('--baseline-ref')
    parser.add_argument('--engines', default='current,linux,calibration')
    parser.add_argument('--select', default='.*', help='regular expression matching scenario names')
    parser.add_argument('--seed', type=int, default=42, help='scenario ordering seed; packet datasets use fixed seed 42')
    parser.add_argument('--no-profiling', action='store_true')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--correctness-only', action='store_true', help='allow instrumented/debug builds; never performance results')
    parser.add_argument('--fail-on-regression', action='store_true')
    parser.add_argument('--regression-threshold', type=float, default=.20)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux with network-namespace/AF_PACKET capabilities is required; see bench/README.md for Docker invocation')
    duration = args.duration if args.duration is not None else (.5 if args.profile == 'quick' else 10.)
    repetitions = args.repetitions if args.repetitions is not None else (1 if args.profile == 'quick' else 7)
    warmup = args.warmup if args.warmup is not None else (.15 if args.profile == 'quick' else 1.)
    if not 0 < duration <= 3600 or repetitions < 1 or warmup < 0:
        parser.error('invalid duration, repetitions, or warmup')
    output = args.output.resolve()
    if (output/'raw_samples.jsonl').exists():
        parser.error('output already contains measurements; select a fresh output directory')
    output.mkdir(parents=True, exist_ok=True)
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 4:
        parser.error('at least four available logical CPUs are needed for distinct worker, control, generator, receiver affinity')
    assignment = {'dataplane': cpus[0], 'control': cpus[1], 'generator': cpus[2], 'receiver': cpus[3],
                  'probe': cpus[4] if len(cpus)>4 else cpus[1], 'applications': cpus[4:] or [cpus[3]]}
    os.sched_setaffinity(0, {assignment['control']})
    # Child tools explicitly override this affinity; discover records the original allowance too.
    current = args.build.resolve() if args.skip_build else build_release(args.build, SOURCE, output)
    cache=(current/'CMakeCache.txt').read_text()
    if not args.correctness_only and ('CMAKE_BUILD_TYPE:STRING=Release' not in cache or '-fsanitize=' in cache):
        parser.error('performance measurements require a non-sanitized Release build')
    if not (current/'bench/bench-traffic-generator').exists():
        parser.error('native benchmark tools are missing; enable PULSAROS_BUILD_BENCHMARKS')
    environment = discover(SOURCE, current)
    environment['original_allowed_cpus'] = cpus
    environment['assignment'] = assignment
    save(output/'environment.json', environment)
    before = baseline(args, output)
    names = [name.strip() for name in args.engines.split(',')]
    if before and 'before' not in names:
        names.append('before')
    if any(name not in ('current', 'before', 'linux', 'calibration') for name in names):
        parser.error('unknown engine')
    if 'before' in names and not before:
        parser.error('before engine requires a compatible baseline build/revision')
    cases = [c for c in matrix(args.profile) if re.search(args.select, c.name)]
    if not cases:
        parser.error('selector matched no cases')
    rng = random.Random(args.seed)
    calibrations = [c for c in cases if c.group == 'calibration']
    other = [c for c in cases if c.group != 'calibration']
    rng.shuffle(other)
    cases = calibrations + other
    manifest = {'schema': 1, 'profile': args.profile, 'duration_requested': duration, 'repetitions': repetitions,
                'warmup': warmup, 'seed': args.seed, 'ordering_seed': args.seed, 'packet_seed': 42,
                'engines': names, 'source': str(SOURCE), 'current_build': str(current),
                'baseline_build': str(before) if before else None, 'baseline_ref': args.baseline_ref,
                'cases': [c.data() for c in cases], 'unsupported': unsupported(), 'assignment': assignment,
                'loss_threshold': .001, 'started_ns': time.monotonic_ns(), 'selector': args.select,
                'correctness_only': args.correctness_only, 'measurement_scope': 'virtual-interface end-to-end; no physical line-rate claims', 'status': 'running'}
    save(output/'manifest.json', manifest)
    save(output/'unsupported.json', unsupported())
    failures, samples = [], []
    raw = (output/'raw_samples.jsonl').open('w', buffering=1)
    run_id = 10000
    try:
        for case_index, case in enumerate(cases):
            engines = [name for name in names if eligible(case, name, args.profile)]
            if not engines:
                continue
            print(f'[{case_index+1}/{len(cases)}] {case.name}: {engines}', flush=True)
            # Application sessions must not be suspended across their IPC deadlines.
            groups = [[name] for name in engines] if case.group == 'application' else [engines]
            if case.group == 'application':
                rng.shuffle(groups)
            for group in groups:
                active = []
                try:
                    for name in group:
                        try:
                            engine = Engine(name, before if name == 'before' else current, current/'bench', case,
                                            output/'cases'/case.name/name, assignment)
                            active.append(engine)
                            engine.pause()
                        except Exception as exc:
                            failures.append({'case': case.name, 'engine': name, 'startup': str(exc)})
                            print(f'  {name} startup failed: {exc}', file=sys.stderr, flush=True)
                    for repetition in range(repetitions):
                        order = list(active)
                        if repetition % 2:
                            order.reverse()
                        for engine in order:
                            engine.resume()
                            directory = engine.directory/f'rep-{repetition}'
                            run_id += 100
                            if case.group == 'application':
                                check = application_sample(engine, directory/'warmup', max(.3, warmup), run_id)
                                if check['received'] == 0:
                                    raise RuntimeError('application warmup delivered nothing')
                            elif case.cold:
                                engine.network('neigh', 'flush', 'dev', 'r1')
                            else:
                                warm(engine, directory/'warmup', run_id, warmup)
                            run_id += 1
                            value = (application_sample(engine, directory, duration, run_id) if case.group == 'application'
                                     else packet_sample(engine, directory, duration, case.rate, run_id))
                            value['repetition'] = repetition
                            value['requested_duration'] = duration
                            value['relative_path'] = str(directory.relative_to(output))
                            raw.write(json.dumps(value, sort_keys=True)+'\n')
                            samples.append(value)
                            engine.pause()
                            print(f'  {engine.name} {repetition+1}/{repetitions}: {value["metric_value"]:.2f} {value["metric_unit"]}, loss={value.get("loss_fraction",0):.4%}', flush=True)
                except Exception as exc:
                    failures.append({'case': case.name, 'engines': group, 'error': str(exc),
                                     'traceback': traceback.format_exc()})
                    print(traceback.format_exc(), file=sys.stderr, flush=True)
                finally:
                    for engine in reversed(active):
                        try:
                            engine.close()
                        except Exception as exc:
                            failures.append({'case': case.name, 'engine': engine.name, 'cleanup': str(exc)})
        if not args.no_profiling and args.profile != 'quick' and environment['capabilities']['software_profiling']:
            from profiling import collect
            collect(current, assignment, output/'profiling', args.select)
        if not samples:
            failures.append({'error': 'no supported benchmark produced measurements'})
        manifest['status'] = 'failed' if failures else 'complete'
    except BaseException as exc:
        failures.append({'error': str(exc), 'traceback': traceback.format_exc()})
        manifest['status'] = 'failed'
        print(traceback.format_exc(), file=sys.stderr)
    finally:
        raw.close()
        manifest['finished_ns'] = time.monotonic_ns()
        manifest['samples'] = len(samples)
        save(output/'manifest.json', manifest)
        save(output/'failures.json', failures)
        from validate import main as validate
        if not validate(output):
            checks = json.loads((output/'correctness.json').read_text())
            rejected = {r['path'] for r in checks['samples'] if not r['passed']}
            for value in samples:
                if value['path'] in rejected:
                    value['valid'] = False
            (output/'raw_samples.jsonl').write_text(''.join(json.dumps(v, sort_keys=True)+'\n' for v in samples))
            failures.append({'error': 'saved-counter validation rejected samples', 'paths': sorted(rejected)})
            manifest['status'] = 'failed'
            save(output/'manifest.json', manifest)
            save(output/'failures.json', failures)
        from analysis.report import analyze
        regression = analyze(output, args.regression_threshold)
    if failures:
        return 1
    if args.fail_on_regression and regression:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
