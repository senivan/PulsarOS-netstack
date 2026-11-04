"""Receiver-based summaries. No estimates are substituted for missing measurements."""
import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def metric(row):
    return row.get('metric_value', row.get('delivered_pps', 0))


def med(rows, key, default=0):
    return statistics.median(r.get(key, default) for r in rows)


def dump_csv(path, rows):
    if not rows:
        return
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, keys)
        writer.writeheader()
        writer.writerows(rows)


def regressions(groups, summary, threshold):
    result = []
    for row in summary:
        key = row['case']
        if row['engine'] != 'current' or (key, 'before') not in groups:
            continue
        current = {r['repetition']: r for r in groups[(key, 'current')]}
        old = {r['repetition']: r for r in groups[(key, 'before')]}
        pairs = [(current[i], old[i]) for i in sorted(current.keys() & old.keys())]
        change = row['median']/statistics.median(metric(b) for _, b in pairs)-1
        comparable = []
        for a, b in pairs:
            application = a['group'] == 'application'
            # Fixed-rate ceilings and receiver drops cannot establish dataplane regressions.
            if application:
                usable = not (a.get('connection_failures') or b.get('connection_failures'))
            else:
                usable = all(r.get('offered_pps', 0) > metric(r)*1.1 and
                             not r.get('receiver_kernel_drops', 0) and
                             r.get('configured_rate_pps') == 0 for r in (a, b))
            if usable and metric(b) > 0:
                comparable.append(metric(a)/metric(b)-1)
        bad = sum(value < -threshold for value in comparable)
        result.append({'case': key, 'change_fraction': change, 'paired_samples': len(pairs),
                       'eligible_pairs': len(comparable), 'paired_degraded': bad,
                       'inconclusive': len(comparable) < 7,
                       'fail': change < -threshold and bad >= 5 and len(comparable) >= 7})
    return result


def plots(directory, groups, summary):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return {'unavailable': 'install python3-matplotlib to generate plots'}
    output = directory/'plots'
    output.mkdir(exist_ok=True)
    generated = []

    def chart(name, title, xlabel, ylabel, select, xvalue, yvalue=lambda r: r['median']/1e6, logx=False, bounds=None):
        fig, ax = plt.subplots(figsize=(8, 4.8))
        count = 0
        for engine in ('calibration', 'before', 'current', 'linux'):
            rows = sorted([r for r in summary if r['engine'] == engine and select(r)], key=xvalue)
            if not rows:
                continue
            xs, ys = [xvalue(r) for r in rows], [yvalue(r) for r in rows]
            # Min/max is variability across repeated runs, not a confidence interval.
            factor = [yvalue(r)/r['median'] if r['median'] else 0 for r in rows]
            errors = [[(r['median']-r['minimum'])*f for r, f in zip(rows, factor)],
                      [(r['maximum']-r['median'])*f for r, f in zip(rows, factor)]]
            if bounds:
                errors = [[y-bounds(r)[0] for r,y in zip(rows,ys)],
                          [bounds(r)[1]-y for r,y in zip(rows,ys)]]
            ax.errorbar(xs, ys, yerr=errors, marker='o', capsize=3, label=engine)
            count += len(rows)
        if count:
            ax.set(title=title, xlabel=xlabel, ylabel=ylabel)
            if logx:
                ax.set_xscale('symlog', linthresh=1)
            ax.grid(alpha=.25)
            ax.legend()
            fig.tight_layout()
            for extension in ('png', 'svg'):
                fig.savefig(output/f'{name}.{extension}', dpi=140)
            generated.append(name)
        plt.close(fig)

    chart('frame-size', 'Verified forwarding: saturation load', 'Logical Ethernet frame bytes', 'Delivered Mpps',
          lambda r: r['group'] == 'forward' and r['configuration']['rate'] == 0,
          lambda r: r['configuration']['size'])
    for pattern in ('stable', 'multiple', 'worst', 'random'):
        chart('routes-'+pattern, 'Route scaling: '+pattern, 'Total unicast routes', 'Delivered Mpps',
              lambda r, p=pattern: r['group'] == 'route' and r['configuration']['pattern'] == p,
              lambda r: r['configuration']['routes'], logx=True)
    for pattern in ('miss', 'early', 'late', 'mixed'):
        chart('acl-'+pattern, 'Ingress ACL: '+pattern, 'Ordered ACL rules', 'Delivered Mpps',
              lambda r, p=pattern: r['group'] == 'acl' and r['configuration']['acl_pattern'] == p,
              lambda r: r['configuration']['acl'], logx=True)
    chart('policy', 'Policy rules: last rule selects a route', 'Policy rules', 'Delivered Mpps',
          lambda r: r['group'] == 'policy' and not r['configuration']['empty_tables'],
          lambda r: r['configuration']['policies'])
    chart('offered-delivered', '128-byte offered-load sweep', 'Actual offered Mpps', 'Delivered Mpps',
          lambda r: r['group'] == 'forward' and r['configuration']['size'] == 128,
          lambda r: r['median_offered_pps']/1e6)
    chart('loss', '128-byte loss versus actual offered load', 'Actual offered Mpps', 'Missing accepted traffic (%)',
          lambda r: r['group'] == 'forward' and r['configuration']['size'] == 128,
          lambda r: r['median_offered_pps']/1e6, lambda r: r['median_loss']*100,
          bounds=lambda r:(r['minimum_loss']*100,r['maximum_loss']*100))
    chart('cpu', 'Daemon CPU includes idle polling; Linux router CPU unavailable', 'ACL rules (all miss)',
          'Daemon CPU microseconds / delivered packet',
          lambda r: r['engine'] in ('current', 'before') and r['group'] == 'acl' and r['configuration']['acl_pattern'] == 'miss',
          lambda r: r['configuration']['acl'], lambda r: r['median_daemon_us_per_unit'],
          bounds=lambda r:(r['minimum_daemon_us_per_unit'],r['maximum_daemon_us_per_unit']))
    chart('udp-applications', 'Independent UDP echo applications', 'Application processes', 'Completed requests / second',
          lambda r: r['group'] == 'application' and r['configuration']['kind'] == 'udp' and r['configuration']['mode'] == 'rr',
          lambda r: r['configuration']['services'], lambda r: r['median'])
    chart('tcp-goodput', 'TCP echo, 8 KiB client flight cap per connection', 'Concurrent connections', 'Verified returned payload Mbit/s',
          lambda r: r['group'] == 'application' and r['configuration']['kind'] == 'tcp' and r['configuration']['mode'] == 'bulk',
          lambda r: r['configuration']['connections'], lambda r: r['median'])
    lookup = {(r['case'],r['engine']):r for r in summary}
    paired = [r for r in summary if r['engine']=='current' and (r['case'],'before') in lookup]
    if paired:
        fig, ax = plt.subplots(figsize=(10,5))
        ratios = [r['median']/lookup[(r['case'],'before')]['median'] for r in paired]
        ax.bar(range(len(paired)),ratios)
        ax.axhline(1,color='black',linewidth=1)
        ax.set_xticks(range(len(paired)),[r['case'] for r in paired],rotation=35,ha='right')
        ax.set(ylabel='Current median / historical median',title='Measured end-to-end change; scenarios have different rate units')
        fig.tight_layout();fig.savefig(output/'before-after.png',dpi=140);fig.savefig(output/'before-after.svg')
        plt.close(fig);generated.append('before-after')
    # Both bars retain their actual delivered rates; no line-rate normalization.
    names = [name for name in ('forward_128_rate0','policy_32_empty','acl_128_miss')
             if (name,'current') in lookup and (name,'linux') in lookup]
    if names:
        fig, ax = plt.subplots(figsize=(8,4.8))
        for index,engine in enumerate(('current','linux')):
            ax.bar([i+(index-.5)*.35 for i in range(len(names))],
                   [lookup[(name,engine)]['median']/1e6 for name in names],width=.35,label=engine)
        ax.set_xticks(range(len(names)),names)
        ax.set(ylabel='Verified delivered Mpps',title='Virtual paths; Linux saturation may be injection-limited')
        ax.legend();fig.tight_layout();fig.savefig(output/'linux-reference.png',dpi=140);fig.savefig(output/'linux-reference.svg')
        plt.close(fig);generated.append('linux-reference')
    # RTT probes use the same clock in one process and include both forwarding directions.
    fig, ax = plt.subplots(figsize=(8, 4.8))
    count = 0
    for engine in ('current', 'linux'):
        for percentile in ('p50_us', 'p90_us', 'p99_us'):
            rows = []
            for (case, name), values in groups.items():
                if name != engine or values[0]['group'] != 'latency':
                    continue
                data = [r['latency'][percentile] for r in values if r.get('latency', {}).get(percentile) is not None]
                if data:
                    rows.append((med(values, 'offered_pps')/1e6, statistics.median(data)))
            if rows:
                rows.sort()
                ax.plot(*zip(*rows), marker='o', label=engine+' '+percentile[:-3])
                count += 1
    if count:
        ax.set(xlabel='Actual background offered Mpps', ylabel='Successful round trip microseconds', title='UDP RTT; timeouts separate in raw data')
        ax.legend(); ax.grid(alpha=.25); fig.tight_layout()
        fig.savefig(output/'latency.png', dpi=140); fig.savefig(output/'latency.svg')
        generated.append('latency')
    plt.close(fig)
    return {'generated': generated, 'error_bars': 'sample minimum and maximum; not confidence intervals'}


def answers(summary):
    lookup = {(r['case'], r['engine']): r for r in summary}
    forwarding = [r for r in summary if r['engine'] == 'current' and r['group'] == 'forward']
    zero = [r for r in forwarding if r['maximum_loss'] == 0]
    sustainable = [r for r in forwarding if r['maximum_loss'] <= .001]
    maxrow = max(forwarding, key=lambda r:r['median'], default=None)
    def comparison(first, second, unit='throughput'):
        a, b = lookup.get((first, 'current')), lookup.get((second, 'current'))
        if not a or not b or not a['median']:
            return 'Insufficient measurements in this selection.'
        return f'{(b["median"]/a["median"]-1)*100:+.2f}% {unit}; {a["median"]:.0f} to {b["median"]:.0f} {a["metric_unit"]} (medians).'
    comparisons = []
    for name in ('forward_128_rate0', 'route_256_stable', 'route_256_worst', 'policy_32_empty'):
        old, new = lookup.get((name,'before')), lookup.get((name,'current'))
        if old and new and old['median']:
            comparisons.append(f'{name}: {new["median"]/old["median"]:.2f}× independently received throughput')
    return [
        f'Maximum measured median forwarding: {maxrow["median"]/1e6:.4f} Mpps in {maxrow["case"]}, median loss {maxrow["median_loss"]:.3%}.' if maxrow else 'Forwarding maximum: not measured.',
        ('Highest tested sustainable median (all samples ≤0.1% loss): '+f'{max(r["median"] for r in sustainable)/1e6:.4f} Mpps. ' if sustainable else 'No tested forwarding point satisfies ≤0.1% loss in all samples. ')+
        (f'Highest tested zero-loss median: {max(r["median"] for r in zero)/1e6:.4f} Mpps.' if zero else 'Zero-loss bound not established.')+' Discrete sweep only; no interpolated capacity.',
        '0 → 128 all-miss ACL rules: '+comparison('acl_0_miss','acl_128_miss'),
        'Default → 32 routing rules: '+comparison('policy_0','policy_32')+' Empty-table fallthrough: '+comparison('policy_0','policy_32_empty'),
        '1 → 256 stable routes: '+comparison('route_1_stable','route_256_stable')+' Read varied/worst distributions separately; the index remains linear within a table.',
        '; '.join(comparisons) if comparisons else 'No compatible historical revision measured; microbenchmark speedups cannot answer end-to-end improvement.',
        'Use actual offered load, independent RX, sink kernel drops, direct calibration and CPU profiles together. Loss at the receiver is not automatically a dataplane bottleneck; Linux no-loss saturation points are generator/path-limited lower bounds.',
        'Application delivery uses copied synchronous IPC. UDP requests/s and TCP returned Mbit/s are separate from forwarding packets/s; see application rows and IPC wall-time diagnostics.',
        'CPU operation attribution requires the separate cpu-clock profiles in profiling/. Hardware cycles are unavailable in this environment; per-thread CPU seconds include idle polling.',
        'Linux rows use identical veth data and offload settings but kernel forwarding versus DPDK AF_PACKET have different I/O/scheduling. This is a qualified virtual-path comparison, not a physical-NIC or universal kernel-versus-DPDK result.',
        'The reference ACL evaluates ordered rules linearly, stops at first match, and supports at most 128 rules here. Linux-only larger rulesets do not imply PulsarOS support.',
        'Choose the next optimization using the measured scenario-specific profiles. A routing microbenchmark alone cannot justify a forwarding change, and application IPC requires separate off-CPU evidence.'
    ]


def analyze(directory, threshold=.20):
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text())
    samples = [json.loads(line) for line in (directory/'raw_samples.jsonl').read_text().splitlines() if line.strip()]
    groups = defaultdict(list)
    for row in samples:
        if row['valid']:
            groups[(row['case'], row['engine'])].append(row)
    summary, raw, cpus, latency = [], [], [], []
    for (case, engine), rows in sorted(groups.items()):
        values = [metric(r) for r in rows]
        cpu_costs = [r['cpu']['cpu_seconds']*1e6/r['received'] for r in rows if r['received']]
        summary.append({'case': case, 'engine': engine, 'n': len(rows), 'median': statistics.median(values),
                        'minimum': min(values), 'maximum': max(values), 'stdev': statistics.stdev(values) if len(values)>1 else None,
                        'median_loss': med(rows,'loss_fraction'), 'minimum_loss': min(r.get('loss_fraction',0) for r in rows),
                        'maximum_loss': max(r.get('loss_fraction',0) for r in rows),
                        'median_offered_pps': med(rows,'offered_pps'),
                        'median_goodput_mbps': statistics.median(r.get('application_goodput_mbps', r.get('udp_payload_mbps',0)) for r in rows),
                        'median_daemon_us_per_unit': statistics.median(cpu_costs) if cpu_costs and engine in ('current','before') else None,
                        'minimum_daemon_us_per_unit': min(cpu_costs) if cpu_costs and engine in ('current','before') else None,
                        'maximum_daemon_us_per_unit': max(cpu_costs) if cpu_costs and engine in ('current','before') else None,
                        'receiver_kernel_drops': sum(r.get('receiver_kernel_drops',0) for r in rows),
                        'durations': sorted({r['requested_duration'] for r in rows}), 'group': rows[0]['group'],
                        'metric_unit': rows[0].get('metric_unit','packets/s'), 'configuration': rows[0]['configuration'], 'raw_values': values})
        for r in rows:
            raw.append({key: value for key,value in r.items() if not isinstance(value,(dict,list))})
            for t in r['cpu']['threads']:
                cpus.append({'case':case,'engine':engine,'repetition':r['repetition'],'window_seconds':r['cpu']['window_seconds'],**t})
            probes = [r['latency']] if 'latency' in r else r.get('clients',[])
            for i,p in enumerate(probes):
                if 'p50_us' in p:
                    latency.append({'case':case,'engine':engine,'repetition':r['repetition'],'client':i,
                                    **{k:p.get(k) for k in ('latency_samples','p50_us','p90_us','p99_us','p999_us','maximum_us','sent','received','failures')}})
    changes = regressions(groups,summary,threshold)
    figures = plots(directory,groups,summary) if not manifest.get('correctness_only') else {'omitted':'instrumented correctness run'}
    result = {'schema':2,'scenarios':summary,'regressions':changes,'plots':figures,'research_answers':answers(summary),
              'timing_claims_permitted':not manifest.get('correctness_only'), 'run_status':manifest['status']}
    (directory/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    dump_csv(directory/'throughput.csv',[{k:v for k,v in r.items() if k not in ('configuration','raw_values')} for r in summary])
    dump_csv(directory/'raw_samples.csv',raw); dump_csv(directory/'cpu.csv',cpus); dump_csv(directory/'latency.csv',latency)
    lines = ['# PulsarOS end-to-end benchmark report','',
             f'Run status: **{manifest["status"]}**. Requested sample: {manifest["duration_requested"]} s; repetitions: {manifest["repetitions"]}.',
             'Virtual interfaces; independently verified reception. No physical line-rate claim. Error bars show observed sample range.', '',
             '**Correctness-only instrumented run: these timings are not performance results.**' if manifest.get('correctness_only') else
             ('**Short exploratory samples:** confirm conclusions with ≥10-second samples. ' if manifest['duration_requested']<10 else 'Ten-second or longer measured intervals. ')+
             'Affinity does not isolate the physical host; inspect raw variation.', '',
             '| Case | Engine | n | Median | Unit | Min–max | Loss median |', '|---|---|---:|---:|---|---:|---:|']
    for r in summary:
        lines.append(f'| {r["case"]} | {r["engine"]} | {r["n"]} | {r["median"]:.2f} | {r["metric_unit"]} | {r["minimum"]:.2f}–{r["maximum"]:.2f} | {r["median_loss"]:.3%} |')
    lines += ['','## Research questions','']
    for i, answer in enumerate(result['research_answers'],1):
        lines += [f'{i}. {answer}','']
    lines += ['## Before/after regression checks','',
              'A failure requires ≥20% median decline (configurable) and at least five degraded pairs among seven eligible repetitions. '
              'Fixed-rate ceilings and receiver drops make forwarding comparisons inconclusive. This is a noise guard, not a statistical confidence test.','']
    for r in changes:
        lines.append(f'- {r["case"]}: {r["change_fraction"]:+.1%}; eligible pairs {r["eligible_pairs"]}; '+('**REGRESSION**' if r['fail'] else 'inconclusive' if r['inconclusive'] else 'no gated regression'))
    if (directory/'baseline-unavailable.json').exists():
        lines += ['', 'Historical comparison unavailable: '+(directory/'baseline-unavailable.json').read_text()]
    lines += ['','## Methodological boundaries','',
              'Logical frames include 14-byte Ethernet, 20-byte IPv4, 8-byte UDP; exclude FCS, preamble, IFG and VLANs. Minimum frame is 60 bytes without FCS. '
              'Delivered rate uses actual sender start to max(sender stop, last accepted receipt). Tail delivery is included; empty drain time is not. '
              'Offered rate counts successful sendmmsg submissions, not configured targets or wire reception. No-loss saturation is a generator/path-limited lower bound.', '',
              'TCP bulk reports independently verified returned payload Mbit/s; read completions are never called packets. '
              'UDP echo reports completed round trips; sink reports independently validated application datagrams. '
              'Linux uses the same simple server loop (1 ms idle sleep), not an optimized kernel socket benchmark. '
              'Raw sender/receiver calibrate their combined direct path, not physical Ethernet capability.', '',
              'Daemon CPU seconds include polling and control threads. Linux router work is softirq and has no attributable daemon PID; '
              'the absence of daemon CPU is not zero CPU cost. Raw endpoint rusage and /proc/stat snapshots accompany each case.', '',
              'ACL drop-eligible traffic is excluded from unexpected loss; ACL counters separately show observed decisions. '
              'Unresolved-neighbour loss is an expected negative test. Capacity limits and unavailable physical/hardware counters are recorded explicitly.', '',
              'Each case directory contains configuration queries, warmup captures, endpoint logs, raw counters and CPU windows. '
              'Use the manifest, failures.json and environment.json before comparing runs.']
    for name in figures.get('generated',[]):
        lines += ['',f'![{name}](plots/{name}.png)']
    (directory/'report.md').write_text('\n'.join(lines)+'\n')
    return any(r['fail'] for r in changes)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--threshold',type=float,default=.20)
    args=parser.parse_args()
    analyze(args.directory,args.threshold)
