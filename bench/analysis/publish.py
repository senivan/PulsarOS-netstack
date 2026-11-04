#!/usr/bin/env python3
"""Export compact, portable measured evidence without build trees or packet dumps."""
import argparse
import csv
import hashlib
import json
import re
import shutil
from pathlib import Path


def publish(name, source, destination):
    manifest = json.loads((source/'manifest.json').read_text())
    if manifest['status'] != 'complete':
        raise ValueError(f'{name}: incomplete run cannot be published as successful')
    correctness = json.loads((source/'correctness.json').read_text())
    if not correctness['passed']:
        raise ValueError(f'{name}: saved-counter verification failed')
    output = destination/name
    output.mkdir(parents=True, exist_ok=True)
    for filename in ('manifest.json','summary.json','throughput.csv','latency.csv'):
        if (source/filename).exists():
            shutil.copyfile(source/filename,output/filename)
    env = json.loads((source/'environment.json').read_text())
    keys = ('platform','machine','uname','cpuinfo','lscpu','compiler','dpdk','cpu_max','cpuset',
            'original_allowed_cpus','assignment','cpu_governors','cpu_frequencies','capabilities',
            'revision','working_tree','benchmark_source_sha256','notes')
    (output/'environment.json').write_text(json.dumps({key:env.get(key) for key in keys},indent=2)+'\n')
    (output/'correctness.json').write_text(json.dumps({key:value for key,value in correctness.items() if key!='samples'},indent=2)+'\n')
    fields = ('case','engine','repetition','requested_duration','measurement_seconds','sent','received',
              'accepted_offered','intentional_drop_offered','offered_pps','metric_value','metric_unit',
              'loss_fraction','receiver_kernel_drops','application_goodput_mbps','delivered_bytes','cpu_seconds',
              'sender_cpu_seconds','receiver_cpu_seconds','valid')
    with (output/'samples.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fields,lineterminator="\n")
        writer.writeheader()
        for line in (source/'raw_samples.jsonl').read_text().splitlines():
            row=json.loads(line)
            row['cpu_seconds']=row['cpu']['cpu_seconds']
            if row['group']=='application':
                if row['configuration']['mode']=='sink':
                    path=source/'cases'/row['case']/row['engine']/f'rep-{row["repetition"]}'/'server-counters.json'
                    row['delivered_bytes']=sum(v['run_bytes'] for v in json.loads(path.read_text())['after'])
                else:
                    row['delivered_bytes']=sum(v['delivered_bytes'] for v in row['clients'])
                row['sender_cpu_seconds']=sum(v['user_seconds']+v['system_seconds'] for v in row['clients'])
            writer.writerow({key:row.get(key) for key in fields})
    selected = {'primary':('frame-size','acl-miss','policy','offered-delivered','loss','udp-applications','tcp-goodput','before-after','latency'),
                'controlled':('routes-stable',)}.get(name,())
    if selected:
        (output/'plots').mkdir(exist_ok=True)
        for figure in selected:
            path=source/'plots'/f'{figure}.png'
            if path.exists():
                shutil.copyfile(path,output/'plots'/path.name)
    if (source/'profiling/manifest.json').exists():
        profiles=[]
        for path in sorted((source/'profiling').glob('*/profile/perf-report.txt')):
            flat=[]
            for line in path.read_text().splitlines():
                if re.match(r'^\s*[0-9.]+%\s*;',line):
                    parts=[p.strip() for p in line.split(';')]
                    flat.append({'percent':float(parts[0].rstrip('%')),'object':parts[2],'symbol':parts[3]})
            entry={'case':path.parent.parent.name,'flat_top20':flat[:20],
                   'kernel_self_percent':sum(r['percent'] for r in flat if r['object']=='[kernel.kallsyms]')}
            for filename in ('kernel-links.json','sample.json','counters.json'):
                if (path.parent/filename).exists():
                    entry[filename]=json.loads((path.parent/filename).read_text())
            trace=path.parent/'ipc-syscalls.txt'
            if trace.exists():
                entry['ipc_wall_time']=trace.read_text()
            profiles.append(entry)
        (output/'profiles.json').write_text(json.dumps({'instrumented_not_headline':True,'profiles':profiles},indent=2)+'\n')
    return {'name':name,'full_evidence_path':str(source),'samples':manifest['samples'],
            'duration_requested':manifest['duration_requested'],'repetitions':manifest['repetitions']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='append',required=True,help='label=completed run directory; cohorts are never pooled')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('select a fresh output directory')
    args.output.mkdir(parents=True,exist_ok=True)
    runs=[]
    for item in args.run:
        name,path=item.split('=',1)
        if not name.replace('-','').isalnum():
            parser.error('invalid label')
        runs.append(publish(name,Path(path),args.output))
    (args.output/'index.json').write_text(json.dumps({'schema':1,'cohorts_not_pooled':True,'runs':runs},indent=2)+'\n')
    hashes={str(p.relative_to(args.output)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(args.output.rglob('*')) if p.is_file() and p.name!='sha256.json'}
    (args.output/'sha256.json').write_text(json.dumps(hashes,indent=2)+'\n')


if __name__=='__main__':
    main()
