"""Post-run checks on saved counters; independent endpoint verification remains mandatory."""
import argparse
import json
from pathlib import Path


def verify(row, root=None):
    directory = Path(root)/(row.get('relative_path') or f'cases/{row["case"]}/{row["engine"]}/rep-{row["repetition"]}') if root else Path(row['path'])
    counters = json.loads((directory/'counters.json').read_text())
    result = {'case':row['case'],'engine':row['engine'],'path':str(directory),'passed':True}
    if row['engine'] not in ('current','before'):
        return result
    before, after = counters['before'], counters['after']
    old = {v['reason']:v['count'] for v in before['nodes']['items'] if v.get('kind')=='drop'}
    drops = {v['reason']:v['count']-old.get(v['reason'],0) for v in after['nodes']['items'] if v.get('kind')=='drop'}
    unexpected = {k:v for k,v in drops.items() if v and any(t in k for t in ('checksum','invalid_ipv4','invalid_udp','invalid_tcp','no_route','graph_overflow'))}
    result['unexpected_protocol_drops'] = unexpected
    if unexpected:
        result['passed'] = False
    c = row['configuration']
    if row['group']=='acl':
        first = before['acl']['items']; last = after['acl']['items']
        counts = [b.get('packets',0)-a.get('packets',0) for a,b in zip(first[:-1],last[:-1])]
        default = last[-1]['default_matches']-first[-1]['default_matches']
        accepted = last[-1]['accepted']-first[-1]['accepted']
        dropped = last[-1]['dropped']-first[-1]['dropped']
        result.update(rule_matches=counts,default_matches=default,accepted=accepted,dropped=dropped)
        pattern = c['acl_pattern']
        valid = accepted >= row['received']
        if pattern=='miss':
            valid = valid and sum(counts)==0 and default>0
        if pattern=='early':
            valid = valid and counts[0]>0 and sum(counts[1:])==0 and default==0
        if pattern=='late':
            valid = valid and counts[-1]>0 and sum(counts[:-1])==0 and default==0
        if pattern=='mixed':
            valid = valid and all(v>0 for v in counts) and default>0
        if pattern=='drop':
            valid = valid and dropped>0 and row['intentional_drop_offered']>0
        result['passed'] = result['passed'] and valid
    return result


def main(directory):
    rows = [json.loads(line) for line in (directory/'raw_samples.jsonl').read_text().splitlines()]
    results = []
    for row in rows:
        try:
            results.append(verify(row, directory))
        except Exception as exc:
            results.append({'path':row['path'],'passed':False,'error':str(exc)})
    output = {'schema':1,'passed':all(r['passed'] for r in results),'samples_checked':len(results),'samples':results}
    (directory/'correctness.json').write_text(json.dumps(output,indent=2)+'\n')
    return output['passed']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    raise SystemExit(0 if main(parser.parse_args().directory) else 1)
