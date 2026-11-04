#!/usr/bin/env python3
"""Inject deliberate corruption, loss, duplication and 16-bit IP-ID wrap. Not a speed test."""
import argparse
import json
import subprocess
import time
from pathlib import Path

from topology import MACS, Topology, terminate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    binary = args.build.resolve()/'bench/bench-traffic-generator'
    for option, value in (('--sport','4294967295'),('--dport','4294967295'),('--duration','nan'),('--size','59'),('--flows','0')):
        result = subprocess.run([str(binary),'--interface','no-bench-device','--output',str(args.output/'invalid.json'),option,value],capture_output=True,timeout=3)
        assert result.returncode == 2, (option,result.returncode,result.stderr)
    topology = Topology(args.output, direct=True)
    receiver = None
    try:
        output = args.output/'rx.json'
        with (args.output/'receiver.log').open('w') as log:
            receiver = topology.sink.start([str(args.build.resolve()/'bench/bench-traffic-receiver'),
                '--interface','d0','--output',str(output.resolve()),'--src','192.0.2.1','--dst','198.51.100.1',
                '--src-mac',MACS['source'],'--dst-mac',MACS['sink'],'--ttl','64','--run','7','--sequence-limit','65538'], stdout=log,stderr=log)
            time.sleep(.2)
            if receiver.poll() is not None:
                raise RuntimeError('receiver failed to start')
            script = '''
from scapy.all import Ether, IP, UDP, Raw, sendp
import struct
frames=[]
for seq,run,fault in [(0,7,0),(1,7,0),(1,7,0),(3,7,0),(65536,7,0),(4,7,1),(5,7,2),(6,8,0)]:
    payload=struct.pack('!IIQ',0x50534231,run,seq)+bytes((seq+i*17+42)&255 for i in range(16,86))
    p=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='198.51.100.1',ttl=64,flags='DF',id=seq&65535)/UDP(sport=20000,dport=9000)/Raw(payload)
    data=bytearray(bytes(p))
    if fault==1:data[-1]^=1
    if fault==2:data[24]^=1
    frames.append(Ether(bytes(data)))
sendp(frames,iface='g0',inter=.01,verbose=False)
'''
            topology.source.run('python3','-c',script)
            time.sleep(.2)
            terminate(receiver)
        value = json.loads(output.read_text())
        for key, expected in {'packets':5,'unique':4,'duplicates':1,'invalid':2,'unexpected':1,
                              'highest_sequence':65536,'ipv4_id_wraps':1,'missing_below_highest':65533}.items():
            assert value[key] == expected, (key,value)
        assert receiver.returncode == 0
        (args.output/'correctness.json').write_text(json.dumps({'passed':True,'observed':value},indent=2)+'\n')
        print('Endpoint corruption, duplication, missing sequence and IPv4-ID wrap checks passed')
    finally:
        terminate(receiver)
        topology.close()


if __name__ == '__main__':
    main()
