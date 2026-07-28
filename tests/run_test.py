import json, pathlib, struct, subprocess, sys

exe = pathlib.Path(sys.argv[1])
outdir = pathlib.Path(sys.argv[2])
pcap = outdir / 'sample.pcap'
report = outdir / 'report.json'

def ip(a): return bytes(map(int, a.split('.')))
def eth(payload): return b'\x00'*12 + b'\x08\x00' + payload

def ipv4(proto, src, dst, payload):
    total = 20 + len(payload)
    return bytes([0x45,0, total>>8,total&255,0,1,0,0,64,proto,0,0]) + ip(src)+ip(dst)+payload

def udp(srcp,dstp,payload):
    length=8+len(payload)
    return struct.pack('!HHHH',srcp,dstp,length,0)+payload

def tcp(srcp,dstp):
    return struct.pack('!HHIIHHHH',srcp,dstp,1,0,0x5002,65535,0,0)

def dns_query(name):
    q=b''
    for part in name.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\0' + struct.pack('!HH',1,1)
    return struct.pack('!HHHHHH',0x1234,0x0100,1,0,0,0)+q

packets=[
    eth(ipv4(17,'192.168.1.10','1.1.1.1',udp(53000,53,dns_query('example.com')))),
    eth(ipv4(6,'192.168.1.10','192.168.1.20',tcp(50000,443)))
]
with pcap.open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i,p in enumerate(packets):
        f.write(struct.pack('<IIII',i,0,len(p),len(p))); f.write(p)

result=subprocess.run([str(exe),str(pcap),'--json',str(report)],capture_output=True,text=True)
print(result.stdout)
if result.returncode != 0:
    print(result.stderr,file=sys.stderr); sys.exit(result.returncode)
data=json.loads(report.read_text())
assert data['packets']==2
assert data['protocols']['udp']==1 and data['protocols']['tcp']==1
assert data['dnsQueries']['example.com']==1
print('packetlens test passed')
