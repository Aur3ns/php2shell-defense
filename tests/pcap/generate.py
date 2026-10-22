#!/usr/bin/env python3
"""Deterministic, dependency-free synthetic HTTP/TCP PCAP generator.

Creates 4 separate sessions. Traffic is benign and contains no exploit payloads.
The source addresses use RFC 5737 documentation address ranges.
"""
import json
import socket
import struct
from pathlib import Path

def checksum(data):
    if len(data) % 2: data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def packet(src, dst, sport, dport, seq, ack, flags, data, ipid):
    sa, da = socket.inet_aton(src), socket.inet_aton(dst)
    tcph = struct.pack("!HHIIHHHH",sport,dport,seq,ack,(5<<12)|flags,65535,0,0)
    pseudo = sa+da+struct.pack("!BBH",0,6,len(tcph)+len(data))
    c = checksum(pseudo+tcph+data)
    tcph = tcph[:16]+struct.pack("!H",c)+tcph[18:]
    ip = struct.pack("!BBHHHBBH4s4s",0x45,0,len(tcph)+len(data)+20,ipid,0,64,6,0,sa,da)
    ip = ip[:10]+struct.pack("!H",checksum(ip))+ip[12:]
    return ip+tcph+data

def make(dest):
    dest=Path(dest);dest.mkdir(parents=True,exist_ok=True)
    frames=[]; expected=[]
    # Heuristic tests only. Large legitimate requests intentionally produce false positives.
    cases=[
      ("small_php","/index.php",128,False),
      ("large_php_upload","/upload.php",350000,True),
      ("large_nonphp","/api/upload",350000,False),
      ("large_php_report","/report.php",450000,True),
    ]
    for i,(name,path,declared,hit) in enumerate(cases):
        src=f"198.51.100.{10+i}";dst="192.0.2.10"; sport=20000+i
        body=b"x"*declared
        request=(f"POST {path} HTTP/1.1\r\nHost: demo.invalid\r\nContent-Length: {declared}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n").encode()+body
        # 3-way handshake; chunk payload into valid TCP segments to ensure reassembly.
        packets=[packet(src,dst,sport,80,1000,0,2,b"",10+i),
                 packet(dst,src,80,sport,5000,1001,18,b"",20+i),
                 packet(src,dst,sport,80,1001,5001,16,b"",30+i)]
        seq=1001
        for off in range(0,len(request),1300):
            chunk=request[off:off+1300]
            packets.append(packet(src,dst,sport,80,seq,5001,24,chunk,100+i*1000+off//1300))
            seq+=len(chunk)
        packets.append(packet(dst,src,80,sport,5001,seq,24,b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",40+i))
        packets.append(packet(src,dst,sport,80,seq,5041,17,b"",50+i))
        frames.extend(packets)
        expected.append({"name":name,"src_ip":src,"expected_sid_9900101":hit})
    with (dest/"synthetic-http.pcap").open("wb") as out:
        out.write(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,101))
        for i,p in enumerate(frames):
            out.write(struct.pack("<IIII",1761150000+i//1000000,i%1000000,len(p),len(p)));out.write(p)
    (dest/"expected.json").write_text(json.dumps(expected,indent=2)+"\n")
    return expected

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--output",default="build/pcap")
    args=p.parse_args()
    print(json.dumps(make(args.output),indent=2))
