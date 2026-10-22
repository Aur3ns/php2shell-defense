#!/usr/bin/env python3
"""Convert our existing DLT_RAW synthetic PCAP to Ethernet DLT_EN10MB.

This changes only the link-layer framing: the underlying IPv4 packets remain
byte-identical and contain no exploit material.
"""
import argparse
import struct
from pathlib import Path

def convert(source, destination):
    raw=Path(source).read_bytes()
    if len(raw)<24:
        raise ValueError("truncated PCAP header")
    magic=raw[:4]
    if magic != b"\xd4\xc3\xb2\xa1":
        raise ValueError("expected little-endian PCAP")
    if struct.unpack_from("<I",raw,20)[0]!=101:
        raise ValueError("expected DLT_RAW=101")
    output=bytearray(raw[:20]+struct.pack("<I",1))
    offset=24
    count=0
    while offset<len(raw):
        if len(raw)-offset<16:
            raise ValueError("truncated packet header")
        ts,us,caplen,wirelen=struct.unpack_from("<IIII",raw,offset)
        offset+=16
        if len(raw)-offset<caplen:
            raise ValueError("truncated packet")
        ipv4=raw[offset:offset+caplen]
        offset+=caplen
        if not ipv4 or ipv4[0] >> 4 != 4:
            raise ValueError("non-IPv4 input")
        eth=b"\x02\x00\x00\x00\x00\x01"+b"\x02\x00\x00\x00\x00\x02"+b"\x08\x00"
        output+=struct.pack("<IIII",ts,us,caplen+14,wirelen+14)+eth+ipv4
        count+=1
    Path(destination).write_bytes(output)
    return count

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    a=parser.parse_args()
    print(f"Wrapped {convert(a.source,a.destination)} IPv4 packets in Ethernet")
