#!/usr/bin/env python3
"""Check Zeek notice output on the standalone synthetic PCAP."""
import csv
import sys
from pathlib import Path

def check(path):
    file=Path(path)
    if not file.is_file():
        raise AssertionError("Zeek did not create notice.log")
    fields=[]
    hits=[]
    for line in file.read_text().splitlines():
        if line.startswith("#fields\t"):
            fields=line.split("\t")[1:]
        elif line and not line.startswith("#"):
            if not fields:
                raise AssertionError("missing Zeek TSV field header")
            parts=line.split("\t")
            row=dict(zip(fields,parts))
            if "PHP2SHELLDefense::Large_PHP_POST" in row.get("note",""):
                hits.append(row)
    # Synthetic fixture has two large PHP POST requests, both benign.
    if len(hits)!=2:
        raise AssertionError(f"expected two generic notices; got {len(hits)}")
    print("PASS: Zeek notices for two synthetic large PHP POSTs (not exploit evidence)")

if __name__=="__main__":
    check(sys.argv[1])
