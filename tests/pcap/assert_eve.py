#!/usr/bin/env python3
"""Verify Suricata emitted exactly the expected alerts for each synthetic flow."""
import json
import sys
from pathlib import Path

def check(eve, expected):
    wanted={row["src_ip"] for row in expected if row["expected_sid_9900101"]}
    found=set()
    for line in Path(eve).read_text().splitlines():
        row=json.loads(line)
        if row.get("event_type")=="alert" and row.get("alert",{}).get("signature_id")==9900101:
            found.add(row["src_ip"])
    if found != wanted:
        raise AssertionError(f"Expected alerts {sorted(wanted)}; observed {sorted(found)}")
    print("PASS: expected heuristic alerts, including documented false positives")
if __name__=="__main__":
    check(sys.argv[1],json.loads(Path(sys.argv[2]).read_text()))
