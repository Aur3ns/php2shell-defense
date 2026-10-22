#!/usr/bin/env python3
"""Offline JSONL ingest from specific vendor alert schemas; no network access."""
import argparse
import json
from pathlib import Path
from tools.adapters import normalize_many

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,choices=("suricata","falco","wazuh"))
    p.add_argument("--input",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--suricata-destination-host",
                   help="Map Suricata destination to the monitored hostname")
    a=p.parse_args()
    try:
        rows=[json.loads(x) for x in Path(a.input).read_text().splitlines() if x.strip()]
        identity={"suricata_destination_host":a.suricata_destination_host} if a.suricata_destination_host else {}
        norm=normalize_many(a.source,rows,identity)
        Path(a.output).write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in norm))
        print(f"{len(norm)} normalized records")
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        p.exit(2,f"Invalid input: {e}\n")
if __name__=="__main__":main()
