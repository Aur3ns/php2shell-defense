#!/usr/bin/env python3
"""Offline, read-only heuristic event correlator. No exploit recognition claim."""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone

ALLOWED = {"http_anomaly", "php_memory_error", "web_child_process"}
WEIGHT = {"http_anomaly": 1, "php_memory_error": 1, "web_child_process": 2}

def parse_timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)

def correlate(events, window=120):
    by_host = defaultdict(list)
    for e in events:
        if not isinstance(e, dict) or e.get("kind") not in ALLOWED:
            raise ValueError("unsupported event kind")
        host = e.get("host")
        if not isinstance(host, str) or not host or len(host) > 255:
            raise ValueError("invalid host")
        by_host[host].append((parse_timestamp(e["timestamp"]), e["kind"]))
    alerts = []
    for host, items in sorted(by_host.items()):
        items.sort()
        for i, (now, kind) in enumerate(items):
            previous = [(t, k) for t, k in items if 0 <= (now-t).total_seconds() <= window]
            kinds = sorted({k for _, k in previous})
            if len(kinds) >= 2 and "web_child_process" in kinds:
                alerts.append({"host": host, "timestamp": now.isoformat(),
                               "kinds": kinds, "score": sum(WEIGHT[k] for k in kinds),
                               "assessment": "suspicious_correlation_not_attribution"})
                break
    return alerts

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", help="JSONL synthetic or sanitized telemetry")
    p.add_argument("--window-seconds", type=int, default=120)
    args = p.parse_args()
    if not 0 < args.window_seconds <= 3600:
        p.error("window must be 1..3600 seconds")
    try:
        with open(args.file, encoding="utf-8") as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
        print(json.dumps({"schema": 1, "alerts": correlate(rows, args.window_seconds)}, indent=2))
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
