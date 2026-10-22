#!/usr/bin/env python3
"""Read-only, offline temporal correlation of sanitized observations.

This detects combinations of generic behaviors, not PHP2Shell exploitation.
"""
import argparse
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

ALLOWED = {"http_anomaly", "php_memory_error", "web_child_process"}
WEIGHT = {"http_anomaly": 1, "php_memory_error": 1, "web_child_process": 2}


def parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


def correlate(events, window=120):
    """Return at most one alert per host from a bounded sliding window.

    Input order does not matter. The returned alert contains no raw payloads.
    Runtime: O(N log N) for sorting plus O(N) sliding-window processing.
    """
    if isinstance(window, bool) or not isinstance(window, int) or not 0 < window <= 3600:
        raise ValueError("window must be an integer in 1..3600")
    by_host = defaultdict(list)
    for e in events:
        if not isinstance(e, dict) or e.get("kind") not in ALLOWED:
            raise ValueError("unsupported event kind")
        host = e.get("host")
        if not isinstance(host, str) or not host.strip() or len(host) > 255:
            raise ValueError("invalid host")
        if "timestamp" not in e:
            raise ValueError("missing timestamp")
        by_host[host].append((parse_timestamp(e["timestamp"]), e["kind"]))

    alerts = []
    for host, items in sorted(by_host.items()):
        items.sort()
        active = deque()
        counts = defaultdict(int)
        for now, kind in items:
            active.append((now, kind))
            counts[kind] += 1
            while active and (now - active[0][0]).total_seconds() > window:
                _, old_kind = active.popleft()
                counts[old_kind] -= 1
            kinds = sorted(k for k, count in counts.items() if count > 0)
            if len(kinds) >= 2 and "web_child_process" in kinds:
                alerts.append({
                    "host": host, "timestamp": now.isoformat(),
                    "kinds": kinds, "score": sum(WEIGHT[k] for k in kinds),
                    "assessment": "suspicious_correlation_not_attribution",
                })
                break
    return alerts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", help="JSONL synthetic or sanitized telemetry")
    p.add_argument("--window-seconds", type=int, default=120)
    args = p.parse_args()
    try:
        with open(args.file, encoding="utf-8") as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
        print(json.dumps({"schema": 1, "alerts": correlate(rows, args.window_seconds)}, indent=2))
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
