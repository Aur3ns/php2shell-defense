#!/usr/bin/env python3
"""Offline detection-to-correlation report. No live scanning or exploitation."""
import argparse
import json
from pathlib import Path
from tools.correlate import correlate
from tools.evaluate import evaluate

def run(events, labels=None, window=120):
    seen=set()
    normalized=[]
    for event in events:
        if not isinstance(event,dict):
            raise ValueError("event must be object")
        eid=event.get("id")
        if not isinstance(eid,str) or not eid or eid in seen:
            raise ValueError("event id missing or duplicated")
        seen.add(eid)
        normalized.append({k:event[k] for k in ("host","timestamp","kind")})
    findings=correlate(normalized,window)
    output={"schema_version":1,"event_count":len(events),"correlations":findings,
            "disclaimer":"Offline heuristic correlation; not a PHP2Shell exploit verdict."}
    if labels is not None:
        # Evaluation is per host case. Case ID should be a distinct test host.
        for e in events:
            if e["host"] not in {x["id"] for x in labels}:
                raise ValueError("all event hosts must have labels")
        observed=[{"id":alert["host"]} for alert in findings]
        output["evaluation"]=evaluate(labels,observed,"synthetic_correlated_host")
    return output

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events",required=True)
    parser.add_argument("--labels")
    parser.add_argument("--output")
    parser.add_argument("--window-seconds",type=int,default=120)
    args=parser.parse_args()
    try:
        events=[json.loads(x) for x in Path(args.events).read_text().splitlines() if x.strip()]
        labels=json.loads(Path(args.labels).read_text()) if args.labels else None
        report=run(events,labels,args.window_seconds)
        value=json.dumps(report,indent=2,sort_keys=True)+"\n"
        if args.output: Path(args.output).write_text(value)
        print(value,end="")
    except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError) as e:
        parser.exit(2,f"Invalid input: {e}\n")

if __name__=="__main__":
    main()
