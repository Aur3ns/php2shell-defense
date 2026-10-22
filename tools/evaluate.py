#!/usr/bin/env python3
"""Evaluate a detection result against explicitly labeled independent cases.

No hidden assumptions about exploit effectiveness. Inputs are JSON arrays.
"""
import argparse
import json
from pathlib import Path

def evaluate(labels, observed, target="php2shell"):
    truth = {}
    for row in labels:
        case = row["id"]
        if case in truth:
            raise ValueError("duplicate case id")
        if row.get("label") not in ("benign", "suspicious"):
            raise ValueError("invalid label")
        truth[case] = row["label"] == "suspicious"
    alerts = set()
    for row in observed:
        case = row["id"]
        if case not in truth:
            raise ValueError("unknown case id")
        if case in alerts:
            raise ValueError("duplicate alert")
        alerts.add(case)
    tp=sum(truth[i] and i in alerts for i in truth)
    fp=sum(not truth[i] and i in alerts for i in truth)
    fn=sum(truth[i] and i not in alerts for i in truth)
    tn=sum(not truth[i] and i not in alerts for i in truth)
    def ratio(n,d):
        return None if d==0 else round(n/d,4)
    return {"scope":target, "cases":len(truth), "tp":tp, "fp":fp, "tn":tn, "fn":fn,
            "precision":ratio(tp,tp+fp), "recall":ratio(tp,tp+fn),
            "false_positive_rate":ratio(fp,fp+tn),
            "warning":"Synthetic benchmark only; not PHP2Shell exploit efficacy."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--labels",required=True)
    p.add_argument("--alerts",required=True)
    p.add_argument("--output")
    args=p.parse_args()
    result=evaluate(json.loads(Path(args.labels).read_text()),
                    json.loads(Path(args.alerts).read_text()))
    payload=json.dumps(result,indent=2)+"\n"
    if args.output: Path(args.output).write_text(payload)
    print(payload,end="")

if __name__=="__main__":
    main()
