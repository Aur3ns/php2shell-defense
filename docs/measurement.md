# Transparent detection measurement

Run:

```sh
python -m unittest discover -s tests -p 'test_*.py'
python tools/evaluate.py --labels tests/evaluation/labels.json --alerts tests/evaluation/alerts.json
```

The tiny *synthetic* demonstration currently yields 2 TP, 1 FP, 2 TN and 0 FN. It intentionally includes a benign upload falsely flagged as suspicious. **These numbers are examples only; do not describe them as PHP2Shell recall, prevention, or production false-positive rates.**

Metrics have explicit denominators: precision TP/(TP+FP), recall TP/(TP+FN), false-positive rate FP/(FP+TN). Undefined ratios are reported as null rather than zero. All detections are manually labeled, with event IDs kept separate from untrusted log contents.

For real comparative benchmarks, collect ethically sourced, labeled, de-identified data with provenance and a held-out test corpus. Report engine version, observation point, capture depth, ground truth, tuning settings, uncertainty, and timing.
