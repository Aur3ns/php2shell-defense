# Correlation proof-of-concept

The offline `tools/correlate.py` accepts **already sanitized** JSON Lines events:

```json
{"host":"web-1","timestamp":"2026-10-22T10:00:00Z","kind":"http_anomaly"}
{"host":"web-1","timestamp":"2026-10-22T10:00:30Z","kind":"web_child_process"}
```

Run `python3 tools/correlate.py tests/correlation_example.jsonl`.

A finding is created only when at least two **distinct** signals occur on the same host within a bounded 120-second window, **including** a web worker child-process event. Simple POST-size alerts alone are insufficient. This is an exploratory correlation, **not a PHP2Shell signature** or a claim of compromise.

No raw HTTP bodies, usernames, IP addresses, or cookies are required. Do not forward unsanitized operational telemetry to third parties. Future work: process tree confidence, ingestion adapters, scalable sliding windows and measurable detection performance.
