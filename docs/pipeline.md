# Offline evidence pipeline

A reproducible **synthetic demonstration**, not a PHP2Shell exploitation test.

```bash
python3 -m tools.pipeline --events tests/pipeline/events.jsonl --labels tests/pipeline/labels.json --output report.json
```

Input JSONL events require unique `id`, a `host`, an offset-aware `timestamp`, and `kind` from `http_anomaly`, `php_memory_error`, and `web_child_process`. Events are sorted within each host, correlated in a bounded time window, and evaluated against independently labeled test hosts.

Reports contain event counts, correlations, TP/FP/TN/FN, precision and false-positive rate. They intentionally omit raw request bodies, cookies, user names and log contents. Hostnames in real deployments may be sensitive: de-identify them before sharing.

**Limitations:** no SIEM adapters, no production-scale streaming, no deduplication across sessions and no attribution of an alert to either CVE. Measurements on three tiny synthetic hosts are software regression tests, not realistic detection performance.
