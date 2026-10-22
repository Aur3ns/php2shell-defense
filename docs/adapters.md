# Safe offline adapters

These adapters accept **vendor-style alert JSONL** and produce the pipeline's minimal JSONL schema. They deliberately only map signatures defined in this repository and never claim an event alone proves exploitation.

```bash
python -m tools.ingest --source suricata --input tests/adapters/suricata.jsonl --output suricata.normalized.jsonl --suricata-destination-host web-demo
python -m tools.ingest --source falco --input tests/adapters/falco.jsonl --output falco.normalized.jsonl
python -m tools.ingest --source wazuh --input tests/adapters/wazuh.jsonl --output wazuh.normalized.jsonl
```

To correlate signals across sources, host identifiers **must actually refer to the same monitored asset**. The Suricata destination address is not equivalent to Falco's hostname by default; use an explicit mapping and maintain provenance separately. Do not merge events on source IP, NAT public IP or an assumed shared host.

Only synthetic records are committed. Real logs may contain sensitive addresses and application metadata and should be sanitized before sharing. These are smoke-test-compatible representations of EVE, Falco and Wazuh output, *not evidence of direct vendor integration validation*.
