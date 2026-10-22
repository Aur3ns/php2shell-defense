# Release readiness and known limitations (2026-10-22)

This repository is **experimental**, not production-certified. CI green means the tested checks passed; it does not mean that PHP2Shell exploitation was prevented.

## Required gates
- Python unit tests, synthetic pipeline, corpus evaluation: automated portable CI.
- Suricata syntax and synthetic **benign** PCAP regression: automated native CI.
- Falco native rule parser: automated native CI.
- Zeek script syntax: automated native CI; **no active Zeek detection yet**.
- Wazuh `analysisd -t` rules loading: automated native CI.
- Wazuh `wazuh-logtest` end-to-end match: **experimental manual workflow**, not a release gate until a stable and repeatable validation is established.
- Realistic held-out attack/benign test corpus, FP rate, parser fuzzing, distro backport checks: **not done**.

## Why Wazuh logtest is separate

The Wazuh manager needs its full analysis process and local socket. Several hosted CI runs failed connecting to `wazuh-analysisd`, despite successful static/native rule configuration checks. The manual experimental workflow keeps the unresolved test visible without making every unrelated code change fail for service-startup reasons. **This is not a claim of test success**. Before upgrading its status, demonstrate successful and repeatable `wazuh-logtest` matching of rule 100511, plus benign negative fixtures.

## Current HTTP parser

The multipart analyzer uses a bounded, simplified boundary split. It is **not** a complete RFC 7578 MIME parser. It can miss encoded, malformed, folded or intentionally ambiguous structures. `unknown` means unassessed, not safe.

## Deployment

Alert-only by default. Patch supported PHP branches and verify vendor security backports. No rule alone proves a compromise. Do not deploy generic oversized POST heuristics in blocking mode.
