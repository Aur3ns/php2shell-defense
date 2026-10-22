# 🛡️ PHP2Shell Defense

**Open-source, multi-platform detection engineering starter pack for PHP2Shell and related PHP web-server post-exploitation behaviors.**

[![Validate](https://github.com/Aur3ns/php2shell-defense/actions/workflows/validate.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/validate.yml)
[![Suricata native validation](https://github.com/Aur3ns/php2shell-defense/actions/workflows/suricata-native.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/suricata-native.yml)
![Status](https://img.shields.io/badge/status-experimental-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

> [!IMPORTANT]
> **Experimental, not an exploit-specific detection guarantee.** Signals such as a shell spawned by a PHP worker or an oversized HTTP request are behavioral heuristics. They may occur during legitimate operations, and attacks that remain inside the PHP process may evade them. **Apply vendor PHP security patches** regardless of detection coverage. The HTTP rules are alert/log-only; do not switch them to automatic blocking without lab validation.

## Why this exists

Defenders face fragmented telemetry: network monitoring can see HTTP anomalies, while Linux process monitoring observes post-exploitation. This repository provides a starting point to correlate both in a transparent and testable way without distributing exploitation payloads.

## Coverage

| Technology | File(s) | Signal | Default |
|:--|:--|:--|:--|
| Sigma | `sigma/*.yml` | PHP/HTTP worker child shells, download tools, temp execution | Detection |
| Wazuh | `wazuh/php2shell_rules.xml` | Web-service process activity and PHP memory errors | Alert |
| Splunk | `splunk/php2shell_hunts.spl` | Process hunts and memory-error trends | Hunt |
| Elastic | `elastic/php_web_child.eql` | Suspicious child processes | Hunt |
| Falco | `falco/php_web_children.yaml` | Runtime process activity | Alert |
| Suricata | `suricata/php2shell_heuristics.rules` | Large POST toward a PHP path | Alert |
| ModSecurity | `modsecurity/php2shell_heuristics.conf` | Large POST toward a PHP path | **Pass + log** |
| Grafana Loki | `loki/php_oom.logql` | PHP memory-exhaustion events | Hunt |

## Quick start

```bash
git clone https://github.com/Aur3ns/php2shell-defense.git
cd php2shell-defense
python3 -m pip install pyyaml
python3 scripts/validate.py
```

This runs **portable structural checks and four synthetic behavior fixtures**, *not* native rule-engine tests. Read [validation status](docs/validation.md) and [native engine validation](docs/native-validation.md) before deploying to any engine.

**Production assessment:** Before operational rollout, use the [production go/no-go checklist](docs/production-gate.md). A passing CI does not authorize automated blocking or demonstrate CVE-specific coverage.

## Deploy safely

1. Keep PHP security releases or vendor-supported backports up to date.
2. Confirm log/EDR schema and process-parent telemetry exist.
3. Import only the rules for your engine into a test environment.
4. Enable alert/log mode, collect benign baseline traffic and tune.
5. Correlate process, web and PHP-error signals instead of relying on any single indicator.
6. Use the [tuning guide](docs/tuning.md) and [coverage matrix](docs/matrix.md).

## Help improve this project

We welcome reproducible contributions: native-engine validation reports, benign false-positive samples (with secrets removed), engine compatibility notes, better rule logic and additional safe test fixtures.

Before opening a pull request, see [CONTRIBUTING](CONTRIBUTING.md). **Do not submit live credentials, personal data or weaponized exploit payloads.**

## Research & limitations

- [UK NHS PHP2Shell alert](https://digital.nhs.uk/cyber-alerts/2026/cc-4875)
- [Datadog Security Labs analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Telemetry prerequisites](docs/telemetry.md)
- [Engine-by-engine confidence](docs/matrix.md)

**Disclaimer:** This is a community defense project, not an official signature feed or a certification that deployment blocks CVE exploitation.

Apache-2.0 © contributors.
