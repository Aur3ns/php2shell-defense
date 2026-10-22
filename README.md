# 🛡️ PHP2Shell Defense
### Detect the signals. Correlate the evidence. Investigate with confidence.

**Open-source detection engineering for suspicious PHP web-server activity — across network sensors, runtime monitoring and SIEMs.**

[![Release acceptance](https://github.com/Aur3ns/php2shell-defense/actions/workflows/release-acceptance.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/release-acceptance.yml)
[![Python checks](https://github.com/Aur3ns/php2shell-defense/actions/workflows/validate.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/validate.yml)
[![Zeek behavioral test](https://github.com/Aur3ns/php2shell-defense/actions/workflows/zeek-native.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/zeek-native.yml)
[![Suricata PCAP regression](https://github.com/Aur3ns/php2shell-defense/actions/workflows/suricata-pcap.yml/badge.svg)](https://github.com/Aur3ns/php2shell-defense/actions/workflows/suricata-pcap.yml)
![Maturity](https://img.shields.io/badge/maturity-experimental-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

**One repository. Multiple detection engines. Reproducible evidence.**

PHP2Shell Defense brings together detection and hunting content for PHP-focused threats, including behaviors relevant to investigations of **CVE-2026-109618** and **CVE-2026-109619**. Instead of promising a magic signature, it helps defenders combine imperfect signals: abnormal HTTP requests, PHP errors, suspicious child processes and cross-source correlation.

> [!IMPORTANT]
> **Experimental detection toolkit — not a patch, exploit-specific guarantee, or production-certified prevention system.** Generic large POST requests and PHP errors frequently have benign explanations. Some attacks may leave none of these signals. **Apply supported PHP vendor patches first.** Keep rules in **alert/log-only** mode until locally validated. See the [production go/no-go checklist](docs/production-gate.md).

## ⚡ What you get

| Layer | Integrations | What to investigate |
|---|---|---|
| 🌐 Network | **Suricata · Zeek · ModSecurity** | Oversized POST requests to PHP endpoints (generic, often benign) |
| 🖥️ Runtime | **Falco · Wazuh** | Web-worker child processes and PHP memory-exhaustion logs |
| 🔎 Hunting | **Sigma · Splunk · Elastic · Loki** | Portable investigation starting points |
| 🧩 Correlation | **Python tools** | Normalize synthetic events, correlate multiple signals and evaluate labeled fixtures |

**Built for investigation, not sensational claims:**

- **Multi-engine coverage:** use the rules for the telemetry you actually have.
- **Evidence-driven CI:** native engine checks plus synthetic Suricata/Zeek PCAP replay and Wazuh positive/negative log tests.
- **Explainable correlation:** explore how network, PHP-error and process signals combine.
- **Safe test data:** synthetic benign traffic; no weaponized exploit payloads.
- **Tunable by design:** explicit [limitations](docs/matrix.md), [telemetry requirements](docs/telemetry.md) and [tuning guidance](docs/tuning.md).

## 🚀 Try it in two minutes

```bash
git clone https://github.com/Aur3ns/php2shell-defense.git
cd php2shell-defense
python3 -m pip install pyyaml
python3 scripts/validate.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

This runs **portable checks and synthetic tests** locally; it does not deploy sensors, scan targets or prove detection of a real exploit.

**Want evidence from the actual engines?** Explore the [release acceptance campaign](https://github.com/Aur3ns/php2shell-defense/actions/workflows/release-acceptance.yml) running Python, Suricata, Zeek, Falco and native Wazuh behavior checks. The [validation documentation](docs/validation.md) explains what each check really proves.

## 🗺️ Find your starting point

| You use… | Start here |
|---|---|
| Suricata | [Rule](suricata/php2shell_heuristics.rules) · [PCAP regression](docs/pcap-regression.md) |
| Zeek | [Script](zeek/__load__.zeek) · [Usage and limits](zeek/README.md) |
| Falco | [Runtime rule](falco/php_web_children.yaml) |
| Wazuh | [XML rules](wazuh/php2shell_rules.xml) |
| Sigma / SIEM | [Sigma detections](sigma/) · [Splunk hunts](splunk/) · [Elastic query](elastic/) |
| Detection engineers | [Correlation](docs/correlation.md) · [Metrics](docs/measurement.md) · [Detection matrix](docs/matrix.md) |

## 🤝 Help make it better

**SOC analysts, detection engineers, PHP maintainers, threat researchers and open-source contributors are welcome.**

The most valuable contributions right now are **reproducible, privacy-safe evidence**, not bigger detection claims. Good first contributions include:

- A confirmed benign false positive, with the rule, engine version and sanitized event.
- A native-engine compatibility report from your lab.
- A focused regression test or parser edge case.
- A documentation improvement showing which telemetry is required.
- A carefully reviewed new heuristic, with positive **and** negative tests.

Check [CONTRIBUTING.md](CONTRIBUTING.md), open an [issue](https://github.com/Aur3ns/php2shell-defense/issues) or propose a [pull request](https://github.com/Aur3ns/php2shell-defense/pulls). **Never share credentials, identifying raw logs or live exploit payloads.** Use [SECURITY.md](SECURITY.md) for sensitive reports.

If you find the project useful, **⭐ star the repository** to help other defenders discover it. If you test it, tell us **what worked — and what didn't**.

## 🔬 Transparency & responsible use

The current automated tests validate **synthetic observations and engine integration**, not representative exploitation coverage, real-world false-positive rates or autonomous blocking. A successful CI run is not a security certification.

Read the [release readiness assessment](docs/release-readiness.md), [production acceptance gates](docs/production-gate.md), [third-party provenance](docs/third-party-provenance.md) and [engine coverage matrix](docs/matrix.md).

**Research context:** [UK NHS PHP2Shell alert](https://digital.nhs.uk/cyber-alerts/2026/cc-4875) · [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/).

Apache-2.0 © contributors. Community project; not an official vendor signature feed.
