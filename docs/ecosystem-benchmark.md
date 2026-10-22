# Defense ecosystem benchmark — 2026-10-22

This is an independent comparative review of publicly available defensive projects, not a ranking or endorsement. We **do not** vendor third-party signatures without reviewing licenses, provenance, and efficacy. Documentation can become stale quickly after disclosure.

| Project | Observed approach | What we can add independently | Cautions |
|---|---|---|---|
| [Corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) | Zeek HTTP/session correlation, serialized field/multipart anomalies, Suricata, version-inventory notices; README reports Suricata 8.0.6 validation | Native Zeek and Suricata CI, bounded session correlation, synthetic benign + suspicious corpus | Requires plaintext visibility; body depth, sampling, false positives; honor their license |
| [Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) | PHP estate discovery, proxy mitigations and a Docker integration test matrix | Local read-only version inventory and staged edge tests | A mitigation test cannot prove CVE immunity; risky to deploy an information-exposing webcheck |
| [darkfibr/php2shell-detect](https://github.com/darkfibr/php2shell-detect) | Offline HTTP-shape and log analysis, Suricata/Snort, YARA, fixtures | Offline detectors with structured confidence classes and provenance | Some README branch/fix claims contradict upstream PHP releases; do not import as truth |
| [yetDevs/php2shell-triage](https://github.com/yetDevs/php2shell-triage) | Plesk/PHP inventory, local and HTTP assessment, synthetic host tests | Testable package-aware inventory with vendor backport status | README contains pre-disclosure claims now outdated |
| [JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner) | Non-destructive scanning, subdomain recon, banner/version checks | Safe opt-in surface assessment with proof provenance | Banner accuracy, CDN hiding and distro backports |

## Confirmed upstream references

- [CVE-2026-109618 PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Datadog's independent verification](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Elastic's assessment of coverage](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)

## Immediate release blockers

1. **Native parser tests**, not merely YAML/XML syntax: Suricata -T, Zeek package load, Falco rule validation, Wazuh logtest, Sigma CLI, ModSecurity test config.
2. **Specificity**: existing generic oversized POST heuristic is low-confidence and may match normal uploads. No claim it detects either exploit.
3. **Correlation and ground truth**: independently develop deterministic benign and suspicious fixtures, blinded false-positive tests, expected alerts for each engine.
4. **Asset inventory**: report upstream fixed branches 8.2.35, 8.3.36, 8.4.27, 8.5.12; explicitly distinguish vendor backport status and PHP web-worker version from CLI version.
5. **Responsible deployment**: observation default, no global WAF state mutations, bounded collection, privacy-preserving logs, no live exploitation.
6. **License provenance**: add credits, SPDX fields and license checks for independently adapted work. Do not copy rules from repos just because they are public.

## New focus: unique and useful deliverables

- Schema mappings to process_creation/Sysmon for Linux, ECS, Splunk CIM, Wazuh auditd.
- Unified detection catalog: `id, platform, required telemetry, confidence, false positives, validation level, references`.
- CI on pinned official engines and documented, sanitized fixtures.
- Clear release gate: `portable` ≠ `native` ≠ `integration` ≠ `production verified`.

**Non-goal:** claiming that generic PHP OOM, POST size, or process children prove exploitation.
