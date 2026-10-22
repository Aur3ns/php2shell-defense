# Third-party research and provenance (2026-10-22)

We reviewed code/documentation from the following external defensive repositories **as references**. This project does **not** vendor or paste their detection code:

| Source | License verified in repository | Research insight | Independent follow-up |
|---|---|---|---|
| [Corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) | BSD-3-Clause, copyright Corelight, Inc. | Zeek transaction/session correlation, HTTP body inspection limits, extensive btest traces, Suricata rules | Correlate only provenance-linked events and add privacy budgets |
| [Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) | MIT, copyright Blue-B | Read-only estate checks, reverse-proxy mitigation tests | Integrate package-aware inventory, avoid unsafe exposure probes |
| [darkfibr/php2shell-detect](https://github.com/darkfibr/php2shell-detect) | MIT | Mechanism-based repeated-form triage and offline log scans | Independently test small, benign synthetic multipart fixtures |

## Rules for future imports

1. Read the complete original license before copying files. Retain original copyright/license notices and link to upstream.
2. Distinguish **conceptual inspiration** (no copied code) from **derived artifacts** (license and provenance required).
3. Require independent native validation, representative benign samples, and measured regression tests.
4. Prefer reporting uncertain coverage over claiming protection from CVE-2026-109618/109619.
5. Avoid copying publicly posted proof-of-concept exploit payloads into our public defensive test corpus.

## Current validation caveat

Zeek's current script is only a scaffold, not a functioning detector. Wazuh's native rule configuration needs engine initialization in the container. The CI outcome — not merely the presence of a workflow — determines the validation claim.
