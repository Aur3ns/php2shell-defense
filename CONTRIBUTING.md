# Contributing

Thank you for improving community defense.

## Contributions we prioritize
- **Native-engine validation:** engine name/version, exact CLI, sanitized output, and whether a rule loaded.
- **Detection improvements:** explain why the signal is relevant, supply synthetic positive and negative events, and discuss false positives.
- **Compatibility:** mapping common Apache/PHP-FPM/auditd/ECS/CIM field names.
- **Documentation:** examples that avoid production secrets and avoid recommending untested blocking.

## Pull request checklist
- [ ] No real credentials, internal IPs, logs containing personal information, or weaponized exploit payloads.
- [ ] Applicable detection engines and supported versions identified.
- [ ] At least one positive and one benign negative test fixture.
- [ ] Severity and false positives described.
- [ ] `python3 scripts/validate.py` passes.
- [ ] Changes do not silently enable deny/drop or globally change WAF policy.

Please open an issue before proposing broad breaking changes. Be respectful and technical in review discussions.
