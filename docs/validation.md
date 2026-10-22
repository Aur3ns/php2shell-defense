# Validation status

The GitHub Actions pipeline runs portable structural checks: YAML/XML parsing, required Sigma keys, unique Wazuh IDs, WAF safety guard, alert-only Suricata check, and four synthetic behavioral fixtures.

Not native-validated: Suricata -T, Wazuh logtest, Falco engine, ModSecurity configtest, vendor Sigma CLI, SPL/EQL runtime. Synthetic tests do not demonstrate detection of either PHP2Shell exploit.

All rules are experimental and must be tuned before deployment.