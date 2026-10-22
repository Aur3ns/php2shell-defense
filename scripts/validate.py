#!/usr/bin/env python3
"""Portable structural tests. Not equivalent to native engine validation."""
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
root = Path(__file__).resolve().parents[1]
rules = list((root / "sigma").glob("*.yml"))
assert len(rules) >= 3
for p in rules:
    d = yaml.safe_load(p.read_text())
    assert all(k in d for k in ("title", "id", "logsource", "detection", "level"))
    assert d["status"] == "experimental"
for p in list((root / "falco").glob("*.yaml")) + list((root / "tests").glob("*.yml")):
    yaml.safe_load(p.read_text())
for p in (root / ".github/workflows").glob("*.yml"):
    yaml.safe_load(p.read_text())
xml = ET.parse(root / "wazuh/php2shell_rules.xml")
ids = [e.attrib["id"] for e in xml.iter("rule")]
assert len(ids) == len(set(ids)) and len(ids) >= 2
modsec = (root / "modsecurity/php2shell_heuristics.conf").read_text()
assert not any(line.lstrip().startswith("SecRuleEngine") for line in modsec.splitlines())
suricata = (root / "suricata/php2shell_heuristics.rules").read_text()
assert "alert http" in suricata and "drop http" not in suricata
fixtures = yaml.safe_load((root / "tests/fixtures.yml").read_text())["cases"]
assert len(fixtures) >= 4
shells = {"sh", "bash", "dash", "zsh", "curl", "wget", "nc", "ncat", "socat"}
for case in fixtures:
    web_parent = any(x in case["parent"] for x in ("php-fpm", "apache2", "httpd"))
    predicted = web_parent and case["child"].rsplit("/", 1)[-1] in shells
    assert predicted == case["expected_behavior_alert"], case["name"]
print(f"PASS: {len(rules)} Sigma rules, {len(ids)} Wazuh rules, {len(fixtures)} synthetic fixtures; portable checks only")