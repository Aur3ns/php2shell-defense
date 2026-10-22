# Native engine validation

CI includes an opt-in isolated `Suricata native validation` workflow that installs Suricata using the Ubuntu 24.04 package repository and runs the engine's `-T` config test on the experimental rule file.

**Important:** This is a syntax/configuration load check, not a proof of detection quality or PHP2Shell exploitation coverage. Suricata's installed version is printed in the action log. The operating-system package may change over time; do not call this image/version-pinned without recording the precise package version.

No network scans, exploits, production traffic, or automatic blocking are performed.

Future work: version-pinned container tests, generated benign PCAPs, native engine regression assertions, and Wazuh/Falco/Zeek verification.
