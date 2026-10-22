# Native engine validation

CI includes an opt-in isolated `Suricata native validation` workflow that installs Suricata using the Ubuntu 24.04 package repository and runs the engine's `-T` config test on the experimental rule file.

**Important:** This is a syntax/configuration load check, not a proof of detection quality or PHP2Shell exploitation coverage. Suricata's installed version is printed in the action log. The operating-system package may change over time; do not call this image/version-pinned without recording the precise package version.

No network scans, exploits, production traffic, or automatic blocking are performed.

Future work: version-pinned container tests, generated benign PCAPs, native engine regression assertions, and Wazuh/Falco/Zeek verification.

## Falco

The `Falco native validation` workflow uses the official `falcosecurity/falco:0.45.0` container to execute `falco --validate` against the custom Falco rule file. This is a static/native rule parser check with **no host sensor, driver, or live workload**. The actual engine result must be checked in GitHub Actions. It is not an execution or false-positive test.

## HTTP fixtures

See [synthetic HTTP corpus](http-corpus.md). Those header-only test records are not packets or replayable HTTP messages; no native network test is claimed.
