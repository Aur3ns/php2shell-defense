# Offline Suricata behavior test

This test builds a deterministic synthetic TCP/HTTP PCAP in Python's standard library, then runs a **real offline Suricata replay** and asserts the SID 9900101 alerts.

Run the GitHub Actions workflow `Suricata PCAP behavioral regression`. No target is scanned, no exploit is generated and no network request is transmitted.

**Crucial:** the two expected alerts are both **benign large PHP requests**, demonstrating the current heuristic's false-positive potential. The test validates only the signature's observable behavior, **not PHP2Shell exploit detection**. It must never be treated as a blocking policy or proof of prevention.

The PCAP data and expected outputs are regenerated in CI rather than storing a binary fixture.
