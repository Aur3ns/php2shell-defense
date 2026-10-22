# Production deployment gate (security review required)

**Status: NO-GO for unattended prevention.** This repository provides experimental
detection and triage components. A passing CI validates only the asserted
synthetic fixtures and native parser/load checks. It is not a claim that
CVE-2026-109618 or CVE-2026-109619 is reliably detected or blocked.

## Mandatory prerequisites for a monitored, alert-only pilot

- [ ] All six required GitHub Actions workflows succeed on the *exact* deployed commit.
- [ ] Confirm PHP versions and vendor backports directly against maintained vendor advisories; prioritize patching.
- [ ] Review each individual rule and its detection quality and data dependencies.
- [ ] Validate Wazuh with native logtest positive **and negative** fixtures in the target deployment. XML load alone is not enough.
- [ ] Evaluate Zeek, Suricata and Falco with production-equivalent log schemas, encryption visibility, traffic shapes and parser limits.
- [ ] Exercise benign workloads and representative *authorized* security regression scenarios with independent labels, including false positives.
- [ ] Document detection delay, event-loss rates, timezone, host mapping, NAT/reverse proxy behavior and data retention policy.
- [ ] Assign responders, tune severities, configure rate-limits, and rehearse an alert triage/rollback procedure.
- [ ] Ensure logs are scrubbed before external sharing; no raw requests or credentials in CI artifacts.
- [ ] Verify least-privilege installation, pin image versions/digests, review dependencies and host compatibility.

## Hard NO-GO triggers

- Automatic blocking based only on large POST, PHP memory exhaustion or upload-progress field presence.
- Claim of complete PHP2Shell CVE coverage without representative labeled evaluation.
- Treating a missing/oversize/invalid multipart body as benign.
- Unmapped asset identities (e.g. NAT IP equated to a server hostname).
- No operational team to investigate alerts or roll back deployment.

## Deployment recommendation

1. Patch PHP first and measure inventory coverage.
2. Deploy one engine at a time in alert-only mode in a monitored staging environment.
3. Use synthetic and local benign fixtures to validate expected behavior.
4. Collect and analyze production-equivalent *permitted* telemetry with privacy controls.
5. Document measured misses and false positives, obtain security owner sign-off.
6. Promote only those components whose local tests and acceptance thresholds pass.

Never call the project production-certified on the strength of CI checks alone.
