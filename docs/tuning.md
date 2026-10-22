# Deployment safety

1. Update PHP using vendor-supported fixes or backports; detections are not patches.
2. Run detection-only first. Do not enable inline deny/drop for heuristic HTTP rules.
3. Baseline uploads, routine scheduled web processes and PHP error rates.
4. Verify all required process parent fields and PHP log ingestion.
5. Tune false positives and measure precision using representative local traffic.
6. Native-validate each engine before production deployment.