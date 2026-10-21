# PowerShell metrics and test records

- [Per-test CSV](powershell_test_results.csv): **90 scored executions** across five version/dataset phases.
- [Metrics summary CSV](powershell_metrics_summary.csv): TP/FN/FP/TN and calculated percentages.
- [Detailed report](../../docs/POWERSHELL_RULE_TUNING_REPORT.md): methodology, errors, telemetry, limitations.

**One test execution is one observation**, regardless of emitted alert count. Each user-reported result was 0 or 1 alert. Labels are based on benign-vs-suspicious-technique exercise intent; positive simulations used harmless payloads, not confirmed malware.

Four extra targeted checks of v3 (IV-P01, IV-P02, IV-B03, IV-P08) overlap the 20-case v3 regression and are **not double-counted**. Only **10/20 planned** prospective v3 holdout scenarios were executed; do not claim the holdout is complete. Zero-alert cases are considered FN only conditionally on successful execution and NEW_PROCESS visibility; comprehensive raw telemetry was not exported.
