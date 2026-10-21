# Suspicious PowerShell — Rule Tuning and Evaluation

**Environment:** LimaCharlie `NEW_PROCESS` on a Windows 10 VM; `COMMAND_LINE` / `FILE_PATH` telemetry. Windows 10 was assigned the legacy sensor label `win11-home` to match the rule.  
**Scope:** `powershell.exe` and `pwsh.exe` process-launch patterns. No claims of malware detection or production efficacy.  
**Versions:** [v1](../detection-rules/powershell/powershell_v1.yml), [v2](../detection-rules/powershell/powershell_v2.yml), [v3](../detection-rules/powershell/powershell_v3.yml); [current combined v3 example](../detection-rules/suspicious-powershell.yml).  
**Status:** **Stopped after v3. The prospective v3 holdout remains incomplete (10/20).**

## Executive summary

A custom LimaCharlie PowerShell detection rule progressed from broad `contains` matching (v1) to constrained regex (v2), then to less order-dependent startup argument matching (v3). All positive exercises ran **harmless commands that simulate suspicious execution techniques**. Their labels distinguish exercise intent rather than confirming attack behavior.

The initial **paired 20-scenario** v1/v2 benchmark (10 benign, 10 simulations, each version tested against the same definitions) improved from v1 **FPR 60% and recall 60%** to v2 **FPR 10% and recall 90%**. A separate 20-scenario **independent evaluation of v2** revealed significant weaknesses (**FPR 40%, recall 40%**). The second dataset was then used to tune v3; v3 regression on that same 20 yielded **FPR 30%, recall 90%**. A new v3 holdout had 20 planned cases, but only Batch 1 was run (5 benign + 5 simulation): **FPR 40%, recall 60%**. This is **not** a complete 20-case holdout.

## Scorecard

| Dataset (test executions) | Version | TP | FN | FP | TN | Recall | FPR | Precision |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Initial 20, paired baseline | v1 | 6 | 4 | 6 | 4 | 60% | 60% | 50% |
| **Same** initial 20, regression | v2 | 9 | 1 | 1 | 9 | **90%** | **10%** | 90% |
| New 20, independent validation of v2 | v2 | 4 | 6 | 4 | 6 | 40% | 40% | 50% |
| **Same** second 20, regression influenced by tuning | v3 | 9 | 1 | 3 | 7 | **90%** | **30%** | 75% |
| Third suite, **only Batch 1 (10/20)** | v3 | 3 | 2 | 2 | 3 | **60%** | **40%** | 60% |

[Full per-execution CSV](../metrics/powershell/powershell_test_results.csv) | [Machine-readable metrics summary](../metrics/powershell/powershell_metrics_summary.csv).

**Metrics:** `Recall = TP/(TP+FN)`; `FPR = FP/(FP+TN)`; `Precision = TP/(TP+FP)`. One execution is scored once even when multiple detections appear. **90 scored executions** across phases are **not 90 independent attacks/samples**. Four v3 targeted retests (IV-P01, IV-P02, IV-B03, IV-P08) were repeated for confirmation but are not included as additional observations.

## Rule evolution and observed failure cases

### v1 — Broad keywords

v1 matched keywords such as `-EncodedCommand`, `FromBase64String`, `DownloadString`, and `Invoke-Expression` anywhere in command-line text. This caused **6 FP** on B03, B04, B06, B07, B08, B10 (including strings merely quoted in documentation and harmless Base64 operations) and **4 FN** on P03 (`iex`), P05 (`-e`), P06 (`-w`), P08 (dynamic IEX).

### v2 — Regex, baseline gain and independent weaknesses

The 20 matched initial tests showed **6 FP → 1 FP** and **6 TP → 9 TP**. B04 (legitimate encoded administration) remained a benign alert. But independent scenarios uncovered that v2 depended on particular **argument order** and missed basic PowerShell option combinations:

- **IV-P01:** `-NoLogo -NoProfile -EncodedCommand` — 0 alerts.
- **IV-P02:** `-ExecutionPolicy Bypass -e` — 0 alerts.
- **IV-P05:** dynamically constructed `Invoke-Expression` — 0 alerts.
- **IV-P07:** `-ExecutionPolicy Bypass -enc` — 0 alerts.
- **IV-P08:** `iex` inside ScriptBlock — 0 alerts.
- **IV-P09:** `-NoLogo ... -w Hidden` — 0 alerts.

Independent benign alerts: **IV-B03** (`.DownloadString(` in documentation), **IV-B05** (legitimate EncodedCommand), **IV-B07** (benign Invoke-Expression), **IV-B08** (legitimate hidden window).

**Telemetry confirmation:** The user supplied real `NEW_PROCESS` event excerpts for **IV-P01** and **IV-P02**. Both contained valid PowerShell `FILE_PATH` and `COMMAND_LINE` showing the launch combinations above. Their misses were therefore supported as actual rule-level misses, rather than simply an absence of process telemetry. Raw host identifiers, user names and hashes were intentionally omitted here.

### v3 — Less order-sensitive matching

v3 uses argument-position-independent regex for encoded and hidden startup flags, a constrained direct IEX/ScriptBlock pattern, and a limited `DownloadString` call pattern. Four repeated targeted checks confirmed these improvements:

| Targeted scenario | v2 alerts | v3 alerts |
|---|---:|---:|
| IV-P01 NoLogo + EncodedCommand | 0 | 1 |
| IV-P02 ExecutionPolicy Bypass + -e | 0 | 1 |
| IV-B03 documentation containing `.DownloadString(` | 1 | 0 |
| IV-P08 IEX in simple ScriptBlock | 0 | 1 |

The entire **second 20-scenario regression** gave **9 TP / 1 FN / 3 FP / 7 TN**. **IV-P05** (dynamic Invoke-Expression) remained undetected. Benign alerts remained on **IV-B05, IV-B07 and IV-B08**. This dataset is **not an independent evaluation of v3**, because findings from it guided v3.

### v3 new holdout, Batch 1 only

| Case | Alerts | Exercise-level outcome |
|---|---:|---|
| H-B01 normal environment query | 0 | TN |
| H-B02 quoted encoded flag | 0 | TN |
| H-B03 documentation resembling a DownloadString call | 1 | FP |
| H-B04 minimized window | 0 | TN |
| H-B05 legitimate encoded administration | 1 | FP |
| H-P01 encoded startup with multiple flags | 1 | TP |
| H-P02 IEX expression | 1 | TP |
| H-P03 hidden window with reordered flags | 1 | TP |
| H-P04 dynamic IEX inside ScriptBlock | 0 | Provisional FN |
| H-P05 pipeline to IEX | 0 | Provisional FN |

**Batch 2 (H-B06–H-B10 and H-P06–H-P10) was planned but NOT EXECUTED.** Therefore do not assert a final 20-case v3 holdout rate.

## Interpretation, evidence, and limitations

1. **Paired comparison:** v1 → v2 improved FPR **60% → 10% (−50 percentage points)** and technique recall **60% → 90% (+30 percentage points)** on the **same first 20 lab scenarios**. This is an in-sample benchmark.
2. **Within-dataset tuning regression:** v2 → v3 on the second 20 improved FPR **40% → 30%** and recall **40% → 90%**. It does **not** establish a fresh independent estimate for v3.
3. **No cross-dataset percentage comparison:** v1 60% FPR and v3 30% FPR come from *different* scenario sets; they are not a paired before/after measurement.
4. **Holdout uncertainty:** Only **10 of 20** new v3 holdout cases were measured; on these, FPR 40% and recall 60%. The sample is small and hand-selected. Do not describe the unfinished holdout as complete.
5. **Benign vs suspicious:** EncodedCommand, hidden windows and IEX can be legitimate. A benign-labeled FP here refers to this exercise's ground truth; it need not mean the signal is always wrong for a security hunting policy. Likewise, simulated positive cases are harmless, not true malware.
6. **Telemetry caveat:** All alert totals came from manual user reporting. Raw `NEW_PROCESS` excerpts were examined only for IV-P01 and IV-P02; many zero-alert positive simulations lack independently preserved execution/telemetry confirmation. Therefore FN classifications outside confirmed excerpts should be treated as **conditional on successful execution and process-event visibility**.
7. **Detection limitation:** `NEW_PROCESS` command-line pattern matching cannot reliably identify malicious intent, decoded payload behavior, or all obfuscation. Future research could add parent/child process context, PowerShell Script Block Logging (Event ID 4104), applicable script telemetry, benign baselines and allowlisting; these were **not implemented**.
8. **Version provenance:** The v1 archive comes from the existing repo export; v2 is reconstructed from the tested candidate specification; v3 was transcribed from the rule text supplied after testing. The v3 combined example includes a `report` action. The live deployed rule and every historical event were not re-exported for this report.

## Conservative portfolio / CV language

> Iteratively tuned a LimaCharlie PowerShell detection rule across three versions. On 20 paired Windows lab scenarios, v2 reduced test-level FPR from 60% to 10% and improved technique recall from 60% to 90% relative to v1; subsequent v3 regression and partial holdout validation documented remaining limitations.

**Avoid:** claiming 100% detection, production SOC rates, 90 independent attacks, or complete v3 holdout validation. Work stopped deliberately at v3 after transparent evaluation.
