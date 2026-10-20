# LaZagne Detection Engineering — Rule Tuning & Validation Report

**Project:** LimaCharlie EDR + Tines SOAR Automation Lab  
**Component under evaluation:** LimaCharlie Detection & Response (D&R) rule for LaZagne-like tool execution  
**Rule versions:** `lazagne_v1.yml` → `lazagne_v2.yml` → `lazagne_v3.yml`  
**Environment:** Windows 10 VM and Windows Server 2019 VM, LimaCharlie EDR  
**Evaluation status:** Completed rule tuning and limited validation; **not** a production detection benchmark.

## Executive summary

A custom LaZagne process detection rule was iteratively audited and tuned across three versions. Version 1 generated false positives from command lines ending in `all` and missed a renamed executable with a previously unseen SHA-256. Version 2 removed the broad command-line conditions and added a second verified hash. Version 3 further constrained filename-based matching to unsigned executables, addressing a signed-Notepad false positive discovered during expanded testing.

**Primary paired benchmark result:** Across the **same 20 controlled scenarios**, each executed once per version for scoring, v1 versus v3 improved **detection recall from 90% (9/10) to 100% (10/10)** and reduced the **false positive rate from 70% (7/10) to 10% (1/10)** — a **60-percentage-point FPR reduction**. This is the most direct comparison in this report. BP02 (missed renamed LaZagne on v1) and FB08 (unsigned harmless program named `LaZagne.exe`) were rechecked against both rule versions for consistency; verification repeats do not count as additional test cases.

**Earlier engineering evidence:** On the same expanded 20-test regression suite, v2 yielded 1/10 benign false positives and v3 yielded 0/10; both detected 10/10 positives. In a separate eight-trial limited validation, v3 detected 3/3 known-hash positives and alerted on 1/5 benign controls (20% FPR). These results use different suites and should not be treated as directly comparable population estimates.

## Test coverage and metrics

Each **test execution**, rather than each emitted alert, is the unit of classification. If an execution is malicious-tool-labeled and creates at least one matching rule alert, it counts as one TP; a benign execution with at least one alert counts as one FP. `TP`, `FN`, `FP` and `TN` should **not** be counted per process or per alert.

| Dataset / purpose | Rule | TP | FN | FP | TN | Detection rate (recall) | False positive rate |
|---|---|---:|---:|---:|---:|---:|---:|
| Initial baseline: 6 positive + 10 benign | v1 | 5 | 1 | 5 | 5 | **83.3%** | **50.0%** |
| Regression using original 16 test scenarios | v2 | 6 | 0 | 0 | 10 | **100.0%** | **0.0%** |
| Expanded: 10 positive + 10 benign | v2 | 10 | 0 | 1 | 9 | **100.0%** | **10.0%** |
| **Same expanded 20 scenarios**, retested after tuning | **v3** | **10** | **0** | **0** | **10** | **100.0%** | **0.0%** |
| Additional limited validation: 3 positive + 5 benign | **v3** | **3** | **0** | **1** | **4** | **100.0%** | **20.0%** |
| **Final paired benchmark: same 10 positive + 10 benign** | **v1** | **9** | **1** | **7** | **3** | **90.0%** | **70.0%** |
| **Final paired benchmark: same 10 positive + 10 benign** | **v3** | **10** | **0** | **1** | **9** | **100.0%** | **10.0%** |

- **Detection rate / recall** = `TP / (TP + FN)`.
- **False positive rate** = `FP / (FP + TN)`.
- **Precision** = `TP / (TP + FP)`; on the additional v3 validation set, precision was **75% (3/4)**.
- **Total scored test executions:** **120 across all phases** (80 prior scored trials plus 40 in the final paired benchmark). Retests used for verification are not scored again. These are **not 120 independent samples**; multiple tests reuse the same executables, known hashes, and scenarios.
- **P14/P15 were not performed.** Do not describe the last validation as a completed five-positive/five-benign test suite.

## Final paired benchmark — v1 versus v3

**Design:** 20 fixed scenarios (10 benign controls `FB01–FB10`, 10 LaZagne-positive cases `BP01–BP10`). Both versions were enabled separately and tested against the same scenario definitions on Windows 10 and Windows Server 2019 VMs. Scoring is **per executed test**, not per emitted alert. Raw results are in [`../metrics/lazagne/lazagne_final_benchmark.csv`](../metrics/lazagne/lazagne_final_benchmark.csv).

| Metric | v1 | v3 | Change |
|---|---:|---:|---:|
| True positives | 9/10 | 10/10 | +1 detected positive |
| False negatives | 1/10 | 0/10 | -1 missed positive |
| False positives | 7/10 | 1/10 | -6 benign alerts at test level |
| True negatives | 3/10 | 9/10 | +6 benign tests correctly ignored |
| Detection recall | 90.0% | 100.0% | **+10 percentage points** |
| False positive rate | 70.0% | 10.0% | **-60 percentage points** |
| Precision (test level) | 56.25% | 90.91% | +34.66 percentage points |
| Detection alerts emitted | 25 | 21 | Counts reflect parent/child processes; not a test-level accuracy measure |

### Failure analysis and verification

- **BP02 (positive, Windows 10):** The renamed known LaZagne binary `audit-test.exe -h` generated **0 alerts on v1** and **2 on v3**. A v1 rerun confirmed a `NEW_PROCESS` event, establishing a genuine v1 **false negative**, not missing telemetry.
- **FB08 (benign, Windows 10):** A harmless **unsigned** .NET program was copied to `FB08\LaZagne.exe`. It yielded **one false-positive alert under v1 and one under v3**. An initial v3 run appeared to produce zero alerts, but the event examined was the **signed Notepad binary from FB07** at a shared path. The test was repeated in a distinct `FB08` directory and then confirmed against both versions. The recorded paired result is **1 alert on both v1 and v3**.
- **FP root causes corrected:** v3 no longer alerts solely because command lines end in `all` or mention `LaZagne`, and a signed Notepad binary called `LaZagne.exe` is no longer sufficient to match.
- **Remaining FP:** The `filename == LaZagne.exe AND unsigned` branch still alerts on an unsigned harmless executable with that filename.

### Interpretation

The result supports **“Reduced the false-positive rate from 70% to 10% on 10 controlled benign cases while improving LaZagne detection recall from 90% to 100% on 10 controlled positive cases.”** It **does not** support an enterprise-wide FPR claim. Several scenarios and binaries were used previously in tuning or validation; this is a **paired, controlled lab benchmark**, not a statistically independent hold-out evaluation. Most positive tests reused just two known SHA-256 values, and some used `-h`, which validates execution indicator detection, not actual credential access.

## Engineering timeline

### v1 — Baseline and root-cause analysis

**Detection logic:** Windows processes; `NEW_PROCESS` and `EXISTING_PROCESS`; match on LaZagne filename, `COMMAND_LINE` ending with `all`, `COMMAND_LINE` containing `lazagne`, or one known SHA-256.

**Observed weaknesses:**

1. **Broad command-line match:** Five deliberately benign commands with endings such as `install`, `firewall`, `recall`, and `overall` were incorrectly detected because they end in `all`.
2. **Rename + unknown hash:** Renamed `audit-test.exe browsers` ran successfully and generated two `NEW_PROCESS` telemetry events, but generated **zero** detections on Windows 10 (confirmed false negative).
3. **Alert volume:** Each successful test of the LaZagne sample generally produced **two alerts** from **two distinct parent/child processes** (`NEW_PROCESS`), not a duplicate recording of a single process event.

**Baseline:** 5 TP, 1 FN, 5 FP, 5 TN.

### v2 — Remove broad indicators; expand hash coverage

**Changes from v1:**

- Remove `COMMAND_LINE ends with all`.
- Remove `COMMAND_LINE contains lazagne`.
- Retain filename matching for `LaZagne.exe`.
- Match two lab-verified LaZagne SHA-256 values (Windows 10 and Windows Server 2019 samples).
- Restrict the rule to `NEW_PROCESS`.

**Validation:** In the initial 16-case regression, 6/6 positives were detected and 0/10 benign cases generated alerts. In a **new 20-case expanded dataset**, 10/10 positive trials were detected, but **B09** produced 1 false positive when a **signed Notepad binary** was copied under the filename `LaZagne.exe` (`FILE_IS_SIGNED=1`).

### v3 — Add signature context to filename matching

**Rule logic:** On Windows `NEW_PROCESS`, alert when either:

- `event/HASH` equals either known LaZagne SHA-256; **OR**
- executable basename equals `LaZagne.exe` **AND** `event/FILE_IS_SIGNED=0`.

**Regression:** The 20 expanded v2 cases were rerun against v3. B09 no longer alerted, and all 10 positive trials remained detected: **10 TP, 0 FN, 0 FP, 10 TN**.

**New limitation found:** **B11** compiled a harmless **unsigned** .NET console application as `LaZagne.exe`. LimaCharlie observed `NEW_PROCESS`, `FILE_IS_SIGNED=0`, and a hash not matching the known LaZagne hashes. The v3 rule still alerted (**false positive**). This establishes that **unsigned status plus filename is not sufficient proof of malicious identity**.

## Focused evidence and reproduction notes

| Test | Ground truth | Evidence / reasoning | Result |
|---|---|---|---|
| v1 `TP03` | Positive | `audit-test.exe browsers` (Windows 10); execution and `NEW_PROCESS` observed, but no matching detection | **FN** |
| v1 `FP01–FP05` | Benign | Harmless command lines ending in `all`; 1 alert per execution | **5 FP** |
| v2 `B09` | Benign | Signed Notepad renamed `LaZagne.exe`; filename rule matched | **FP** |
| v3 `B09` | Benign | Same signed Notepad renamed `LaZagne.exe`; signature-aware filename clause prevented alert | **TN** |
| v3 `B11` | Benign | Harmless unsigned .NET `LaZagne.exe` (SHA-256 starts `34b3e54b...`); `NEW_PROCESS` and one alert observed | **FP** |
| v3 `P11–P13` | Positive | Known-hash LaZagne binaries with different filenames/launch contexts; 2 alerts per execution | **3 TP** |

### What the duplicate-looking alerts actually mean

In sample LaZagne tests, an execution created a parent and a child `LaZagne.exe` process, each of which independently matched `NEW_PROCESS`. Two detections therefore represent two distinct observed process instances. They may constitute **alert volume / analyst workload** at the *test execution* level, but must not be mislabeled as duplicated event ingestion. Downstream Tines/Slack delivery reliability was **not** evaluated in this report.

## Threat model and limitations

1. **Static indicators:** Known SHA-256 hashes do not cover unknown builds, modified binaries, or distinct LaZagne variants. Filename-based matching can be evaded through renaming.
2. **Signature is context, not a verdict:** Signed files can still be malicious; unsigned files can be benign. The v3 unsigned-filename clause remains vulnerable to false positives.
3. **Narrow dataset:** Benign samples were deliberately crafted; many positives are the same two LaZagne binaries launched with variations. These tests do not estimate prevalence-weighted enterprise FPR or true in-the-wild recall.
4. **Regression vs independent validation:** A 0% FPR on test cases used to guide tuning is **not evidence of 0% FPR on unseen workloads**. The next validation set demonstrated a remaining false positive.
5. **Process/tool detection vs credential theft:** `-h` testing validates detection of known executable/process indicators, not successful credential extraction or complete coverage of credential-access behavior.
6. **Additional tests:** Only B11–B15 and P11–P13 were completed in the final validation, and the B12–B15 binaries were largely variants of the same benign compiled artifact. No formal confidence interval is claimed.
7. **Operational metrics out of scope:** No reliable detection-to-Tines notification latency, containment success, or incident MTTR measurement was collected as part of this rule benchmark.

## Reproducibility / repository artifacts

Published repository paths (linked from README):

```text
detection-rules/lazagne/lazagne_v1.yml
detection-rules/lazagne/lazagne_v2.yml
detection-rules/lazagne/lazagne_v3.yml
metrics/lazagne/lazagne_final_benchmark.csv
metrics/lazagne/lazagne_tuning_test_results.csv
metrics/lazagne/lazagne_tuning_metrics_summary.csv
docs/LAZAGNE_RULE_TUNING_REPORT.md
```

Record supporting `detect_id`, event timestamp, PID, parent PID, process hash, rule version, and `test_id` where available. Do **not** expose active API keys, webhook secrets, account emails, local usernames, private IPs, or unredacted device identifiers in public evidence.

### Further engineering work (not yet done)

- Design a **behavior-based** rule/hunt using stronger process, access, and execution context, rather than assuming filename and unsigned status prove LaZagne.
- Test on additional **independent benign binaries** and truly new tool builds; freeze the next rule version before evaluating a separate hold-out set.
- Independently benchmark Tines workflow delivery and analyst approval decisions, distinguishing multiple process detections from SOAR notifications.

## CV-ready wording (conservative)

> Tuned a custom LimaCharlie EDR LaZagne detection rule across three versions, **reducing false-positive rate from 70% to 10%** and improving detection recall from **90% to 100%** across **20 paired, controlled Windows lab scenarios** (10 benign + 10 positive per version).

**Interview-ready caveat:** Explain that scores were calculated from trial-level confusion matrices, not raw alert counts; most positive trials used known LaZagne hashes, and one unsigned benign sample remained a false positive. Multiple process alerts for one trial are not multiple successful detections.

> **Avoid claiming:** “100% malware detection”, “10% production false positives”, “tested 120 independent attacks”, or “eliminated duplicate alerts”.

---

**Data provenance:** Results manually reported during controlled lab testing and collated from the test log conversation. The v1/v2/v3 YAML contents were inspected in the supplied repository ZIP; this does not independently verify the live rule versions at every historical test timestamp. Only a subset of process telemetry was shared, and no complete export of raw LimaCharlie detections is included. No new screenshots are required for the summary; where original telemetry is unavailable, retain this provenance disclosure.
