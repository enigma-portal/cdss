# Case 11331 causal-evidence remediation

The main database was inspected through SQLite `mode=ro`. Investigation and assessment replay used a temporary SQLite backup with network connections blocked. No live Wazuh query or attack execution was performed.

## Audit findings established before correction

- Correct Event 11 reached archive retrieval: **Yes**. Retrieval 83 retained it as archive evidence **4068**, source document `pHm2Z6EB9arOxXJ3RLbl`.
- Correct Event 11 reached retained evidence: **Yes**.
- Correct Event 11 reached evaluator snapshot: **Yes**, represented by equivalent source alert **23457**. Cross-source deduplication omitted only its redundant archive representation.
- It was not lost through archive ranking/cap, normalization, deduplication, or evaluator filtering.
- The old selector matched process path/account while ignoring PID, ProcessGuid, and process-before-file ordering. It preferred command-bearing pairs, then sorted signed evidence IDs. The matching file was positive alert 23457; archive file 4048 was represented as negative ID -4048, so the invalid older file won the tie-break. Process 4069 and network 4072 then completed a mixed-instance chain.
- The old selected chain **4048 / 4069 / 4072 is invalid** under corrected semantics.
- All **225** process/file candidate pairs in saved evaluator execution 84 are enumerated in `t4_audit_after.csv`, including both old and corrected `_file_related` results, receipt/source times, process identity, path, account, and observed file path. `t4_audit_before.txt` preserves the original audit and replay.

## Corrected replay

| Observation | Evidence | Source UTC time | PID |
|---|---|---|---|
| Process | Archive 4069, PowerShell, command includes `cdss_t4_live.txt` and `Invoke-WebRequest` | 07:42:32.502 | 624 |
| File | Alert 23457, equivalent archive 4068 | 07:42:32.606 | 624 |
| Network | Archive 4072, `10.10.10.20 → 10.10.10.10:8080` | 07:42:38.522 | 624 |

All three report agent 003 and ProcessGuid `{a0423c02-0fe8-6adb-0002-000000000e00}`.

The observed file is `C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_wc5kiv0p.n1i.ps1`. The decisive Event 11 does **not** establish creation of `cdss_t4_live.txt`; that filename is present in the command line. Original source strings, including their escaping, remain unchanged in storage and the JSON replay artifact.

- Resulting state: **T4**, selected through normal evaluation, not forced.
- Coverage: **Partial**, **200 / 597** same-agent events retained; truncated. The supplied 200/288 example is not this saved run's total. Cross-system coverage remains unavailable.
- Confidence: **Medium**, changed from saved Low because partial retrieval no longer satisfies the archive-unavailable low-confidence gate. The remaining Medium rule applies because decisive process/file rows lack `source_ip`. Their timestamps and usernames are present, so the temporal/entity Low branch does not apply.
- Exact existing Medium branch: missing asset **or** any decisive row missing `source_ip` or `username` **or** incomplete fallback evidence. Only the missing decisive source IP condition applies here. Its returned explanation remains: “Direct traceable evidence supports the state, but non-decisive context is incomplete.” That generic wording understates which rows lack context; the actual rule examines decisive rows.
- Decisive-evidence completeness affects confidence through those timestamp/entity checks. There is no separate decisive-chain completeness score or penalty for partial retrieval. State evaluation independently verifies required observations and relationships.
- Contextual risk: **Medium**, from the unchanged matrix **T4 + Low criticality**, with Contextual Risk Assessment enabled.
- Main-database historical assessments remain unchanged; these corrected results exist only in the local replay output, not as a rewritten saved assessment.

## Implementation

- `app/services/contextual_risk.py`: reject conflicting process identifiers; require same agent; prefer matching ProcessGuid, otherwise matching PID within the existing default archive-window span (20 minutes); use Sysmon UTC occurrence times without rewriting receipt timestamps; enforce process-before-file ordering; evaluate candidate progression before deterministic selection; favor a grouped-trigger member after progression/identifier strength. Version new assessments as `cdss-contextual-v3`. Matrix and T-state definitions are unchanged.
- `app/services/archive_evidence.py`, `app/services/investigation.py`: distinguish complete, partial, and unavailable coverage in findings without a schema migration. Retained truncated observations are available evidence. Confidence uses coverage availability rather than conflating truncation with failure.
- `app/services/evidence_progression.py`, `app/services/dashboard_context.py`, `app/routes/dashboard.py`, `templates/incident_detail.html`: display decisive observations, their instance relationship and ordering; separate background observations; preserve and label unsupported historical relationships. Display clear asset onboarding, criticality and risk-assessment status. Disabled assets show “Contextual Risk: Not calculated — Risk Assessment disabled for this asset.”
- `app/services/contextual_recommendations.py`: remove asset-scope configuration advice from incident recommendations. Historical stored recommendations are preserved; obsolete configuration advice is suppressed or clarified for display. New guidance uses `cdss-guidance-v3`.
- `tests/test_t4_causal_evidence.py`: focused offline regressions for identifiers, ordering, PID bounds, candidate selection, unrelated network traffic, coverage/confidence, decisive-only presentation, and historical invalid chains.
- `tests/test_case10934_fixes.py`, `tests/test_architecture_remediation.py`, `tests/test_task4_playbook_evidence.py`, `tests/test_task5_guidance.py`, `tests/test_dashboard_context.py`: replace obsolete relationship/wording expectations and give synthetic T-state fixtures explicit process identity and coherent ordering. Missing identifiers in historical-case fixtures are not invented.
- `tests/test_dashboard.py`, `tests/test_reference_evaluation.py`: isolate default-database writes and byte-protection checks in disposable storage.
- `scripts/audit_t4_case.py`, `scripts/replay_t4_disposable.py`, `scripts/run_isolated_checks.py`: reproducible read-only audit, offline disposable replay, and isolated test runner. Audit/replay files are local review artifacts.

Pre-existing user changes in other files were preserved.

## Regression diagnosis and verification

The requested `test_real_pipeline_repeatability_integrity_and_explainability` passed before its fixture change on an isolated outer database. The outer database had **zero changed bytes and zero write statements**. The original reported named-test failure therefore was **not reproduced**, and its exact historical cause is unverified.

A separate database-isolation defect was verified in the full suite: `tests/test_dashboard.py` inserted/deleted fixture users, alerts, incidents, investigations and assessments through the default database path. The isolated outer database recorded those writes and byte changes even after fixture cleanup. Cleanup does not restore SQLite file headers, allocation or autoincrement state byte-for-byte. Dashboard tests now initialize a per-test temporary database. The reference repeatability assertion now protects its own temporary database instead of monitoring a potentially active runtime database.

The named regression also passed after correction, with zero outer writes and zero changed bytes. Final full-suite result: **376/376 passed**, zero failures/errors, zero outer-database writes and zero changed bytes. Required `compileall` and `git diff --check` checks passed. Main-database read-only `PRAGMA integrity_check`: **ok**; foreign-key violations: **0**; checked orphan relationships: **0**; duplicate retained archive documents within a retrieval: **0**. The five orphan checks cover case-member alert/case references, archive-evidence and finding execution references, and assessment execution references.

The disposable replay also rendered the real case with an analyst session: HTTP **200**, decisive progression separated from **43** background observations, and no asset-configuration recommendation in Recommended Actions. Existing historical assessment rows compared exactly unchanged.

Historical assessments modified: **No**. Main DB reset: **No**. GitHub push: **No**.
