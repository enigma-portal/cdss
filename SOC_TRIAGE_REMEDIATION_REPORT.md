# SOC triage and alert retention remediation

## Audit findings

The original Overview led with stored source-alert/group counts and ingestion activity, followed by recent groups. Its lower investigation queue ranked existing cases by contextual risk. It did not recommend the highest-priority pending detection. From the landing page, opening an investigation required opening a group and then selecting Investigate: two clicks after login.

Repeated titles were not sufficient evidence of duplicate work. The existing artifact-group identity preserves Wazuh agent, rule, detection level, mapped asset, source IP, account, destination IP, artifact and a configured grouping window. Existing analyst case membership has its own immutable partition. Separate artifacts, identities, time windows and saved cases can therefore legitimately repeat a title. Source-ID and analyst case-member duplicate checks both returned zero. This does not prove that all semantically equivalent source telemetry is deduplicated.

The read-only current-data audit found, for example, 2,035 alerts titled “Registry Value Entry Added to the System,” spanning three agents and 424 reported syscheck paths. Same-title registry deletions included three agents and 354 paths. Merging these by title would conceal real differences.

The authoritative methodology is `cdss-initial-priority-v2`: Low, Medium, High, Critical, or unassigned. It uses the existing severity, administrator criticality and bounded ATT&CK/recurrence rules. Saved case-opening priorities are historical snapshots. Pending means no analyst-group case membership; legacy automatically created incidents do not claim that an analyst has investigated the group. Started and assessed analyst cases remain separate from pending work.

## SOC TRIAGE

- Investigate Next implemented: Yes.
- Default ranking: pending families only on Overview; Critical, High, Medium, Low, Not Assessed; within a priority, latest family event first; final tie-break by representative alert ID descending.
- Alerts' priority sort puts pending families before saved case families, using the same priority/time ordering. Explicit newest-activity sort is also available.
- Can analyst identify the next investigation immediately: Yes, in the rendered landing page and route regressions. The direct Investigate form requires one click after login. No browser-based usability study was performed.
- Overview complexity reduced: replaced risk distribution and multiple case queues with Investigate Next, a compact pending queue, three pending-priority counters, a separately labeled active-case count, event-time recent detections and existing collection health.
- First-seen counters count detection families first observed in the selected event period. They are not ingestion-time or case counts.
- Source metadata, ATT&CK IDs and priority explanation remain expandable; raw source records remain in the existing drill-down.

## ALERT GROUPING

- Old analyst-facing behavior: artifact groups appeared as repeated same-title rows without a family parent.
- New hierarchy: detection family → distinct artifact/context group → original source alerts. Family and artifact-list pagination occurs in SQL.
- Family identity retains agent, asset, rule, detection level, account and source/destination identities. It relaxes only artifact identity and uses a fixed UTC window based on the child group's latest activity. Existing artifact groups retain their original anchored windows; a parent can span a UTC boundary because its children remain intact.
- Repeated-title presentation reduced: Yes, for compatible artifacts within the same family context. Legitimately different systems, rules, accounts, networks, windows and cases remain separate.
- Raw alerts preserved: Yes, by grouping. Only explicitly confirmed admin retention can remove eligible source alerts.
- Old case/new activity: saved memberships remain unchanged. Pending groups whose first event follows a matching case's creation and historical event link to that prior case. New matching and earlier unmatched contexts have separate parent identities. The row shows prior status, new occurrences and first/last event time, with Investigate New Activity.
- Investigate on a family opens its highest-priority artifact group, not an implicit merged multi-artifact case. Expansion explains this and exposes each artifact's own action.

## PRIORITY

- Existing Initial Priority methodology changed: No.
- T1/T2/T3/T4 and contextual-risk matrix changed: No.
- Priority now prominent: Yes, uppercase badges with explicit CDSS labeling.
- Why-this-priority available: Yes, using the existing calculator or saved rationale.
- Corrected a presentation/sort inconsistency: a stored unassigned case priority remains unassigned even if current asset context would now permit a calculation. Historical records are not updated.

## RETENTION

- Admin retention page: Yes, `/admin/alert-retention`, linked for administrators.
- Event-time From/To range: Yes; UTC, with optional source/asset and linked/unlinked filters.
- Preview: Yes; selection count, eligible/protected counts, affected artifact triage groups, source-family pairs, oldest/newest event and estimated remaining alert count.
- Unlinked alerts deletable: Yes, after a session-bound preview, CSRF validation and explicit confirmation.
- Investigation-linked alerts protected: Yes. The service discovers all direct foreign-key references regardless of CASCADE/SET NULL behavior, protects incident ATT&CK provenance, and checks archive `selected_fields_json.source_alert_id` source references. Source ATT&CK mappings alone may cascade with an eligible source alert.
- Purge audit record: Yes; actor, UTC timestamp, selection filters, deleted count and protected/skipped count. No deleted alert content is retained in the audit row.
- Transaction safety: eligibility and preview token are rechecked under `BEGIN IMMEDIATE`; deletion, audit insert and foreign-key verification commit together. Failure rolls back deletion. A stale preview requires another preview.
- No manual purge was executed against the main database. No automatic retention, VACUUM or compaction action was added.

## PERFORMANCE

Recursive artifact grouping and priority calculation run inside SQLite. Compact group/prior-case summaries are stored only in connection-local TEMP tables with indexes. Python receives at most 20 representative rows per page, rather than the entire alerts table. Overview reuses those summaries for counters. Prior matching uses the same normalized identity expression as artifact grouping.

Query-plan inspection showed indexed case membership, source mapping and prior-family lookups, plus temporary sorting/grouping. The SQL still scans source alerts to reconstruct dynamic groups; it is not an incremental or enterprise-scale queue. Additive startup migration supplies event-epoch and agent/rule indexes; existing case-membership indexes remain in use.

Local pending-page service measurements: approximately 200.09 seconds initially, 24.23 seconds after summary reuse, then 1.66 seconds after indexed prior matching. The final observed run was 1.12 seconds across 13,956 alerts and 937 pending families. These are individual local measurements under changing collection activity, not a controlled benchmark or browser-load timing.

## VALIDATION

Final full suite: 389/389 tests passed, zero failures and zero errors. All 13 focused SOC/retention tests also pass. The isolated outer database remained byte-for-byte unchanged during test discovery/execution, with zero recorded writes after its initial disposable setup; integrity was `ok` and foreign-key violations were zero.

Commands:

```powershell
.\venv\Scripts\python.exe scripts/run_isolated_checks.py full soc_tests_final.log
.\venv\Scripts\python.exe -m compileall -q app tests scripts run.py wsgi.py config.py
git diff --check
.\venv\Scripts\python.exe scripts/audit_soc_triage.py
```

The runner points database initialization and discovery imports at disposable storage and rejects attempts to open the main database. New regressions cover ordering, family boundaries, artifact expansion/raw access, prior-case membership, composable filters/pagination, saved unassigned priority, admin/CSRF checks, retention preview/deletion, archive and future foreign-key protection, stale preview, rollback and unchanged saved investigation/findings/assessment/recommendation/decision rows.

- compileall: pass.
- git diff --check: pass; Git printed existing LF/CRLF normalization warnings.
- Read-only main database integrity: `ok`.
- Main FK violations: 0.
- Orphan analyst case memberships: 0.
- Duplicate source IDs: 0.
- Duplicate analyst case memberships: 0.
- Latest read-only audit main-file hash unchanged: Yes. Earlier audit intervals observed file changes while source-alert counts increased; the audit itself opens the main database with `mode=ro` and does not initialize it.
- Historical investigation records modified by this remediation: No; retention preservation is tested on disposable databases.
- Main DB reset: No.
- GitHub push: No.
- Live Wazuh validation: not performed.

## Files and activation

Task edits: `app/database/__init__.py`; `app/routes/dashboard.py`; `app/services/alert_view.py`; new `app/services/triage.py` and `app/services/alert_retention.py`; `templates/overview.html`, `templates/alerts.html`, `templates/base.html`; new family/card/retention templates; `static/css/contextual-dashboard.css`; `tests/test_alert_grouping.py`, `tests/test_dashboard.py`, `tests/test_product_audit.py`; new `tests/test_soc_triage.py`; new `scripts/audit_soc_triage.py`; and the existing isolated runner's log selection, main-DB guard and SQLite function registration.

Pre-existing changes in other risk, evidence and playbook files were not edited by this task. The first full run used the existing runner's default and refreshed `t4_tests_full.log`; subsequent results use `soc_tests_full.log`, `soc_tests_final.log` and `soc_tests_focused.log`.

The running application was not restarted. Its next normal runtime initialization applies the additive retention table/index migration and loads the new routes/templates. No startup initialization, reseeding, backfill, historical rescore or purge was run against the main database during this work.
