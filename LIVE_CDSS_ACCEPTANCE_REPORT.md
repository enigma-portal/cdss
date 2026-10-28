# Live CDSS startup and SOC analyst acceptance

Completed checks: 2026-10-27. Database timestamps and ranges below are UTC. The last preservation snapshot was taken at 09:15:27 UTC. Collection remains running, so source-alert counts can subsequently increase.

## Scope and verification limits

The application was started through the existing venv interpreter and `run.py`, using the existing `data/cdss.db`. No demo database was used. No attacks, Wazuh changes, asset configuration changes, purge, GitHub push, historical rescore or manual seed command were performed.

The native computer-use helper was unavailable after documented recovery attempts. The in-app browser, Chrome and Edge each reported unavailable; browser inventory was empty. The user signed into Edge, confirmed that Overview showed all key triage information, and performed the single requested Investigate click. The case and its evidence chain were then verified directly. This is user-assisted UI acceptance, not independent browser automation or a complete visual usability review. No authentication bypass or fabricated session was used.

The user subsequently confirmed that Recommendations and Analyst Decision were visible, and reported a confusing “Investigation” heading inside Recommended Actions. That wording was inspected and corrected as described below. The remaining case-section and admin Preview UI confirmations had not been received when this report was written. Server logs contained exactly one normal investigation POST and zero retention POSTs at the recorded check. Retention was therefore tested against the real database through the preview service on a read-only connection, not through the live admin form.

## STARTUP

Application restarted: **Yes.** There was no existing listener/application process initially. CDSS was started, then cleanly restarted after the reproduced timestamp/link defects and the user-requested recommendation wording correction. Ctrl+C was delivered only to verified CDSS console process groups; a new instance was launched only after the previous listener exited. No competing instance was launched.

URL responding: **Yes**, `http://127.0.0.1:5000`; `/health` returned HTTP 200. Unauthenticated Overview, Alerts and Retention requests redirected to login.

Migration applied: **Yes.** `alert_retention_audit`, `idx_alerts_event_epoch` and `idx_alerts_agent_rule` exist. Existing records remain present.

SIEM status: **Connected.** Connector 7 remained enabled and reported successful contact at 09:15:03 UTC. Connector 5 remained disabled, with its pre-existing historical error status; it was not changed.

Live ingestion: **Pass.** Alerts increased from 13,956 to 14,680: 724 additional source alerts. Connector contact and the persisted cursor advanced. The cursor's stored event value advanced from `1792989353607` to `1793092499746`. Some received events were older telemetry caught up by the persisted cursor; receiving backlog is not a failed ingestion test. No event was generated for this test.

The unmodified normal entry point invokes its existing knowledge initialization and legacy recommendation backfill. No separate seed/backfill command was run. Knowledge table counts remained unchanged. Normal startup added four previously missing legacy recommendations, and a later restart added two legacy recommendations for the newly opened case. None of the original recommendation rows changed.

## SOC TRIAGE

Investigate Next: **Pass, user-assisted visibility plus backend verification.** The user confirmed that detection, asset, priority, occurrences, last activity and pending status were all visible on Overview without opening Alerts.

Actual selected detection in the later queue snapshot: **Sysmon - Suspicious Process - svchost.exe**, DC01, Wazuh agent 002, representative alert 27000. It had nine family occurrences, last activity 08:55:44.442 UTC, no current case membership, and prior matching Case #10924.

Priority: **Critical.** The existing explanation uses Wazuh level 12, configured Critical asset importance (+1 before banding), two occurrences in the representative artifact group, and an actual source ATT&CK ID resolving to the local official catalogue. The family occurrence total is not substituted into the child priority formula.

Why it ranked first: pending family; highest available priority band; newest family activity within Critical; representative alert ID descending breaks exact ties. No additional score was introduced.

Can analyst identify the next investigation immediately: **Yes, according to the user's live Overview confirmation.** Independent first-screen visual verification was unavailable.

The user-investigated detection was an earlier explorer.exe queue item, described below. Ongoing ingestion changed the queue during the test. A reconstruction using the case creation second found several newer Critical rows. Consequently, the exact freshness/rank of the browser's rendered item at click time cannot be certified; no pre-click screenshot or page snapshot was available. This is not evidence that the SQL priority ordering is wrong.

Overview separately supplies Critical/High/Medium pending family counts, first-seen detection counts for the selected event period, explicitly labeled analyst-opened case counts and collection health. The read-only service snapshot, for example, reported 345 Critical, 240 High, 211 Medium, 20 first-seen recent families and 24 active analyst cases before the new case. These values are time-dependent. The user confirmed key row visibility; individual counter presentation was not independently observed.

## PRIORITY QUEUE

Ordering verified: **Yes, in live-data SQL/view models and disposable route regressions.** The exact rendered browser snapshot at the user's click was unavailable.

Wazuh severity separated from CDSS priority: **Yes in the rendered template/route regressions; not independently visually inspected in the connected Edge session.**

Why-this-priority verified: **Yes, backend.** The initial selected candidate was independently resolved to its actual group and recomputed with the existing authoritative calculator. The live case's saved priority rationale and factors were also inspected.

Real-data quick views and filters returned the expected states and labels. At one snapshot:

| Filter | Matching pending families |
|---|---:|
| Critical | 361 |
| High | 245 |
| Medium | 215 |
| Low | 135 |
| Not Assessed | 56 |

Needs Investigation contained only pending families. Critical + High returned only eligible pending work. Already Investigated returned 24 saved case families before the new case. All sampled priority values matched their filter.

Combined search `Application Compatibility`, Critical, Needs Investigation, custom event range October 1–27 yielded 176 families over nine pages. Pages one and two contained 20 distinct representatives each, with no overlap. Query parameter preservation is covered by the disposable route regression. Live browser interaction with these controls was not independently exercised.

Last 15 minutes, Last 1 hour, Last 24 hours and Custom use event occurrence time. The first two returned no matching pending families in the sampled interval, while 24 hours returned 50 families and 273 occurrences in matching groups. This was compatible with collection catching up older telemetry and does not imply ingestion failure. Group membership remains intact when an event-time filter matches a member.

## GROUPING

Real family tested: **Executable dropped in Windows root folder**.

At the same live-data grouping snapshot:

- Raw alerts represented: **1,016**.
- Old artifact/group presentation rows: **1,013**.
- New top-level analyst clusters: **70**.
- Distinct artifact identities retained: **1,000**.
- Sources: three agents, kept distinct in parent identity.

A real parent expanded through the service to 116 child groups, paginated 20 at a time. The sampled children retained their reported file paths, including separate System.Management.Automation.dll, TaskScheduler.dll and AM_Delta patch paths. Original alerts remain separate source rows and retain their authenticated drill-down routes. Their live browser pages were not independently opened by automation.

Additional audited families:

| Detection family/pattern | Raw alerts represented | Old group rows | Parent clusters | Distinct artifacts |
|---|---:|---:|---:|---:|
| DLL search-order hijack titles, aggregated by the existing meaningful identities | 454 | 192 | 19 | 108 |
| Sysmon suspicious svchost.exe, earlier snapshot | 764 | 115 | 114 | 1 |
| Executable dropped in commonly used malware folders, earlier snapshot | 484 | 474 | 38 | 446 |

Repeated Sysmon process titles across different agents, accounts/network contexts and time windows intentionally remain distinct. Same title alone is not the grouping key. No cross-agent/asset parent identity violation was found in the audited summaries. This is a bounded identity check, not proof that every possible semantic grouping is perfect.

Distinct artifacts preserved: **Yes, database/service verified.**

Incorrect merges: **0 detected by the audited parent agent/asset identity check.**

## OLD CASE / NEW ACTIVITY

Verified: **Yes, backend, after the timestamp defect was fixed.** Live visual confirmation of the marker/link was unavailable.

Prior case: **#10929**, Open, saved evidence state T1.

Example: 14 newer svchost.exe family occurrences on WIN-CLIENT, first 07:20:20.738 UTC and last 08:46:31.720 UTC. The prior case retains its nine original members. New activity has no active case membership and is not inserted into the old case. The view model supplies the prior-case link/status, count, time range and separate action. After the correction, the sampled New Activity view contained 215 families.

New activity remained separate: **Yes**. All baseline historical membership fingerprints remained present unchanged.

## ONE-CLICK INVESTIGATION

Detection: **Sysmon - Suspicious Process - explorer.exe**, DC01.

Case: **#11466**.

New/reused: **New**, created by the user's single normal UI action. Server logs contain exactly one `POST /alerts/groups/26790/investigate`. No second investigation was submitted to test reuse; idempotency/reuse is covered by the disposable suite. No duplicate group anchors or case memberships were found.

The case contains the two original trigger alerts 26677 and 26790. Retrieval execution 91 and file/process evaluation execution 92 both completed. Saved Initial Priority is Critical: level 12, configured Critical asset, source-provided official ATT&CK context, two stored occurrences.

Evidence actually consumed: **Yes**. Retrieval retained 200 archive records from 2,995 hits and explicitly recorded truncation. Findings reference 199 distinct archived records through 446 finding/evidence links. The file/process finding contains 50 structured observations: 48 archived observations and two triggers. A cross-source duplicate is not counted as independent evidence.

Evidence State: **T1 — Limited Evidence**.

Contextual Risk: **Medium**.

Confidence: **Medium**, separate from risk.

Read-only recomputation of the saved findings returned the same T1, Medium risk and Medium confidence. The unchanged matrix maps T1 + Critical protected asset to Medium. No state was forced and no assessment was rerun or rewritten.

Recommendations tied to decisive evidence: **Yes**. Both saved contextual recommendations reference assessment 110 and decisive archive record 4589. They advise validating file/process origin and monitoring related activity, rather than claiming confirmed compromise. The progression view model separates one decisive observation from 49 background observations.

Coverage limitations: archive retrieval is partial (200/2,995), cross-system coverage is unavailable, and no related file-and-process corroboration was established. Those limitations must not be interpreted as benign activity. Recommendations and Analyst Decision visibility were user-confirmed; the remaining case sections and complete layout were not independently visually verified.

No analyst decision was submitted. The task required verification of that section, not choosing a security response on the user's behalf.

## RETENTION PREVIEW

Preview: **Pass on the real-data preview service using a read-only connection; live admin-form confirmation pending.**

Selected From / To: **2026-10-23 11:40–11:51 UTC**.

- Total selected alerts: **49**.
- Eligible unlinked alerts: **19**.
- Protected alerts: **30**.
- Affected triage groups: **35**, across four agent/rule source-family pairs.
- Oldest occurrence: **11:42:05.871 UTC**.
- Newest occurrence: **11:47:26.116 UTC**.
- Estimated remaining count at the later snapshot: **14,650** from 14,669; only an estimate, because collection continues.

The protection service checks direct FK references regardless of CASCADE/SET NULL behavior, case/incident membership, findings, incident MITRE provenance and archive source-ID references. Assessments, recommendations and decisions preserve their case/evidence chain through those protected relationships. Direct and archive-only protection, future FK protection, rollback and stale preview checks passed on disposable databases. This test did not attempt a real protected or unprotected deletion.

Actual purge performed: **No**. Purge audit count is zero. No destructive confirmation was clicked by the agent. No retention POST was observed in the captured server logs as of the last check.

## UX VERDICT

Can analyst understand what to investigate first: **Yes, user-confirmed on Overview.** The single user-assisted workflow created the expected case without requiring a backend shortcut.

Priority queue clearer than raw Wazuh browsing: the hierarchy and separation are verified in data/route regressions, but a comparative user judgment was not supplied. Repetitions are materially reduced for artifact-heavy file/DLL families; process detections across preserved identities/windows remain repeated intentionally.

The concrete user-reported usability issue was an ambiguous “Investigation” category heading inside Recommended Actions. The user wanted recommendations framed as actions arising from the investigation. The template now says “Based on the saved investigation findings, CDSS recommends:” and uses “Recommended follow-up” for that category. Actual actions, reasons and supporting evidence remain unchanged; no stored recommendation was rewritten. The running app was restarted with that wording; post-refresh user confirmation was not received.

Additional usability issues independently visible in the running product: **not independently assessable**, because no browser/computer surface was available. This does not mean there are none. Complete visual review of technical-detail placement, terminology, all quick views, pagination, the remaining case sections and the live admin preview remains unconfirmed.

Two concrete usability defects were reproduced with real data, reported before code changes, fixed and regression-tested:

1. SQLite-owned case creation times were passed to the strict source-time parser. All 142 prior-member rows had NULL parsed creation times, suppressing new-activity matches. The fix uses the existing `parse_timestamp(..., sqlite_utc=True)` only for database-owned timestamps. After the fix, zero of 142 times were unparsed. Strict source timestamp behavior is unchanged.
2. Family links resolved only the current representative. In a real pending group, older member 26990 failed while representative 26997 succeeded. Family resolution now looks up the supplied member's current SQL group. The old link resolves correctly without changing any grouping identity, alert, priority or membership.

Only `app/services/triage.py`, `tests/test_soc_triage.py` and `templates/incident_detail.html` were changed as product/test code in this live acceptance task. The template change is limited to the two recommendation wording lines above. Supporting JSON, logs and this report record the checks. Existing unrelated edits were preserved.

## PERFORMANCE

End-to-end browser/HTTP timings for authenticated pages were **not measured**, because the authenticated browser was unavailable to automation.

| Requested measurement | Result |
|---|---|
| Overview | Not measured end-to-end; live-data service 1.529 seconds after the timestamp correction (earlier concurrent snapshot 4.065 seconds) |
| Alerts | Not measured end-to-end; sampled live-data service 1.597 seconds; quick-view samples approximately 0.89–1.01 seconds |
| Investigate Next click | Not measured; retrieval and evaluation record timestamps fall in the same UTC second, which is insufficient for a precise duration |
| Case page | Not measured |
| Health HTTP | 0.068 seconds in the later sample |
| Retention preview service | 3.307 seconds for the exact historical selection in the later sample |

These are local service measurements under live collection, not browser render timings or scalability claims. The normal entry point runs Flask's local development server; production deployment readiness was not evaluated.

## VALIDATION

Tests: **391/391**, zero failures/errors. Focused SOC/retention tests: **15/15**.

```powershell
.\venv\Scripts\python.exe scripts/run_isolated_checks.py full live_acceptance_final3_tests.log
.\venv\Scripts\python.exe scripts/run_isolated_checks.py full live_acceptance_focused.log test_soc_triage.py
.\venv\Scripts\python.exe -m compileall -q app tests scripts run.py wsgi.py config.py
git diff --check
```

The runner uses disposable storage before discovery imports and rejects main-DB connections. The disposable outer database remained byte-for-byte unchanged during discovery/execution, with zero tracked writes after setup. Its integrity was `ok`, FK violations zero. Expected mocked connector-failure messages are test scenarios, not evidence of a live connector failure.

- compileall: **Pass**.
- git diff --check: **Pass**; existing LF/CRLF normalization warnings were printed.
- Main DB integrity after tests: **ok**.
- Main FK violations: **0**.
- Checked orphan case memberships / archive-finding links: **0 / 0**.
- Duplicate source IDs / case memberships / group anchors: **0 / 0 / 0**.
- Original historical row hashes missing or changed: **0** across all captured case, execution, finding, assessment, recommendation, decision, priority and archive tables.

| Record type | Before | After | Explanation |
|---|---:|---:|---|
| Source alerts | 13,956 | 14,680 | Normal live ingestion, +724 |
| Case records | 1,987 | 1,988 | One authorized new case |
| Investigation executions | 90 | 92 | One retrieval and one evaluator for that case |
| Assessments | 108 | 110 | Initial and contextual records for that case |
| Analyst decisions | 7 | 7 | No decision submitted |
| Contextual recommendations | 158 | 160 | Two for the new assessment |
| Legacy recommendations | 4,597 | 4,603 | Existing normal startup backfill; no original row changed |
| Archive evidence rows | 4,547 | 4,747 | Bounded live retrieval for the single case |
| Purge audit rows | Absent before migration | 0 | Additive table created; no purge |

Main DB reset: **No**.

Alerts purged: **No**.

Historical investigations rewritten: **No**.

Attacks generated: **No**.

GitHub push: **No**.

## FINAL VERDICT

**Ready with limitations for local use; complete independent browser acceptance remains unverified.**

Startup, live ingestion, real-data queue/grouping, historical preservation, a single user-assisted investigation, evidence/assessment/recommendation traceability and backend retention preview passed. The two reproduced defects and the user-reported recommendation wording issue were corrected and loaded into the running application. Remaining limits are the unavailable automated browser/visual review, pending remaining case/admin-preview UI confirmations, uncaptured pre-click page freshness, unmeasured authenticated page timings, partial archive coverage and unavailable cross-system evidence. Live repeated-investigation reuse and actual purge were deliberately not exercised.
