# Full CDSS E2E hardening report

Audit date: 28 October 2026, Asia/Karachi. Database/source event times below are UTC unless stated otherwise.

**30 October 2026 update:** The PR #1 remediation section at the end supersedes the earlier collection-health/source-identity behavior and the 433-test verification record. The October 28 audit remains historical evidence. The remediation was verified on disposable databases; the running live app and its database were not upgraded or restarted for this follow-up.

## Verdict

**READY WITH LIMITATIONS for reviewed local use.** This is not production certification, independent detection-effectiveness validation, or a claim of enterprise scalability. Final verification and remote branch identifiers are recorded at the end of this report.

## GitHub checkpoint

- Source of truth: `C:\Users\Waleed\OneDrive\Documents\Codex\2026-08-19\you-are-assisting-me-in-developing-3\CDSS`.
- Initial branch: `main`; local HEAD and previous remote main: `d47842e7bd104752ba91def885cb33b992429f38`.
- New remote main/checkpoint: **`5623b51aff3e5873a11e53e9bce38f61e5c2044f`**.
- Commit: **Checkpoint SOC triage, evidence presentation, and retention remediation**.
- Reviewed/staged: 52 files, 2,910 additions and 348 deletions. Independent review found no checkpoint blocker.
- Excluded/preserved: 35 runtime logs, JSON/CSV/audit outputs. Database, SQLite sidecars, environment files, keys, credentials, venv, screenshots and generated runtime files were not staged.
- Fresh checkpoint verification: 407 tests, zero failures/errors, 293.460 seconds; compileall and diff check passed. Read-only database integrity `ok`, zero FK violations, zero orphans across 56 relationships, zero duplicate source IDs/case memberships/archive documents.
- Normal push succeeded. A fresh remote read proved remote main equals the checkpoint SHA; ahead/behind was 0/0. No force push, reset, clean or history rewrite was used.

## Hardening workspace

- Branch: **`e2e-hardening-2026-10-28`**.
- Worktree: `C:\Users\Waleed\.codex\.chatgpt-projects\g-p-6a67530412588191802a0c826e53a0b7\hardening`.
- Base: checkpoint `5623b51aff3e5873a11e53e9bce38f61e5c2044f`.
- The explicit worktree authorization overrides the local AGENTS prohibition for this task. The app-native worktree tool returned “Not a git repository” because the chat is attached to a project mirror; Git's worktree fallback targeted the actual checkout.
- Existing venv/Python 3.13 was reused. No dependencies were installed. Main was not used for experimental changes.
- The worktree's `data` junction points to the existing runtime directory for normal live startup. The task-generated test session key was moved outside the worktree before linking; existing live keys were preserved.
- Final branch remains separate from main. No merge is authorized or performed.

## Plugin workflows actually used

- **Superpowers:** using-superpowers, systematic-debugging, test-driven-development including writing-good-tests, using-git-worktrees, requesting-code-review, verification-before-completion and finishing-a-development-branch. The user already selected branch push without merge, so no redundant integration menu was needed.
- **Senior full-stack security architect:** source/evidence traceability, minimal fixes, no fabricated telemetry, additive storage, preservation and explicit verification limits.
- **Build Web Apps frontend-testing-debugging:** target flows, browser availability classification, rendered behavior, console capture, screenshots, desktop/mobile and interaction checks. **Browser plugin not available.** Installed Edge/Playwright was the approved fallback. The signed-in in-app browser additionally verified live pages through computer-use APIs.
- **Build Web Data Visualization:** data-visualization router, dashboards-and-real-time-visualization, testing-data-visualizations, visualization-strategy-and-critique. Evaluated analytical value, data windows, aggregation, stale/partial states and mobile reading order before deciding against extra charts.
- **GitHub:** repository inspection, remote verification and review handoff. Code Review connector capabilities are limited to PR CI diagnostics; source review was independently performed by reviewer agents, not represented as a plugin-generated review.

## Prioritized audit outcome and implementation sequence

| Priority | Finding | Disposition |
|---|---|---|
| High | Cookie-only login budget; unattended dashboard renews sessions | Proven and fixed with server-side budgets and explicit refresh |
| High | Transport paths permit unsafe destinations or changed DNS resolution | Proven and fixed with shared validation and pinned TLS transport |
| High | Malformed events and identity collisions impede lossless collection | Proven and fixed with durable quarantine, provenance and fail-closed cursor handling |
| High | Test runner main-database protection accepts URI aliases | Proven and fixed before broader mutation testing |
| Medium | Retention preview repeatedly scans history; NULL/reference-column edge cases | Measured/reproduced and fixed without purge or grouping changes |
| Medium | Priority versus evidence strength could be confused conceptually | Current local wording and matrix are correct; no methodology change |
| Medium | Repeated grouping/history scans; startup seeds mutate legacy templates | Measured/disclosed; further changes deferred |
| Low | Action-link contrast and missing favicon | Rendered failures corrected and browser verified |

Executed sequence: (1) inspect every pending source file and exclude runtime/secrets; (2) run fresh baseline and read-only database checks; (3) checkpoint/push main and verify SHA; (4) isolate hardening; (5) trace source/database/business/UI truth; (6) reproduce each defect and observe RED; (7) apply minimal fixes and verify GREEN/full regression; (8) test rendered desktop/mobile flows on a disposable copy and read live pages; (9) independently review code and evidence; (10) run final verification and push the separate branch for review. Remaining work is deployment/proxy planning, quarantine operations/replay design and performance targets at larger volumes; none is silently represented as completed.

## Source-to-UI truth trace

“Source” means retained Wazuh records and archive provenance, independently checked against stored snapshots. It does not mean original remote archive documents were fetched again or attacks were generated. Disposable browser mutations were isolated on port 5001; live browser reads/previews used port 5000.

| Feature | Source | DB relationship | Backend | Presentation | Rendered HTML | Browser | Result |
|---|---|---|---|---|---|---|---|
| Investigate Next | Real pending records | Unlinked groups/families | `triage_overview` | Highest child priority, then activity | Correct selected POST target | Live + disposable | PASS |
| Initial Alert Priority | Source level, asset, eligible mappings, distinct members | Alert/asset/mapping joins | Unchanged v2 calculator | Explicit initial label | Separate from final risk | Live + disposable | PASS |
| Why this priority | Actual factors | Saved snapshot or current child | Shared priority model | `priority_reason` | Reason visible | Live + disposable | PASS |
| Triage counters | Pending families | Same grouped candidates | `triage_overview` | Pending bands, active cases | Linked quick views | Live + fixture/browser | PASS |
| Grouping | Agent/rule/entities/artifact/event time | Raw members and frozen case membership | Shared recursive query | Family versus child selection | Compare/review links | Live + disposable | PASS |
| Occurrences | Distinct stored rows | Membership, not firedtimes | SQL counts | Family/selected scope separated | 28 total versus 1 selected in audited example | Live + disposable | PASS |
| Alert detail | Original raw alert | Alert ID and provenance | `alert_detail_data` | Source versus configured asset | Escaped/collapsed details | Disposable rendered drill-down | PASS |
| Old case/new activity | New source time, prior case creation | Earlier case preserved | Prior identity lookup | “New activity after Case” | New selection has its own action | Live + fixtures | PASS |
| Investigation evidence | Raw/retained archive documents | Execution/finding/evidence references | `_load`, investigation services | Saved execution snapshot | Supporting/decisive evidence separated | Requested live cases | PASS |
| Evidence progression | Timestamp, agent, PID/ProcessGuid | Decisive IDs in saved snapshot | Unchanged evaluator | `evidence_progression` | Ordered observations | Live + desktop browser | PASS |
| T-state | Structured observed evidence | Assessment/execution | Existing dedicated evaluators | Explicit T1–T4/Inconclusive | No compromise claim | Live cases + offline E2E | PASS |
| Confidence | Availability and identity/time completeness | Saved assessment | Existing confidence rules | Independent confidence label | Partial/unavailable distinctions | Live + fixtures | PASS |
| Contextual risk | Evidence state + saved criticality/scope | Saved assessment matrix inputs | Unchanged matrix | Saved risk and current-setting notice | Unassessed retained where historically disabled | Live + fixtures | PASS |
| Recommendation | Evaluated observations | Assessment/execution/finding/source references | Existing advisory generator | Specific action/reason | Advisory, conditional containment | Live read; disposable creation | PASS |
| Analyst decision | Human form selection | Append-only decision/current assessment | Auth + CSRF + decision service | Decision/history | Explicit human choice | Actual save on disposable DB | PASS |
| Retention preview | Event-time selection | Investigation/audit references | Snapshot counts + confirmation token | Eligible/protected/remaining | Preview with unchecked purge confirmation | Live + disposable preview only | PASS |

No critical source-to-presentation mismatch was found in these checked chains. Matching strings alone were not used as proof: independent SQL, retained source fields, relationship validation, matrix literals and deterministic fixtures were checked.

## T1 / Critical investigation

**Example: Case 10923, assessment 66, execution 50.**

| Factor | Verified value |
|---|---|
| Wazuh source level | 15 |
| Initial Alert Priority | Critical |
| Evidence State | T1 — Limited Evidence |
| Saved contextual risk | Medium |
| Saved asset criticality | Critical |
| Confidence | Low |

Critical initial priority can legitimately coexist with T1: triage urgency does not establish evidence strength. The existing matrix gives **T1 + Critical asset = Medium contextual risk**. No saved contextual assessment had T1 with Critical contextual risk in the audited database.

The browser explicitly labels Initial Alert Priority, Evidence State, Saved Contextual Risk, Assessment Confidence and Asset Criticality Used. No additional T1-specific wording or methodology change was necessary.

Historical nuance: an archive record in Case 10923 contains a potentially matching process observation, but its retained metadata lacks provider/channel/rule-group context needed for strict classification. The conclusion is insufficient retained classified corroboration, not proof that no process log existed.

## Priority boundary verification

Hand-derived expected bands covered Wazuh levels **0, 1, 4, 5, 7, 8, 11, 12, 16**, all four asset criticalities, and neither/MITRE/recurrence/both modifier combinations: **144 combinations**, plus missing severity and missing asset criticality.

- Level 0 remains unassigned; original source level below 12 cannot become Critical.
- Critical asset importance alone respects the source boundary.
- Eligible official source mapping and recurrence together add at most the approved single tier.
- Occurrences use distinct stored members, capped at five for the model; firedtimes is not authoritative.
- SQL sorting, detail calculations and saved priority snapshots remain covered by existing regressions. Model v2, thresholds, weights and risk matrix were not changed by hardening.

## Grouping verification

Real audited top family: representative alert **28173**, agent **002**, Wazuh level **15**, Critical configured asset; **28 family occurrences, 28 children, selected investigation group 1 occurrence**, prior Case **10923**. The actual member count matched the displayed selected scope. All 16,676 original alerts were preserved byte-for-value at row level.

Existing and new disposable checks cover different systems/agents/users/source and destination IPs, distinct files, inside/outside windows, search preserving membership, frozen historical cases, new activity and stable family links after representative changes. No incorrect merge or count mismatch was found in the checked examples. These are test/sample conclusions, not exhaustive proof for every possible telemetry shape.

## Saved evidence-state cases

| Case | Assessment / execution | State | Saved contextual risk | Confidence |
|---|---|---|---|---|
| 10923 | 66 / 50 | T1 | Medium | Low |
| 10932 | 88 / 72 | T2 | Unassessed | High |
| 10931 | 86 / 70 | T3 | Unassessed | Low |
| 10933 | 92 / 75 | T3 | Unassessed | Low |
| 11331 | 108 / 90 | T4 | Medium | Medium |
| 11472, normal recent case | 132 / 114 | T3 | Medium | Medium |

The three authentication references had assessment scope disabled in their historical snapshot. Their Unassessed risk is correct even though current configuration enables assessment. The UI warns about changed asset context and preserves history.

- 10932: thirteen raw 4625 failures share agent/account/source/PID; no success in that execution snapshot.
- 10931: eleven failures precede the related retained 4624 success (archive 3070).
- 10933: failures 22511/22513 precede archive 3241 success with matching identity. Nearby generic process events do not by themselves establish T4 progression.
- 11472: archive 6661 process precedes alert 27306 file, matching agent/GUID/PID; no later matching network event in retained evidence. The reused source alert ID alone is insufficient identity; document provenance and process relationship matter.

**Corrected T4 Case 11331:** archive **4534** process → raw alert **23457** file → archive **4537** network. All report agent **003**, PID **624**, ProcessGuid **`{a0423c02-0fe8-6adb-0002-000000000e00}`**. Source ordering: **07:42:32.502 → 07:42:32.606 → 07:42:38.522 UTC**. The network destination is **10.10.10.10:8080**. Latest decisive refs exclude the old mixed-instance chain. Retention is partial, not unavailable; confidence and risk remain separately explained. Containment advice is conditional on confirmed unauthorized activity and human approval. No historical assessment was rewritten or rerun on the main DB by this audit.

## Test-driven fixes and observed evidence

| Defect | Failing regression / RED | Minimal correction | GREEN |
|---|---|---|---|
| Runner main-DB guard URI aliases | Three `RuntimeError not raised` failures | Canonicalize/decode SQLite URI paths before comparison | 2 runner tests |
| Fresh-cookie throttle bypass | New cookie returned 200 instead of 429 | Atomic SQLite source/pair attempt budgets | Auth hardening tests; full 414-test pass |
| Background refresh renews idle session | last_activity advanced on health/static; refresh meta present | Exclude background endpoints; replace auto refresh with explicit snapshot refresh | Auth hardening tests; full regression |
| Malformed document blocks valid successors | 0 alerts instead of 1 | Durable identified rejection before cursor progress | Ingestion hardening tests |
| Source-ID/namespace collision silently ignored | Missing rejection/provenance | Preserve original alert; quarantine conflict with connector/index/document identity | Ingestion hardening tests |
| Changed document inserted as second unrelated alert | 2 alerts instead of 1 | Serialized provenance/content check | Replay/idempotency tests; full 420-test pass |
| Cleartext/forbidden endpoints accepted | HTTP constructor accepted; forbidden transport reached | Shared HTTPS/destination policy | Endpoint tests |
| DNS changes after validation | Socket attempted rebound 127.0.0.1 | Pin validated numeric socket, preserve TLS hostname, disable environment proxies | Rebinding + hostname tests |
| Unavailable IPv6 prevents IPv4 fallback | IPv6 OSError, no IPv4 attempt | Include socket creation inside retry scope | 5 endpoint tests |
| Retention repeated scans | Exhausted 2 million SQLite operations | Set membership evaluated once per reference source | Deterministic budget/count regression |
| Referenced column ignored | Expected 0 eligible/1 protected failed | Honor declared FK target column | Retention tests |
| Nullable historical source IDs disappear from counts | Total != eligible + protected | Explicit boolean COALESCE | Retention tests |
| Incomplete transport identity accepted | Missing _index/_id returned advancing page | Validate entire page before returning | Ingestion tests |
| Migration committed caller transaction | Marker persisted after rollback | Individual DDL statements | Rollback test |
| Partial status never becomes stale | Old partial contact remained partial | Apply contact freshness before partial state | Status regression |
| Identified non-object source stalls page | Valid successor not stored | Preserve original source JSON outside dict and quarantine it | Ingestion tests |
| Partial/timed-out search advances cursor | Accepted timed_out/failed shards | Fail closed, retain prior cursor | Ingestion tests |
| Action links unreadable on navy surface | Rendered contrast 1.82 < 4.5 | Scoped existing theme link color | Rendered contrast **6.54:1** |
| Browser console favicon 404 | E2E console-health assertion failed | Local SVG favicon reference | Browser suite, zero console errors |

Transport fixtures were updated to contain the real Indexer `_index` metadata required by the new contract; cursor/order assertions were preserved. A pre-review full run failed one existing error-message assertion; the implementation retained the established HTTPS wording rather than weakening that test. Test-clock and browser-locator harness mistakes were corrected before treating their outcomes as product regressions.

Regression locators (under `tests/`):

- Runner guard: `test_isolated_runner.test_sqlite_uri_and_filesystem_aliases_resolve_to_protected_database`.
- Auth/session: `test_auth_hardening.test_fresh_cookie_does_not_reset_server_login_throttle`, `test_automatic_refresh_cannot_extend_idle_session`, `test_page_refresh_is_removed_and_real_navigation_extends_session`; unrelated-source lockout protection has its own test.
- Transport: `test_endpoint_hardening.test_environment_and_client_paths_reject_cleartext_credentials`, `test_actual_transport_blocks_forbidden_resolved_destination`, `test_dns_change_cannot_redirect_connection_after_validation`, `test_unavailable_socket_family_falls_back_without_losing_tls_hostname`.
- Retention: `test_retention_hardening.test_preview_preserves_counts_with_a_bounded_sql_work_budget`, `test_reference_to_source_identifier_is_protected`, `test_nullable_legacy_source_id_does_not_disappear_from_preview_counts`.
- Ingestion: `test_ingestion_hardening` contains separately named regressions for durable bad-document recovery/restart, source-ID collisions, quarantine failure/cursor preservation, immutable transport identity, changed documents, replay idempotency, incomplete identity, transaction rollback, stale partial status, non-object sources and partial searches.
- Rendered contrast, favicon health and interaction regressions: `scripts/browser_e2e.cjs`; observed RED/GREEN logs and screenshots remain local outside Git.

## Ingestion guarantees and limits

Identified invalid sources are recorded with their original JSON, connector/index/document identity and payload hash in `rejected_source_events`. If rejection storage fails, the prior cursor remains. Rejection and document replay are idempotent. Unidentifiable or incomplete API pages fail closed. Partial search results never establish a safe advancing cursor.

The existing global unique Wazuh alert-ID schema is deliberately preserved. Conflicting namespaces/documents are quarantined rather than silently dropped, merged or given invented source IDs. An operator must review and resolve quarantined conflicts; no automated replay/repair UI is introduced. Provenance is additive and historical source identities are not fabricated.

Source/pair login budgets survive cookie changes and worker restarts. Limits use the direct source address, avoiding account-wide lockout by an unrelated address; clients behind an unconfigured reverse proxy share that proxy budget. No forwarded headers are newly trusted.

## Rendered UI E2E

- Live app: **http://127.0.0.1:5000**, normal entry point, original runtime DB/keys, signed-in user browser. Verified triage/action scope, saved cases, labels, progression, collection banner, manual refresh and broad retention preview. No agent-driven live decision, purge or reassessment was submitted.
- Disposable app: **http://127.0.0.1:5001**, a temporary backup with polling disabled. A random test account was created only there and signed in through the normal login form. Investigation, assessment, recommendations and decision saves occurred only on this copy.
- Playwright/installed Edge: **1440×1000 desktop**, **390×844 mobile**. Meaningful page content, expected URLs, no application error overlay, no runtime/console errors, screenshots, real filter/drill-down/action state checks, keyboard focus and no mobile horizontal overflow passed.
- Flows: login → triage → priority reason/target; detections → filter → family → group detail; investigate → case → assessment → advisory recommendation → saved decision; admin → retention preview only; empty and invalid-filter states; browser expiry redirect.
- The in-app browser also exercised the real signed-in UI in its narrow pane. Flask test-client HTML is not represented as browser proof.
- Screenshots remain outside Git, alongside local verification logs. They show the disposable banner as collection disabled by design.

Reproduction: run `scripts/serve_browser_fixture.py` with the worktree, absolute main-DB path and an output directory outside the repository, using the existing venv. It opens the source read-only, backs up to a disposable database, disables polling and creates a random disposable-only account. Set `CDSS_E2E_OUTPUT_DIR`, `CDSS_PLAYWRIGHT_MODULE` to the already installed Playwright module, and `CDSS_BROWSER_EXECUTABLE` to installed Edge before running `scripts/browser_e2e.cjs`. The browser harness is fixed to port 5001 to avoid submitting live decisions. The temporary credential file was removed after final QA; runtime logs/screenshots/backups were not committed. Desktop and mobile screenshots were taken at different stages of the disposable investigation, so one pending occurrence was consumed between them.

## Visualization decision

Analytical job: operational triage and ranked workload comparison. Primary artifact: the existing labeled queue and linked counts; fallback for deeper analysis: filtered detections/family detail. No new chart was implemented.

| Candidate | Question/decision | Source and aggregation/window | Empty/partial/stale treatment | Cost and conclusion |
|---|---|---|---|---|
| Pending by Initial Priority | Which urgency band needs attention? | Pending family counts, current stored snapshot | Unassigned stays separate; contact status visible | Existing linked counts answer more directly; reject duplicate chart |
| Volume over time | Is activity increasing? | Event-time buckets versus ingestion-time buckets | Late/backlogged data must be distinguished; absent data is not zero collection | Extra query/semantics not justified for current next-investigation decision; defer |
| Highest-attention assets | Which system needs review first? | High/Critical pending families by configured asset | Unmapped systems explicit; snapshot scope required | Existing queue/system filter supplies action target; reject duplicate ranking |
| Detection-family activity | Which repeated family dominates? | Actual family members within configured windows | Family count must not substitute selected investigation scope | Existing family counts and comparison already clearer; reject extra chart |

No decorative pies, SIEM chart duplication, chart library, invented metrics or new methodology was added. Chart-specific rendering tests are not applicable. Numeric dashboard/filter/group and mobile interaction checks remain applicable and passed.

## Performance

Representative snapshots held approximately **16.7k alerts**, **1,994–1,995 cases**, and an **84 MB** database. Timings are local observations with other verification work running, not service-level guarantees.

| Path | Observed time |
|---|---|
| Triage service | 1.25–2.36 s across measured snapshots |
| Detections service | 1.70–2.36 s |
| Group detail service / rendered navigation | 1.26–1.46 s / 1.93–2.31 s |
| Family detail service | 2.48–2.79 s |
| Investigations list rendered navigation | 0.40 s |
| T4 case rendered navigation | 0.32–0.47 s |
| Broad retention preview before | Exceeded 15 s query budget; live narrower preview also stalled |
| Broad retention service after | **1.43 s** |
| Broad retention browser POST after | **2.19–2.62 s**, including rendering |

Query plans identified repeated unindexed correlated scans across reference/archive tables. Set membership removed that repeated work while regression tests preserved exact counts/protection and fixed NULL/reference-column cases. Grouping still scans/sorts history and uses request-local TEMP summaries; further optimization is deferred rather than changing semantics without a clear latency target. Live successful contact/cursor state was inspected; no artificial alerts were generated to measure throughput or lag.

## Preservation and operational effects

- Main DB reset: **No**.
- Alerts purged: **No**. All original **16,676** alert rows remain value-for-value identical; subsequent normal collection appended an alert in the audited interval.
- Historical assessments rewritten: **No**. Original 132 assessments, original findings, initial priorities, case memberships, contextual recommendations and analyst decisions retained identical row-prefix hashes. A new user-driven live case appeared while the user was browsing; appended records are distinguished from historical mutation.
- Wazuh configuration changed: **No**. Existing connector settings, credentials and live cursors were not manually reset or edited.
- Attacks generated: **No**.
- Normal startup: existing `prepare_runtime()` initializes storage and runs its existing seed/backfill path. It refreshed `knowledge_base` timestamps/seed values and regenerated the 50 legacy recommendation-template rows; those two table hashes therefore changed. This was not a separately invoked seed/reset or a rewrite of historical contextual recommendations/assessments. Exact pre-startup row values for those two legacy template tables were not retained beyond their baseline hashes.
- Additive tables: login budgets, source-document provenance and rejected-event storage. Runtime files, keys and local credentials are not committed.

## Remaining limitations

1. Local Flask development server remains in use; production WSGI, TLS termination, proxy policy and multiworker deployment are not certified here.
2. No GitHub CI workflow existed. Local tests and independent review are recorded; absent CI is not a passing CI result.
3. Browser mutations were tested on a disposable backup. Live production decisions/purges/reassessments were deliberately not manufactured for testing.
4. Original remote archive documents were not refetched for the saved cases. Retained selected source fields/document IDs were verified; truncation/partial coverage remains visible.
5. Namespace conflicts require operator review in durable quarantine. Global source-ID schema and existing historical identities remain unchanged. No automated repair or replay console is provided.
6. Incomplete identity, malformed API envelopes, partial searches or unavailable quarantine storage retain the cursor and require operator intervention rather than silently losing evidence.
7. Strict event-time search_after ordering can miss sufficiently late-arriving older source events; this task did not reset cursors or implement historical replay.
8. Triage/grouping still costs roughly 1–3 seconds at current history and is not proven at enterprise volumes.
9. Inactivity is based on meaningful HTTP requests. A long open form can expire; no new background activity heartbeat was introduced.
10. Reverse-proxy clients need deliberate trusted-proxy configuration before per-source rate limits represent individual clients. Existing explicit lab TLS verification overrides were preserved, not weakened or certified as production policy.
11. Historical assessments can reflect earlier asset scope/criticality. Their preserved snapshots and current-setting notices must be considered by analysts.
12. Normal startup's existing legacy seed/template refresh remains an operational side effect, disclosed above.

## October 28 verification record (historical)

Final full regression: **433 tests, zero failures/errors, 308.802 seconds**, freshly run after the final source changes. Isolated wrapper confirmed protected outer database unchanged and zero write statements.
Focused E2E: **13 tests, zero failures/errors**, including offline T1–T4/Inconclusive pipeline/forms; protected outer database unchanged, zero writes. These fixtures do not prove live Wazuh detection effectiveness.
Browser: 13 workflow/quality checks passed; zero console errors; desktop/mobile verified.
Visualization: no new charts; dashboard truth/interaction checks passed.
compileall: **passed**, covering app/tests/scripts and entry points. Diff check: **passed**; Git's LF/CRLF conversion notice is informational.
Main DB: read-only integrity `ok`; zero FK violations; zero orphans across 57 relationships; zero duplicate source IDs, case memberships, archive documents, transport documents or rejected versions in the recorded preservation check.
Independent code review: no remaining actionable blocker; its final 433-test verification condition is satisfied.
Hardening implementation commit: **`28cfcd9183e54fb98a23898acf334367e46cbcbc`**, “Harden authentication, ingestion reliability, and retention previews”; 29 files, 1,027 insertions and 60 deletions. A documentation-only follow-up records these verification identifiers.

Remote push: **verified** by fresh `ls-remote`; hardening remote matched the implementation SHA and remote main remained **`5623b51aff3e5873a11e53e9bce38f61e5c2044f`**. Subsequent report-only commits remain on the same branch; the current branch tip is available in Git/PR history.

Draft review: **https://github.com/enigma-portal/cdss/pull/1**. No merge performed. The Code Review plugin returned head revision `28cfcd9183e54fb98a23898acf334367e46cbcbc`, with **zero checks, statuses or annotations**. This means CI is absent, not that CI passed. Independent source/evidence reviewers reported no remaining actionable blocker.
## PR #1 pre-merge remediation — 30 October 2026

### Scope and verdict

**READY WITH LIMITATIONS for review; NOT MERGED.** Only `e2e-hardening-2026-10-28` was changed. Starting local/remote branch SHA: `8a9a259ab0d5f34f49097748f33f0da46b7a6d30`. Remote main remained the checkpoint `5623b51aff3e5873a11e53e9bce38f61e5c2044f`. No merge, reset, force push, dependency installation, live connector edit, cursor reset, purge, or historical assessment rewrite was performed.

Systematic debugging reproduced both requested P1 defects through real Flask administration routes, database migrations, the poller and Indexer parsing, mocking only external transport/credentials. Strict TDD established regression failures before corrections. Independent review identified additional cases within the same source-identity contract; these also followed RED → minimal fix → GREEN. Verification-before-completion was applied to the final source state.

### P1-1: connectivity versus collection health

**Root cause:** Manual connection tests and polling both wrote `status` and `last_success_at`. The collection-status service interpreted those shared contact fields as proof of collection. A manual success could therefore falsely show active collection, overwrite partial status, or conceal a poll failure.

**Fix:** An additive, repeatable migration adds `poll_status`, `last_poll_success_at` and `last_poll_error`. Only an actual successful collection cycle establishes poll proof, including a valid empty response. Manual testing retains its latency, cluster-health, contact timestamp and connection result without modifying poll proof or cursors. Connector edits invalidate previous poll proof.

The banner and connector card use the explicit poll fields. Pending durable rejections remain visible independently of manual connectivity status, including after recreation of a known logical source. Failed/stale/unknown states retain a source-review warning when applicable. The admin page separately labels “Last successful collection cycle” and “Last successful SIEM contact.” Legacy contact timestamps are deliberately not backfilled as proven polls.

### P1-2: stable logical source identity

**Root cause:** The existing observation key `(connection_id, source_index, source_document_id)` treated a recreated connector's new database ID as a different source, even when only credentials changed. Conversely, changing an endpoint under an existing ID could incorrectly retain an old identity.

**Stable source identity semantics:**

- Persist `source_namespace` as versioned JSON: `["endpoint-v1", connector_type, canonical_https_host, effective_port]`.
- Normalize host case, trailing DNS dot, IDNA spelling and IPv6 textual form. Use the shared HTTPS endpoint validator. Identity calculation never resolves DNS.
- Connector ID, friendly name, credentials, TLS verification setting and query/index pattern do not define logical source identity. The actual returned index and document ID independently scope a source document.
- Persist the original observation's namespace. Exact matching payload, Wazuh ID, namespace, actual index and document ID can be observed again through a recreated connector without duplicating or rewriting the alert. A new observation records the new connector ID while preserving the old observation.
- Compare the logical document before insertion, so changing both the payload and Wazuh ID after recreation cannot manufacture a second version of the same immutable document.
- Different origin, conflicting payload, reused source identity, missing historical provenance or unknown legacy namespace fails closed or is durably quarantined. Current editable connector settings are never used to invent historical origin.
- Capture connector configuration before fetch and recheck it inside write transactions for ingestion, quarantine and cycle completion. An administrator edit during fetch cannot attribute old-source data, cursor progress or poll proof to the new configuration.

**Limits:** Different DNS aliases, hostname/IP forms or ports are different identities even if they happen to reach the same cluster. Replacing a cluster behind an unchanged endpoint cannot be detected from endpoint identity alone; a reused immutable document that differs is still rejected, but an exact matching document is indistinguishable. No remote cluster UUID is invented or claimed. Legacy rows with NULL/absent provenance require explicit operator review on replay; no historical backfill, repair or rewrite was performed.

### P2: bounded quarantine reason codes

**Implemented.** New durable rejections use the existing `reason` field with a fixed whitelist: `malformed_event`, `changed_document`, `source_identity_conflict`, `incomplete_identity`. Arbitrary exception strings are never stored there; historical reasons are preserved. Specific malformed/changed/conflicting cases are covered by integration assertions. An unidentifiable API page continues to fail closed rather than pretending a durable source identity exists. No quarantine-management UI was added.

A reused volatile quarantine key whose stored namespace differs cannot be silently ignored: it retains the previous cursor and reports collection failure. Original rejected JSON, hash and origin remain preserved.

### TDD evidence and regression quality

Evidence logs and screenshots are local artifacts outside Git in the parent of the worktree. Assertions were not removed to obtain green. Existing status fixtures were updated to explicitly provide poll proof under the new contract; their freshness, disabled/error and rendering expectations remain.

| Regression | Observed RED | Minimal correction | GREEN |
|---|---|---|---|
| Manual success with no poll; durable review warning; manual success after poll failure | Initial integration run: 5 new failures, zero errors, including both identity failures below | Separate persisted poll proof and independent rejection visibility | Status cases passed; final 17-test integration suite passed |
| Recreate same endpoint/new ID; change endpoint under same ID | Exact replay falsely quarantined; changed endpoint accepted as original | Persist and compare stable namespace, preserve individual observations | Replay creates no duplicate or rewrite; new documents ingest; genuine conflicts quarantine |
| Edit configuration after successful poll | Old collection proof still showed active | Invalidate proof on edit | Edit regression passed |
| Generic rejection reason; reused quarantine key across endpoints | Reason assertion and cursor-retention assertion failed | Whitelisted reason codes and namespace check before idempotent rejection insert | Both passed |
| Changed logical document plus new Wazuh ID after recreation | Second alert incorrectly inserted | Namespace/index/document lookup before insertion | One immutable alert retained; changed version quarantined |
| Configuration edit during fetch, valid and malformed documents | Old-source data/proof could be attributed to changed configuration | Snapshot checks inside write transactions and before completion | No false provenance, rejection, cursor or proof minted |
| Existing alert without historical provenance | Replay invented an origin | Require known compatible provenance before accepting duplicate ID | Historical alert retained and replay quarantined |
| Logical-document lookup at 20,000 provenance observations | New alert failed to complete within a deterministic 20,000 SQLite-operation budget | Composite index on `(source_namespace,source_index,source_document_id)` | Same test passed without weakening the work budget |

Local RED records: `pr1-integration-red.log`, `pr1-edit-red.log`, `pr1-reasons-red.log`, `pr1-review-red.log`, `pr1-query-red.log`. Corresponding GREEN records include `pr1-integration-green.log`, `pr1-edit-green.log`, `pr1-reasons-green.log`, `pr1-review-green.log`, `pr1-query-green.log`. The first discovery harness imported a TestCase directly and also ran nine existing auth tests; that import was corrected to a module reference. No harness error was represented as a product defect.

The new `tests/test_pr1_integration.py` contains 17 tests covering real administration/poll persistence interactions, empty polls, failures, quarantine visibility, recreation, immutable payload/history, endpoint changes, migration idempotency, unknown/absent legacy provenance, canonical origin spelling, configuration races and bounded query work. Schema/provenance fixture checks include FK validation. The SQL budget measures work at a defined history volume; it is not an ingestion-throughput or enterprise-scale claim.

### Rendered browser QA

**Flow:** normal login → SIEM connections → Test connection → Enable collection → actual disposable poll outcomes → banner/card state and separate connectivity information.

**Environment:** `http://127.0.0.1:5001/admin/siem-connections`; installed Edge through Playwright; desktop 1440×1000 and mobile 390×844. **Browser plugin not available.** The fallback used already installed dependencies. This follow-up used a fresh disposable database and synthetic external transport, not a copy modified in place or a live SIEM request. The original app on port 5000 was not restarted.

| Requested state / interaction | Rendered result | Result |
|---|---|---|
| Manual test succeeds, no proven poll | Collection status unknown; green cluster/contact shown separately; no proven successful poll | PASS |
| Valid successful poll with zero alerts | Collection active; successful collection timestamp visible | PASS |
| Old poll followed by successful manual test | Collection stale; manual success does not refresh poll proof | PASS |
| Failed poll followed by successful manual test | Collection interrupted; poll error retained separately | PASS |
| Durable malformed event followed by successful manual test | Collection partial / source documents need review | PASS |
| Empty successful poll with unresolved rejection | Collection remains partial / review required | PASS |
| Mobile 390px | No horizontal overflow; readable collection banner | PASS |
| Keyboard | Focus advances to an actual control | PASS |

| Required QA evidence | Result |
|---|---|
| Page identity, expected route/title, HTTP success | PASS |
| Meaningful nonblank content | PASS |
| No application error overlay | PASS, visually inspected |
| Console/page errors | Zero |
| Screenshot evidence | All five states plus persistent partial and mobile captured and inspected |
| Actual interaction proof | Login, Test connection, Enable collection, and subsequent rendered state checks passed |

Final browser run: **8 checks, zero errors**, after the final migration/index change. Screenshots remain outside Git: `pr1-test-only.png`, `pr1-poll-active.png`, `pr1-poll-stale.png`, `pr1-poll-failed.png`, `pr1-quarantine-partial.png`, `pr1-empty-poll-keeps-review.png`, `pr1-partial-mobile.png`. The active screenshot correctly shows no stored ingestion contact: an empty successful poll proves collection without inventing a new alert.

Reproduction artifacts are `pr1_browser_server.py`, `pr1_browser.cjs` and `pr1-browser-results.json` outside the repository. The QA server controls only a fresh temporary DB, disables background polling and uses a disposable-only random login. Run it with the existing venv and worktree/output arguments, then run the CJS script with the installed Node runtime. QA-only control routes are not production code. The temporary credential file is removed after QA. No new charts, frontend build workflow or dashboard redesign was introduced.

Remaining browser scope: this was Edge at the stated two viewports, with synthetic transport. It does not validate another browser, remote Wazuh service availability, unattended production deployment or a migrated live runtime. Installing the Browser plugin would allow future in-app browser QA; it was not installed by this task.

### Fresh final verification

| Check | Exact result |
|---|---|
| Full regression after final source/index changes | **450 tests, 0 failures, 0 errors; 327.272 seconds** |
| Focused new PR integration suite | **17 tests, 0 failures/errors** |
| Focused authentication (`test_auth*.py`) | **13 tests, 0 failures/errors** |
| Focused ingestion (`test_*ingestion*.py`) | **20 tests, 0 failures/errors** |
| Focused SIEM/status (`test_siem*.py`) | **10 tests, 0 failures/errors** |
| Focused phase 9 E2E | **13 tests, 0 failures/errors**, offline T1–T4/Inconclusive pipeline/forms |
| Isolated wrapper protection | Outer DB byte-for-byte unchanged, zero write statements; integrity ok, FK empty |
| Real rendered browser | **8 checks passed, 0 console/page errors**, desktop/mobile |
| compileall | Passed: app, tests, scripts, run.py, wsgi.py, config.py |
| git diff --check | Passed; LF/CRLF notices informational |
| Main DB explicit read-only integrity | `ok` |
| Main DB FK violations | **0** |
| Main DB orphan checks | **0 across 57 declared relationships** |
| Main DB duplicate checks | **0** source IDs, case memberships, archive documents, transport documents, rejected versions |
| Historical preservation | **18,530/18,530 alerts unchanged; no protected historical table prefix changed** |
| Independent final source review | No remaining correctness/security blocker; composite index addresses review's lookup finding |
| Visualization | No charts added; chart-specific tests not applicable |

Full/focused suites used the existing `scripts/run_isolated_checks.py` wrapper so discovery and tests could not open the main database. Example full invocation: existing venv Python, `scripts/run_isolated_checks.py full ../pr1-final-full.log`; focused runs supply the discovery pattern as the fourth command argument. The final main-DB check used explicit SQLite read-only mode and a consistent read transaction, with per-table baseline hashes and FK/duplicate/orphan checks. Output: `pr1-preservation-final.json`, outside Git.

Expected negative-path polling/error logs were observed during passing tests; they are not hidden production failures. Existing fresh-cookie throttling, unrelated-source lockout protection, idle timeout, HTTPS/pinned destination/DNS rebinding, partial/timed-out search, quarantine preservation/failure, retention preview, T-state and priority-boundary regressions remain included in the 450-test run.

### Preservation and remaining deployment limits

Main DB reset: **No**. Alerts purged: **No**. Historical assessments rewritten: **No**. Wazuh configuration changed: **No**. Attacks generated: **No**. Initial Alert Priority methodology, T1–T4 methodology, contextual-risk matrix and grouping semantics were not changed.

The new additive migration was verified only on disposable databases. The live runtime continues its existing code/schema until a deliberate normal startup/deployment; after migration, collection is conservatively unknown until a successful actual poll. No migration was applied merely for testing this follow-up.

Unknown historical source origin cannot be reconstructed safely; replay can require operator review. The original global unique Wazuh ID model remains, so genuine cross-source collisions still quarantine rather than silently merging or assigning invented IDs. There is still no quarantine resolution/replay console. Pending-quarantine health aggregation depends on retained quarantine history; no high-volume status-query SLA is claimed. The October 28 deployment, proxy, archive coverage, late-arrival, startup seed and scale limitations remain applicable.

### Remediation Git receipt

The verified implementation SHA and push verification are recorded in the following receipt after committing. A report-only receipt commit necessarily has its own SHA; the exact final branch tip is provided in the task handoff and can be resolved from `refs/heads/e2e-hardening-2026-10-28`. PR #1 remains **NOT MERGED**.

- Final verified implementation SHA: **`fcd983d003f8a171c5bf29122a4a8ef944eb1fef`**.
- Commit: **Separate collection proof and preserve stable SIEM source identity**; 14 files, 591 additions and 46 deletions, including this remediation report and 17 new regression tests.
- Final-source verification: **450/450 passed**; the only subsequent change is this documentation receipt. No application or test edits followed the passing run.
- Staged-file inspection: 14 intended files, no forbidden runtime/database/secret paths and no detected private-key/token patterns. The disposable QA server was stopped and its generated credential file removed.
- Pre-push remote verification: hardening was still `8a9a259ab0d5f34f49097748f33f0da46b7a6d30`; main remained `5623b51aff3e5873a11e53e9bce38f61e5c2044f`. GitHub reported PR #1 open, draft and `merged=false`.
- Publication: normal push of the implementation and this report-only receipt to the existing hardening branch; final remote-head equality and PR status are checked after push and recorded in the task handoff. The exact final branch SHA includes the receipt commit and is obtained from Git rather than claiming a self-referential report hash.
