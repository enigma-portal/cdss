# CDSS Project Instructions

## Project
Cyber Incident Decision Support System using Wazuh SIEM and MITRE ATT&CK.

## Source of Truth
Work only in this repository.
Do not create another clone, worktree, or project folder.

Main database:
data/cdss.db

## Critical Rules
- Do not reset or replace data/cdss.db unless explicitly authorized.
- Do not insert demo/test data into the main database.
- Do not push to GitHub unless explicitly authorized.
- Do not invent security logic, mappings, weights, evidence, or validation results.
- If something cannot be verified, say so.
- Preserve existing working functionality unless a verified defect requires change.
- Prefer fixing root causes over adding workaround code.
- Keep backend complexity hidden from normal analyst UI.

## Product Flow
Wazuh Alert
→ Grouped Alert
→ Initial Alert Priority
→ Analyst Investigate
→ Investigation Case
→ Supporting Wazuh Evidence
→ Investigation Playbook
→ Findings
→ T1/T2/T3/T4/Inconclusive
→ Contextual Risk
→ Recommendations
→ Analyst Decision

## Initial Alert Priority
This is for triage only: which grouped alert should be investigated first.

It uses:
- Wazuh detection severity
- administrator-defined asset criticality
- bounded project-defined ATT&CK context
- bounded recurrence

Initial Priority is NOT final contextual risk.

## Final Contextual Risk
After investigation:

Evidence State + Asset Criticality = Contextual Risk

Evidence states:
- T1 Limited Evidence
- T2 Suspicious Activity
- T3 Strong Evidence
- T4 Advanced / Progressed Activity
- Inconclusive

Confidence is separate from risk.

Do not double-count Wazuh severity, ATT&CK, or recurrence in final contextual risk.

## Evidence Rules
Observed != Not Observed != Unavailable.

Unavailable must never be interpreted as benign or zero evidence.

Asset context, MITRE context, Wazuh severity, and playbook selection are context, not automatically malicious evidence.

## Investigation
A grouped alert is the analyst-facing investigation trigger.

Investigation should use:
- all grouped member alerts
- same-asset supporting evidence
- Wazuh archives
- bounded cross-asset evidence when supported by real pivots

Never infer compromise or lateral movement without supporting logs.

## Playbooks
Use the existing imported/normalized open-source playbook framework.

Do not claim XSOAR/MISP/CACAO integration unless the actual imported artifact is used by the selector/evaluator.

Do not install a full SOAR platform unless explicitly requested.

## Recommendations
Recommendations must be:
- evidence-specific
- explainable
- advisory
- human-approved

Do not invent NIST, CIS, MITRE D3FEND, or other framework mappings.

## UI/UX
Normal analyst should quickly understand:
- what happened
- where
- initial priority
- supporting evidence
- evidence strength
- contextual risk
- why
- recommended next action

Keep internal IDs, raw JSON, model versions, hashes, and execution details under collapsed Technical/Audit Details.

## Database
Preserve historical data and auditability.

Before DB changes:
- inspect dependencies
- preserve foreign keys
- avoid destructive migration
- run integrity checks

## Validation
After code changes run:
- full tests
- compile/syntax checks
- PRAGMA foreign_key_check
- relevant duplicate/orphan checks

Do not claim live Wazuh validation unless it was actually performed.

## Working Style
Before making substantial changes:
1. inspect existing implementation
2. identify the real defect
3. explain the intended correction briefly
4. make the smallest coherent fix
5. test it
6. report exactly what changed

Do not add unrelated features or over-engineer.
## Repository Map and Architecture
- `run.py` constructs the Flask app, configures security headers and registers the auth, dashboard and assets blueprints. `prepare_runtime()` initializes storage, seeds knowledge, backfills guidance and starts the poller.
- `wsgi.py` exposes `wsgi:app` and calls `prepare_runtime()` on import. Importing `run:app` does not initialize the main database or start polling, but can create `data/session.key` if absent.
- `app/routes/` handles HTTP and forms; `app/auth.py` handles access control. Keep decision logic in the existing `app/services/` modules rather than duplicating it in routes or templates.
- Collection flows through `poller.py`, `wazuh_indexer.py`, `alert_parser.py` and `ingest.py`. `alert_view.py` groups analyst-facing alerts; `incident_correlation.py` supports investigation cases. Ingestion must not silently create analyst investigation cases.
- `initial_priority.py` handles triage. `investigation.py`, `archive_evidence.py`, `contextual_risk.py` and `contextual_recommendations.py` handle post-investigation evidence, assessments and advice. Preserve the distinction from legacy `app/risk_engine/` and recommendation services.
- `app/database/__init__.py` owns SQLite connections and initialization; `phase3.py` through `phase7.py`, `architecture.py` and `archive_evidence.py` contain incremental migrations. `seed.py` maintains knowledge data.
- `app/mitre/taxii_sync.py` maintains ATT&CK catalogue provenance. `app/playbooks/imported_manifest.json` and playbook services describe imported artifacts and selection.
- `templates/` contains server-rendered Jinja pages; `static/css/` and `static/js/` contain local frontend assets. There is no Node frontend build workflow.
- `tests/test_*.py` uses standard-library `unittest`; `tests/fixtures/` and `tests/reference_evaluation.py` support offline reference evaluation. `scripts/export_source.py` creates allowlisted source archives.

## Setup and Commands
Run commands from the repository root. Use the existing virtual environment when available; on Windows its interpreter is `.\venv\Scripts\python.exe`.

```powershell
# Only if the environment is missing:
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# Start the application only when runtime initialization is intended:
python run.py

# Full regression suite:
python -m unittest discover -s tests -p "test_*.py"

# Focused example (discovery keeps tests/ helper imports working):
python -m unittest discover -s tests -p "test_contextual_risk.py"

# Syntax check, excluding venv and runtime data:
python -m compileall -q app tests scripts run.py wsgi.py config.py
```

- Substitute `.\venv\Scripts\python.exe` for `python` if the environment is not activated. On Linux/macOS use `source venv/bin/activate` or `venv/bin/python`.
- Configure `.env` from `.env.example` only if it is missing; never overwrite existing local settings. The dependency-free loader in `app/environment.py` preserves variables already in the process environment.
- Development startup binds to `127.0.0.1:5000`, with debug and reloader disabled. Both supported server entry points can mutate runtime storage and attempt to start collection. Do not start them merely to validate documentation.
- `CDSS_REALTIME_ENABLED=false` disables realtime collection for an intentional local server run; it does not make database initialization read-only.
- Dependencies are pinned in `requirements.txt`. No separate lint/formatter configuration or CI workflow was found during initialization; do not invent required tool commands.

## Test Isolation and Verification Details
- Follow existing tests: save `app.database.DATABASE`, point it to a `tempfile.TemporaryDirectory()` database before initialization/seeding, then restore it and clean up. Use Flask's test client for route tests.
- For connector tests, patch `app.services.secret_store.KEY_FILE` to a temporary key path. Mock transport and TAXII responses; never use live SIEM credentials or treat offline fixtures as live validation.
- Preserve CSRF and authorization checks in test form submissions. Do not bypass production controls to make tests pass.
- Keep `PRAGMA foreign_key_check` and relevant duplicate/orphan assertions on the disposable database for schema and ingestion tests. Use parameterized SQL and close connections.
- If checking the main database is necessary, open it explicitly read-only; do not call initialization, seed, backfill, rebuild or rescore helpers as a read-only check.
- After code changes, run the full suite and syntax checks required above. For documentation-only changes, review the document and verify the change scope; application tests are not required solely for prose.
- Report the exact checks run and any failures. Reference evaluation demonstrates fixture behavior, not independent proof of effectiveness or real attack execution.

## Implementation Conventions and Change Boundaries
- Match surrounding Python style: four-space indentation, snake_case functions/modules and existing explicit imports. Keep functions focused and reuse current services and connection helpers.
- Keep schema changes additive, repeatable and compatible with existing records. Test migrations on disposable databases before considering any operation on `data/cdss.db`.
- Preserve ingestion deduplication and persisted `search_after` cursors. A threshold change affects future polling; historical replay requires an explicit bounded, deduplicated backfill, not a cursor reset.
- Preserve session security, role checks, CSRF protection and the Content Security Policy. Keep scripts/styles in local static assets compatible with that policy.
- Treat source logs and external responses as untrusted. Keep secrets out of rendered pages, exceptions and logs. Do not read or print `.env`, `.env.txt`, `data/*.key` or connector credentials for routine inspection.
- Do not include runtime data, keys, virtual environments or credentials in source exports. If an export is requested, inspect and use the existing allowlist in `scripts/export_source.py`; do not archive the whole repository blindly.
- Inspect `git status --short` before editing. Existing modified and untracked files are user work, including this AGENTS.md; preserve them and do not clean, reset, stage, commit or publish them without authorization.
- Work in this checkout only. Keep changes limited to the requested task and summarize exactly which files changed, why, and how they were checked.