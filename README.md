# Prototype of Cyber Incident Decision Support System

## Overview

CDSS is a postgraduate cybersecurity prototype that integrates with Wazuh SIEM
and uses MITRE ATT&CK context, where available, to support security analysts
with incident prioritization, contextual risk assessment, and explainable
advisory recommendations.

CDSS complements Wazuh rather than replacing the SIEM. Wazuh remains the
detection and event source, while CDSS provides project-defined decision
support. Missing security context is not fabricated, and the system does not
claim autonomous intelligence or response.

## High-Level Architecture

`Wazuh SIEM → Grouped Alert → Initial Alert Priority → Analyst Investigation Case → Evidence and Playbook Findings → Contextual Risk → Advisory Recommendations → Analyst Decision`

Initial Alert Priority is a versioned, project-defined triage aid for grouped
alerts. It is separate from the post-investigation qualitative Contextual Risk.
MITRE ATT&CK supplies context, not an official severity score.

The SIEM poller resumes from a persisted OpenSearch `search_after` cursor.
Changing the minimum rule level affects future polling only: events already
passed by that cursor are not silently replayed. A historical backfill requires
an explicit, bounded, deduplicated operation; changing the setting does not
reset the cursor.

## Core Technologies

- Python
- Flask
- SQLite
- Wazuh
- MITRE ATT&CK

## Basic Setup

1. Create a Python virtual environment:

   ```bash
   python -m venv venv
   ```

2. Activate the environment.

   Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

   Linux or macOS:

   ```bash
   source venv/bin/activate
   ```

3. Install the required packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and configure the required environment
   variables with authorized lab values. Do not commit credentials or secrets.
5. Start the application:

   ```bash
   python run.py
   ```

6. Open `http://127.0.0.1:5000` and complete the first-run administrator setup
   if required.

For a WSGI server, use `wsgi:app` as the entry point. Both `python run.py` and
`wsgi:app` initialize storage and attempt to claim the single poller lock;
importing `run:app` alone does neither, so test imports cannot start polling.

## Academic / Prototype Scope

CDSS is a cybersecurity decision-support prototype intended for authorized
laboratory and testing environments. Its contextual risk assessment is
project-defined, and its recommendations are advisory. CDSS does not
automatically execute containment or remediation actions.


## Manual authenticated validation after live-audit remediation

The source changes require a controlled restart of the existing CDSS process
before manual validation; debug/reload is disabled. Do not start a second server
or reset storage. Existing application startup initializes storage and resumes
collection as documented above. No credentials, users or asset mappings were
changed by the remediation. Browser automation's `CryptUnprotectData` failure is
an automation limitation, not evidence of a CDSS login defect.

1. Sign in using an authorized analyst account and open Alerts. Review agent
   `002`: its asset is currently **Not mapped**, and criticality and assessment
   scope are unavailable. An administrator must confirm real inventory data
   before mapping it; no criticality or protected status is inferred.
2. Open a grouped alert, refresh it and confirm that no case was created. Use
   Investigate once, then reopen the group to confirm the saved case is reused.
3. Compare every grouped member with the saved case. Review archive coverage,
   selected playbook provenance under Technical / Audit Details, findings,
   evidence state, risk explanation and recommendations. With missing mapped
   asset context, contextual risk must stay Unassessed with an explicit reason.
4. Review truncation before making a decision. New same-agent queries retain
   records nearest to either first_seen or last_seen within the original bounded
   window, with timestamp/index/document-ID tie-breakers. The configured
   `CDSS_INVESTIGATION_MAX_ARCHIVE_EVENTS` hard cap (default 200, maximum 1000)
   still applies; omitted matches remain explicitly truncated, never complete
   negative evidence. Retained observations are displayed chronologically.
   The older saved retrievals remain historical records, not refreshed results.
5. Save an appropriate Analyst Decision with a reason, reload the case and
   verify the current decision and history. This does not execute a response
   action or close the case. This authenticated live workflow remains pending
   manual validation; offline tests do not replace it.

## Timestamp contract and the reported SIEM contact time

The reported `2026-10-16 00:02:00` is the exact value stored in
`siem_connections.last_success_at`. Previously, the poller and manual connection
check generated it using SQLite `CURRENT_TIMESTAMP` from the CDSS host clock.
The banner and SIEM card rendered that offset-free string unchanged; there was
no timezone conversion, and no double conversion. With Wazuh independently
verified at `2026-10-15 12:02 UTC` (`17:02 PKT`), this is evidence to correct the
CDSS host clock, not to shift Wazuh events. The previous cross-host measurement
showed disagreement and did not establish that Wazuh was wrong.

During this audit, SQLite returned UTC `2026-10-16 02:37:13` and host-local
`2026-10-15 19:37:13` (Pacific). Windows `w32tm /query /status` and `/query /source`
both returned `The service has not been started. (0x80070426)`. A fresh Indexer
probe was unreachable and the configured connector was disabled; it was not
re-enabled. An administrator must verify/correct the CDSS host synchronization
against the approved time source separately. No OS clock or service was changed.

Timestamp handling now follows these boundaries:

- New contact writes use an aware UTC clock and explicit `Z` suffix. Other
  SQLite-generated audit metadata remains UTC under SQLite's `CURRENT_TIMESTAMP`
  contract; its historical offset-free format is treated as UTC only for known
  database-owned fields. No historical timestamp was rewritten.
- New normalized alert/archive fields are UTC. Raw Wazuh alert JSON remains
  unchanged. Source timestamps require an explicit offset; an ambiguous naive
  source time is never guessed to be host-local or UTC.
- Grouping, investigation windows and legacy time-window comparisons use UTC
  instants. OpenSearch pagination cursors retain their original sort values.
- Server-rendered timestamps have a canonical UTC `datetime` and labelled UTC
  fallback. Only the UI converts that instant once using the browser's timezone;
  it displays both the local zone name and UTC offset, including DST. The UTC
  value remains in the tooltip and machine-readable attribute. No fixed-hour
  compensation or source-clock correction is performed by CDSS.

For example, `2026-10-15T12:02:00Z` displays as `17:02` in `Asia/Karachi`.
A wrongly generated `2026-10-16T00:02:00Z` correctly displays as `05:02` on
October 16 in Karachi; display conversion cannot repair that wrong instant.
After the CDSS host clock is corrected, a new successful contact is needed to
replace the old value. Restart the existing CDSS process to load source changes;
no application restart or authenticated live validation was performed here.

The archive query uses OpenSearch's [numeric script sorting](https://docs.opensearch.org/latest/search-plugins/searching-data/sort/)
on the already-filtered source window; it transfers only the configured cap.
