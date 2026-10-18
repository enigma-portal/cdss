"""Additive separation of historical auto-cases from analyst-opened group cases."""


def migrate_group_cases(connection):
    columns = {row['name'] for row in connection.execute('PRAGMA table_info(incidents)')}
    if 'case_origin' not in columns:
        connection.execute("ALTER TABLE incidents ADD COLUMN case_origin TEXT NOT NULL DEFAULT 'legacy_ingestion'")
    if 'group_anchor_alert_id' not in columns:
        connection.execute('''ALTER TABLE incidents ADD COLUMN group_anchor_alert_id INTEGER
            REFERENCES alerts(id) ON DELETE SET NULL''')
    connection.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_group_anchor
        ON incidents(group_anchor_alert_id) WHERE group_anchor_alert_id IS NOT NULL''')
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_case_alerts (
        case_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id) ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
        added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(case_id,alert_id), UNIQUE(case_id,ordinal)
    )''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_case_alerts_case
        ON investigation_case_alerts(case_id,ordinal)''')
    connection.execute('''CREATE TABLE IF NOT EXISTS initial_alert_priorities (
        incident_id INTEGER PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
        initial_priority TEXT CHECK(initial_priority IN ('Low','Medium','High','Critical')),
        initial_priority_model_version TEXT NOT NULL,
        initial_priority_rationale TEXT NOT NULL,
        factors_json TEXT NOT NULL CHECK(json_valid(factors_json)),
        initial_priority_created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )''')
    connection.execute('''CREATE VIEW IF NOT EXISTS case_alert_members AS
        SELECT incident_id,alert_id,correlation_reason,ordinal FROM incident_alerts
        UNION ALL
        SELECT case_id AS incident_id,alert_id,'group_trigger' AS correlation_reason,ordinal
          FROM investigation_case_alerts''')
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_finding_archive_evidence (
        finding_id INTEGER NOT NULL REFERENCES investigation_findings(id) ON DELETE CASCADE,
        archive_evidence_id INTEGER NOT NULL REFERENCES investigation_archive_evidence(id) ON DELETE RESTRICT,
        PRIMARY KEY(finding_id,archive_evidence_id)
    )''')
