"""Add execution history and evidence findings; never update risk or incidents."""


def migrate_investigations(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        playbook_key TEXT NOT NULL,
        playbook_import_hash TEXT,
        status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
    columns={row['name'] for row in connection.execute('PRAGMA table_info(investigations)')}
    if 'playbook_import_hash' not in columns:
        connection.execute('ALTER TABLE investigations ADD COLUMN playbook_import_hash TEXT')
    connection.execute('''CREATE INDEX IF NOT EXISTS investigations_incident
        ON investigations(incident_id,id)''')
    connection.execute('''CREATE UNIQUE INDEX IF NOT EXISTS investigation_incident_pair
        ON investigations(id,incident_id)''')
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_findings (
        id INTEGER PRIMARY KEY,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        finding_key TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        finding_value TEXT NOT NULL CHECK(json_valid(finding_value)),
        finding_status TEXT NOT NULL CHECK(finding_status IN ('observed','not_observed','unavailable')),
        evidence_alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
        rationale TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(investigation_id,finding_key))''')
    # A count/sequence can depend on several alerts, not just one primary reference.
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_finding_alerts (
        finding_id INTEGER NOT NULL REFERENCES investigation_findings(id) ON DELETE CASCADE,
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        PRIMARY KEY(finding_id,alert_id))''')
