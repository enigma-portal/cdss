"""Add incident membership without merging or rescoring historical incidents."""

from app.services.incident_correlation import DEFAULT_WINDOW_MINUTES, WINDOW_SETTING


def migrate_incident_alerts(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS incident_alerts (
        incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id) ON DELETE CASCADE,
        correlation_reason TEXT NOT NULL CHECK(length(trim(correlation_reason))>0),
        ordinal INTEGER NOT NULL CHECK(ordinal>=0),
        added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(incident_id,alert_id), UNIQUE(incident_id,ordinal))''')
    columns = {row['name'] for row in connection.execute('PRAGMA table_info(incidents)')}
    if 'last_activity_at' not in columns:
        connection.execute('ALTER TABLE incidents ADD COLUMN last_activity_at TEXT')
        connection.execute('UPDATE incidents SET last_activity_at=detected_at')
    # Conflicting legacy membership fails visibly rather than deleting records.
    columns = {row['name'] for row in connection.execute('PRAGMA table_info(incidents)')}
    origin_clause = "AND i.case_origin='legacy_ingestion'" if 'case_origin' in columns else ''
    connection.execute('''INSERT INTO incident_alerts(incident_id,alert_id,correlation_reason,ordinal)
        SELECT i.id,i.alert_id,'seed_migrated',0 FROM incidents i
        WHERE NOT EXISTS(SELECT 1 FROM incident_alerts ia WHERE ia.incident_id=i.id) ''' + origin_clause)
    connection.execute('INSERT OR IGNORE INTO system_settings(setting_key,setting_value) VALUES(?,?)',
                       (WINDOW_SETTING, str(DEFAULT_WINDOW_MINUTES)))
    connection.execute('''UPDATE alerts SET processing_status='processed'
        WHERE processing_status='new' AND EXISTS (
            SELECT 1 FROM incident_alerts ia WHERE ia.alert_id=alerts.id)''')
