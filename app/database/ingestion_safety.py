"""Additive provenance and durable rejection records; source alerts stay intact."""


def migrate_ingestion_safety(connection):
    connection.execute('''
        CREATE TABLE IF NOT EXISTS alert_source_documents (
            connection_id INTEGER NOT NULL, source_index TEXT NOT NULL,
            source_document_id TEXT NOT NULL, alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            PRIMARY KEY(connection_id,source_index,source_document_id))''')
    connection.execute('CREATE INDEX IF NOT EXISTS idx_source_document_alert ON alert_source_documents(alert_id)')
    connection.execute('''CREATE TABLE IF NOT EXISTS rejected_source_events (
            id INTEGER PRIMARY KEY, connection_id INTEGER NOT NULL,
            source_index TEXT NOT NULL, source_document_id TEXT NOT NULL,
            raw_event_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
            reason TEXT NOT NULL, recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(connection_id,source_index,source_document_id,payload_hash))''')
