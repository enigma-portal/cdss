"""Additive provenance and durable rejection records; source alerts stay intact."""


def migrate_ingestion_safety(connection):
    columns = {row[1] for row in connection.execute('PRAGMA table_info(siem_connections)')}
    for name, definition in (
            ('poll_status', "TEXT NOT NULL DEFAULT 'not_tested'"),
            ('last_poll_success_at', 'TEXT'), ('last_poll_error', 'TEXT')):
        if name not in columns:
            connection.execute(f'ALTER TABLE siem_connections ADD COLUMN {name} {definition}')
    # A legacy successful contact may have been a manual test, never a poll.
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
    for table in ('alert_source_documents', 'rejected_source_events'):
        columns = {row[1] for row in connection.execute(f'PRAGMA table_info({table})')}
        if 'source_namespace' not in columns:
            connection.execute(f'ALTER TABLE {table} ADD COLUMN source_namespace TEXT')
    # Do not infer historical origin from a connector's editable current URL.
    connection.execute('CREATE INDEX IF NOT EXISTS idx_rejected_namespace ON rejected_source_events(source_namespace)')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_source_logical_document
        ON alert_source_documents(source_namespace,source_index,source_document_id)''')
