"""Add investigation-scoped Wazuh archive references without copying archives."""


def migrate_archive_evidence(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_archive_runs (
        investigation_id INTEGER PRIMARY KEY REFERENCES investigations(id) ON DELETE CASCADE,
        connector_id INTEGER REFERENCES siem_connections(id) ON DELETE SET NULL,
        trigger_alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
        asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
        asset_name_snapshot TEXT,
        asset_criticality_snapshot TEXT,
        asset_protected_snapshot INTEGER CHECK(asset_protected_snapshot IN (0,1)),
        reported_agent_id TEXT,
        reported_agent_name TEXT,
        rule_id TEXT,
        rule_description TEXT,
        first_seen TEXT,
        last_seen TEXT,
        window_start TEXT,
        window_end TEXT,
        group_occurrences INTEGER NOT NULL CHECK(group_occurrences > 0),
        pivots_json TEXT NOT NULL CHECK(json_valid(pivots_json)),
        timestamp_field TEXT,
        agent_field TEXT,
        retrieval_status TEXT NOT NULL CHECK(retrieval_status IN
            ('running','available','empty','unavailable','failed')),
        retrieved_count INTEGER NOT NULL DEFAULT 0 CHECK(retrieved_count >= 0),
        total_hits INTEGER CHECK(total_hits IS NULL OR total_hits >= 0),
        total_hits_exact INTEGER CHECK(total_hits_exact IS NULL OR total_hits_exact IN (0,1)),
        truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1)),
        error_category TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )''')
    # Task 3 adds a versioned selection snapshot to the existing retrieval
    # execution. Historical runs remain intact and explicitly unselected.
    columns = {row[1] for row in connection.execute(
        'PRAGMA table_info(investigation_archive_runs)')}
    for name, definition in (
        ('selected_playbook_key', 'TEXT'),
        ('selected_playbook_source_hash', 'TEXT'),
        ('selection_reason', 'TEXT'),
        ('matched_triggers_json', 'TEXT CHECK(matched_triggers_json IS NULL OR json_valid(matched_triggers_json))'),
        ('cross_retrieval_status', "TEXT CHECK(cross_retrieval_status IS NULL OR cross_retrieval_status IN ('available','empty','unavailable','failed'))"),
        ('cross_retrieved_count', 'INTEGER CHECK(cross_retrieved_count IS NULL OR cross_retrieved_count >= 0)'),
        ('cross_total_hits', 'INTEGER CHECK(cross_total_hits IS NULL OR cross_total_hits >= 0)'),
        ('cross_truncated', 'INTEGER CHECK(cross_truncated IS NULL OR cross_truncated IN (0,1))'),
    ):
        if name not in columns:
            connection.execute(f'ALTER TABLE investigation_archive_runs ADD COLUMN {name} {definition}')
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_archive_triggers (
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        PRIMARY KEY(investigation_id,alert_id)
    )''')
    connection.execute('''CREATE TABLE IF NOT EXISTS investigation_archive_evidence (
        id INTEGER PRIMARY KEY,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        source_type TEXT NOT NULL DEFAULT 'wazuh_archive'
            CHECK(source_type = 'wazuh_archive'),
        source_index TEXT NOT NULL,
        source_document_id TEXT NOT NULL,
        event_timestamp TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        event_type TEXT,
        short_summary TEXT NOT NULL,
        selected_fields_json TEXT NOT NULL CHECK(json_valid(selected_fields_json)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(investigation_id,source_index,source_document_id)
    )''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_archive_runs_connector
        ON investigation_archive_runs(connector_id,investigation_id)''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_archive_evidence_run_time
        ON investigation_archive_evidence(investigation_id,event_timestamp,id)''')
