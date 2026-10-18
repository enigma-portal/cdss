"""Additive Phase 3 mapping provenance migration. No scoring writes."""

from app.services.mitre_mapping import attach_alert_context, record_alert_mappings


def migrate_mitre_provenance(connection):
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(mitre_techniques)")}
    if "catalogue_source" not in columns:
        connection.execute("""ALTER TABLE mitre_techniques ADD COLUMN catalogue_source
            TEXT NOT NULL DEFAULT 'legacy'
            CHECK (catalogue_source IN ('legacy','project_seed','placeholder','taxii'))""")
        connection.execute("""UPDATE mitre_techniques SET catalogue_source = 'placeholder'
            WHERE technique_name = 'Technique details awaiting MITRE TAXII synchronization'""")
    if "catalogue_synced_at" not in columns:
        connection.execute("ALTER TABLE mitre_techniques ADD COLUMN catalogue_synced_at TEXT")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS supplementary_mitre_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wazuh_rule_id TEXT NOT NULL CHECK (length(trim(wazuh_rule_id)) > 0),
            technique_id TEXT NOT NULL REFERENCES mitre_techniques(technique_id)
                ON UPDATE CASCADE ON DELETE RESTRICT,
            wazuh_reference TEXT NOT NULL CHECK (length(trim(wazuh_reference)) > 0),
            mitre_reference TEXT NOT NULL CHECK (length(trim(mitre_reference)) > 0),
            rationale TEXT NOT NULL CHECK (length(trim(rationale)) > 0),
            enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
            verification_status TEXT NOT NULL DEFAULT 'unverified'
                CHECK (verification_status IN ('unverified','verified')),
            approval_status TEXT NOT NULL DEFAULT 'pending'
                CHECK (approval_status IN ('pending','approved')),
            verified_at TEXT,
            approved_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (wazuh_rule_id, technique_id),
            CHECK (verification_status <> 'verified' OR verified_at IS NOT NULL),
            CHECK (approval_status <> 'approved' OR approved_at IS NOT NULL)
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alert_mitre_techniques (
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            technique_id TEXT NOT NULL REFERENCES mitre_techniques(technique_id)
                ON UPDATE CASCADE ON DELETE RESTRICT,
            mapping_source TEXT NOT NULL CHECK (mapping_source IN ('wazuh','supplementary')),
            ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
            source_reference TEXT NOT NULL CHECK (length(trim(source_reference)) > 0),
            mapping_rationale TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (alert_id, technique_id, mapping_source)
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS incident_mitre_sources (
            incident_id INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            source_alert_id INTEGER NOT NULL,
            mapping_source TEXT NOT NULL CHECK (mapping_source IN ('wazuh','supplementary')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (incident_id, technique_id, source_alert_id, mapping_source),
            FOREIGN KEY (incident_id, technique_id)
                REFERENCES incident_mitre_techniques(incident_id, technique_id)
                ON UPDATE CASCADE ON DELETE CASCADE,
            FOREIGN KEY (source_alert_id, technique_id, mapping_source)
                REFERENCES alert_mitre_techniques(alert_id, technique_id, mapping_source)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alert_mitre_technique ON alert_mitre_techniques(technique_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_incident_mitre_source_alert ON incident_mitre_sources(source_alert_id, technique_id, mapping_source)")
    for row in connection.execute("SELECT id FROM alerts ORDER BY id").fetchall():
        # Migration never retroactively applies supplementary mappings.
        record_alert_mappings(connection, row["id"], allow_supplementary=False)
    membership_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_alerts'"
    ).fetchone()
    query = ("SELECT incident_id AS id, alert_id FROM incident_alerts ORDER BY incident_id, ordinal"
             if membership_exists else "SELECT id, alert_id FROM incidents ORDER BY id")
    for row in connection.execute(query).fetchall():
        attach_alert_context(connection, row["id"], row["alert_id"])
