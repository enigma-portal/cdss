"""SQLite connection and schema setup for the CDSS project."""

import json
import re
import sqlite3
from app.time_utils import epoch_seconds
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE = BASE_DIR / "data" / "cdss.db"


def _ensure_asset_schema(connection):
    """Add the Phase 1 asset foundation without replacing existing records."""
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL CHECK (asset_type IN
                ('Endpoint', 'Server', 'Network Device', 'Security Appliance',
                 'Cloud Asset', 'Other')),
            asset_role TEXT NOT NULL,
            os_family TEXT NOT NULL,
            os_name TEXT NOT NULL,
            ip_address TEXT,
            wazuh_agent_id TEXT,
            criticality TEXT NOT NULL CHECK (criticality IN
                ('low', 'medium', 'high', 'critical')),
            is_protected INTEGER NOT NULL CHECK (is_protected IN (0, 1)),
            description TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    alert_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
    }
    if "asset_id" not in alert_columns:
        connection.execute("""
            ALTER TABLE alerts ADD COLUMN asset_id INTEGER
            REFERENCES assets(id) ON DELETE SET NULL
        """)
    incident_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(incidents)")
    }
    if "asset_id" not in incident_columns:
        connection.execute("""
            ALTER TABLE incidents ADD COLUMN asset_id INTEGER
            REFERENCES assets(id) ON DELETE SET NULL
        """)
    connection.executescript("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_wazuh_agent_id_unique
            ON assets(wazuh_agent_id) WHERE wazuh_agent_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_assets_asset_name ON assets(asset_name);
        CREATE INDEX IF NOT EXISTS idx_assets_ip_address ON assets(ip_address);
        CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts(asset_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_asset_id ON incidents(asset_id);
    """)


def _ensure_phase2_alert_schema(connection):
    """Preserve source-provided ATT&CK IDs and repair legacy status safely."""
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
    if "wazuh_mitre_ids" not in columns:
        connection.execute(
            "ALTER TABLE alerts ADD COLUMN wazuh_mitre_ids TEXT NOT NULL DEFAULT '[]'"
        )
    technique_pattern = re.compile(r"^T\d{4}(?:\.\d{3})?$")
    rows = connection.execute(
        "SELECT id, raw_alert FROM alerts WHERE wazuh_mitre_ids = '[]'"
    ).fetchall()
    for row in rows:
        try:
            source = json.loads(row["raw_alert"])
            values = ((source.get("rule") or {}).get("mitre") or {}).get("id", [])
            if isinstance(values, str):
                values = [values]
            normalized = []
            if isinstance(values, list):
                for value in values:
                    candidate = str(value).strip().upper()
                    if technique_pattern.fullmatch(candidate) and candidate not in normalized:
                        normalized.append(candidate)
            if normalized:
                connection.execute(
                    "UPDATE alerts SET wazuh_mitre_ids = ? WHERE id = ?",
                    (json.dumps(normalized, separators=(",", ":")), row["id"]),
                )
        except (TypeError, ValueError, json.JSONDecodeError):
            # The original raw record remains available; no values are fabricated.
            continue
    connection.execute("""
        UPDATE alerts SET processing_status = 'processed'
         WHERE processing_status = 'new'
           AND EXISTS (SELECT 1 FROM incidents WHERE incidents.alert_id = alerts.id)
    """)


def get_db_connection():
    """Return a database connection with row names and foreign keys enabled."""
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.create_function("cdss_event_epoch", 1, epoch_seconds, deterministic=True)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _create_alerts_table(connection):
    connection.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wazuh_alert_id TEXT UNIQUE,
            event_timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_description TEXT,
            rule_level INTEGER CHECK (rule_level BETWEEN 0 AND 16),
            agent_id TEXT,
            agent_name TEXT,
            agent_ip TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            mitre_id TEXT,
            wazuh_mitre_ids TEXT NOT NULL DEFAULT '[]',
            rule_groups TEXT NOT NULL DEFAULT '[]',
            username TEXT,
            raw_alert TEXT NOT NULL,
            processing_status TEXT NOT NULL DEFAULT 'new'
                CHECK (processing_status IN ('new', 'processed', 'failed')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (mitre_id) REFERENCES mitre_techniques(technique_id)
                ON UPDATE CASCADE ON DELETE SET NULL
        )
    """)


def _migrate_legacy_alerts(connection):
    """Keep alerts from the original starter table if it already exists."""
    existing_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
    }
    required_columns = {
        "wazuh_alert_id", "event_timestamp", "rule_level", "agent_id",
        "agent_ip", "destination_ip", "raw_alert", "processing_status",
        "created_at",
    }

    if not existing_columns or required_columns.issubset(existing_columns):
        return

    # Prevent SQLite from rewriting existing incident foreign keys to the
    # temporary table name while the alert table is rebuilt.
    connection.execute("PRAGMA legacy_alter_table = ON")
    connection.execute("ALTER TABLE alerts RENAME TO alerts_legacy")
    _create_alerts_table(connection)
    connection.execute("""
        INSERT INTO alerts (
            id, event_timestamp, rule_id, rule_description, rule_level,
            agent_name, source_ip, mitre_id, raw_alert, processing_status
        )
        SELECT
            id,
            COALESCE(timestamp, CURRENT_TIMESTAMP),
            COALESCE(rule_id, 'unknown'),
            rule_description,
            severity,
            agent_name,
            source_ip,
            mitre_id,
            'Migrated from the original CDSS alert table.',
            CASE WHEN decision IS NULL THEN 'new' ELSE 'processed' END
        FROM alerts_legacy
    """)
    connection.execute("DROP TABLE alerts_legacy")
    connection.execute("PRAGMA legacy_alter_table = OFF")


def _repair_incident_alert_foreign_key(connection):
    """Repair databases created by the earlier legacy-alert migration."""
    targets = {
        row["table"] for row in connection.execute("PRAGMA foreign_key_list(incidents)")
    }
    if "alerts_legacy" not in targets:
        return

    connection.execute("PRAGMA legacy_alter_table = ON")
    connection.execute("ALTER TABLE incidents RENAME TO incidents_broken_fk")
    connection.execute("""
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            technique_id TEXT,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
            severity_label TEXT CHECK (severity_label IN ('low', 'medium', 'high', 'critical')),
            detected_at TEXT NOT NULL,
            summary TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            priority TEXT,
            decision_reason TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
                ON UPDATE CASCADE ON DELETE RESTRICT,
            FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
                ON UPDATE CASCADE ON DELETE SET NULL
        )
    """)
    connection.execute("""
        INSERT INTO incidents
            (id, alert_id, technique_id, title, status, severity_label,
             detected_at, summary, created_at, updated_at, priority, decision_reason)
        SELECT id, alert_id, technique_id, title, status, severity_label,
               detected_at, summary, created_at, updated_at, priority, decision_reason
        FROM incidents_broken_fk
    """)
    connection.execute("DROP TABLE incidents_broken_fk")
    connection.execute("PRAGMA legacy_alter_table = OFF")


def _repair_risk_score_incident_foreign_key(connection):
    targets = {
        row["table"] for row in connection.execute("PRAGMA foreign_key_list(risk_scores)")
    }
    if "incidents_broken_fk" not in targets:
        return

    connection.execute("ALTER TABLE risk_scores RENAME TO risk_scores_broken_fk")
    connection.execute("""
        CREATE TABLE risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            rule_level_score REAL NOT NULL CHECK (rule_level_score BETWEEN 0 AND 10),
            technique_risk_score REAL NOT NULL CHECK (technique_risk_score BETWEEN 0 AND 10),
            frequency_score REAL NOT NULL CHECK (frequency_score BETWEEN 0 AND 10),
            final_risk_score REAL NOT NULL CHECK (final_risk_score BETWEEN 0 AND 10),
            calculation_details TEXT,
            calculated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
    """)
    connection.execute("""
        INSERT INTO risk_scores
        SELECT * FROM risk_scores_broken_fk
    """)
    connection.execute("DROP TABLE risk_scores_broken_fk")


def initialize_database():
    """Create the CDSS schema. Running this more than once is safe."""
    connection = get_db_connection()
    try:
        with connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS reference_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL UNIQUE,
                    source_url TEXT,
                    purpose TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS mitre_techniques (
                    technique_id TEXT PRIMARY KEY,
                    technique_name TEXT NOT NULL,
                    tactic TEXT,
                    description TEXT,
                    source_id INTEGER,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_id) REFERENCES reference_sources(id)
                        ON UPDATE CASCADE ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS knowledge_base (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique_id TEXT NOT NULL UNIQUE,
                    base_risk_score INTEGER NOT NULL CHECK (base_risk_score BETWEEN 1 AND 10),
                    d3fend_technique TEXT,
                    nist_ir_guidance TEXT,
                    cis_control TEXT,
                    source_id INTEGER,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
                        ON UPDATE CASCADE ON DELETE CASCADE,
                    FOREIGN KEY (source_id) REFERENCES reference_sources(id)
                        ON UPDATE CASCADE ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    knowledge_base_id INTEGER NOT NULL,
                    action_text TEXT NOT NULL,
                    response_phase TEXT,
                    minimum_risk_score REAL NOT NULL DEFAULT 1 CHECK (minimum_risk_score BETWEEN 1 AND 10),
                    maximum_risk_score REAL NOT NULL DEFAULT 10 CHECK (maximum_risk_score BETWEEN 1 AND 10),
                    priority INTEGER NOT NULL DEFAULT 1 CHECK (priority >= 1),
                    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CHECK (minimum_risk_score <= maximum_risk_score),
                    FOREIGN KEY (knowledge_base_id) REFERENCES knowledge_base(id)
                        ON UPDATE CASCADE ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL,
                    technique_id TEXT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
                    severity_label TEXT CHECK (severity_label IN ('low', 'medium', 'high', 'critical')),
                    detected_at TEXT NOT NULL,
                    summary TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id)
                        ON UPDATE CASCADE ON DELETE RESTRICT,
                    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
                        ON UPDATE CASCADE ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS risk_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    rule_level_score REAL NOT NULL CHECK (rule_level_score BETWEEN 0 AND 10),
                    technique_risk_score REAL NOT NULL CHECK (technique_risk_score BETWEEN 0 AND 10),
                    frequency_score REAL NOT NULL CHECK (frequency_score BETWEEN 0 AND 10),
                    final_risk_score REAL NOT NULL CHECK (final_risk_score BETWEEN 0 AND 10),
                    calculation_details TEXT,
                    calculated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                        ON UPDATE CASCADE ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS incident_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    action_text TEXT NOT NULL,
                    response_phase TEXT NOT NULL,
                    priority INTEGER NOT NULL CHECK (priority BETWEEN 1 AND 10),
                    framework TEXT NOT NULL,
                    control_reference TEXT,
                    rationale TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (incident_id, action_text),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                        ON UPDATE CASCADE ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'analyst')),
                    is_active INTEGER NOT NULL DEFAULT 1
                        CHECK (is_active IN (0, 1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TEXT
                );

                CREATE TABLE IF NOT EXISTS system_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER,
                    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS siem_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    connector_type TEXT NOT NULL DEFAULT 'wazuh_indexer',
                    base_url TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    index_pattern TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB,
                    verify_tls INTEGER NOT NULL DEFAULT 1 CHECK (verify_tls IN (0, 1)),
                    ca_certificate_path TEXT,
                    is_enabled INTEGER NOT NULL DEFAULT 0 CHECK (is_enabled IN (0, 1)),
                    status TEXT NOT NULL DEFAULT 'not_tested',
                    last_success_at TEXT,
                    last_error TEXT,
                    response_time_ms INTEGER,
                    cluster_health TEXT,
                    last_alert_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER,
                    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS connector_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_id INTEGER,
                    actor_user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES siem_connections(id) ON DELETE SET NULL,
                    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
                );
            """)
            alert_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts'"
            ).fetchone()
            if alert_exists:
                _migrate_legacy_alerts(connection)
            else:
                _create_alerts_table(connection)

            _repair_incident_alert_foreign_key(connection)
            _repair_risk_score_incident_foreign_key(connection)

            incident_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(incidents)")
            }
            if "priority" not in incident_columns:
                connection.execute("ALTER TABLE incidents ADD COLUMN priority TEXT")
            if "decision_reason" not in incident_columns:
                connection.execute("ALTER TABLE incidents ADD COLUMN decision_reason TEXT")
            for column, definition in (
                ("classification_source", "TEXT NOT NULL DEFAULT 'UNCLASSIFIED'"),
                ("classification_label", "TEXT NOT NULL DEFAULT 'Unclassified Security Event'"),
                ("risk_basis", "TEXT NOT NULL DEFAULT 'WAZUH_ONLY'"),
                ("engine_version", "TEXT NOT NULL DEFAULT '2.0'"),
            ):
                if column not in incident_columns:
                    connection.execute(f"ALTER TABLE incidents ADD COLUMN {column} {definition}")

            alert_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
            }
            if "rule_groups" not in alert_columns:
                connection.execute("ALTER TABLE alerts ADD COLUMN rule_groups TEXT NOT NULL DEFAULT '[]'")
            if "username" not in alert_columns:
                connection.execute("ALTER TABLE alerts ADD COLUMN username TEXT")

            _ensure_asset_schema(connection)
            _ensure_phase2_alert_schema(connection)

            connection.executescript("""
                CREATE TABLE IF NOT EXISTS incident_mitre_techniques (
                    incident_id INTEGER NOT NULL,
                    technique_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL DEFAULT 0 CHECK (ordinal >= 0),
                    PRIMARY KEY (incident_id, technique_id),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
                        ON UPDATE CASCADE ON DELETE RESTRICT
                );

                CREATE TABLE IF NOT EXISTS knowledge_provenance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    knowledge_base_id INTEGER NOT NULL,
                    source_framework TEXT NOT NULL,
                    source_reference TEXT,
                    source_url TEXT,
                    source_version TEXT,
                    mapping_type TEXT NOT NULL CHECK (mapping_type IN
                        ('official_direct', 'official_cross_mapping', 'project_defined', 'unverified')),
                    verified_status INTEGER NOT NULL DEFAULT 0 CHECK (verified_status IN (0, 1)),
                    last_reviewed TEXT,
                    notes TEXT,
                    UNIQUE (knowledge_base_id, source_framework, source_reference, mapping_type),
                    FOREIGN KEY (knowledge_base_id) REFERENCES knowledge_base(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS ingestion_cursors (
                    connection_id INTEGER PRIMARY KEY,
                    event_timestamp TEXT,
                    document_id TEXT,
                    sort_values_json TEXT CHECK(sort_values_json IS NULL OR json_valid(sort_values_json)),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (connection_id) REFERENCES siem_connections(id) ON DELETE CASCADE
                );
            """)
            cursor_columns = {row['name'] for row in connection.execute(
                'PRAGMA table_info(ingestion_cursors)')}
            if 'sort_values_json' not in cursor_columns:
                connection.execute('''ALTER TABLE ingestion_cursors ADD COLUMN sort_values_json TEXT
                    CHECK(sort_values_json IS NULL OR json_valid(sort_values_json))''')
            connection.execute("""
                INSERT OR IGNORE INTO incident_mitre_techniques
                    (incident_id, technique_id, ordinal)
                SELECT id, technique_id, 0 FROM incidents WHERE technique_id IS NOT NULL
            """)
            connection.execute("""
                UPDATE incidents
                SET classification_source = 'MITRE',
                    classification_label = technique_id,
                    risk_basis = 'WAZUH_PLUS_MITRE'
                WHERE technique_id IS NOT NULL AND classification_source = 'UNCLASSIFIED'
            """)
            connection.execute("""
                UPDATE incidents
                SET decision_reason = REPLACE(
                    decision_reason, 'MITRE technique risk', 'CDSS Technique Risk Weight'
                )
                WHERE decision_reason LIKE '%MITRE technique risk%'
            """)
            connection.execute("""
                UPDATE risk_scores
                SET calculation_details = REPLACE(
                    calculation_details, 'MITRE technique base risk', 'CDSS Technique Risk Weight'
                )
                WHERE calculation_details LIKE '%MITRE technique base risk%'
            """)

            from app.database.phase3 import migrate_mitre_provenance
            migrate_mitre_provenance(connection)
            from app.database.phase4 import migrate_incident_alerts
            migrate_incident_alerts(connection)
            from app.database.architecture import migrate_group_cases
            migrate_group_cases(connection)
            from app.database.phase5 import migrate_investigations
            migrate_investigations(connection)
            from app.database.archive_evidence import migrate_archive_evidence
            migrate_archive_evidence(connection)
            from app.database.phase6 import migrate_risk_assessments
            migrate_risk_assessments(connection)
            from app.database.phase7 import migrate_contextual_guidance
            migrate_contextual_guidance(connection)

            user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
            if "theme" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'system'")
            if "auth_version" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1")
            connection.execute("INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('session_timeout_minutes', '60')")
            connection.execute("INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('default_theme', 'navy')")
            for setting_key, setting_value in (
                ("poll_interval_seconds", "30"),
                ("poll_batch_size", "100"),
                ("minimum_rule_level", "5"),
                ("correlation_threshold", "3"),
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES (?, ?)",
                    (setting_key, setting_value),
                )

            connection.executescript("""
                CREATE INDEX IF NOT EXISTS idx_alerts_event_timestamp ON alerts(event_timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_mitre_id ON alerts(mitre_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_alert_id ON incidents(alert_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_risk_scores_incident_id ON risk_scores(incident_id);
                CREATE INDEX IF NOT EXISTS idx_recommendations_knowledge_base_id
                    ON recommendations(knowledge_base_id);
                CREATE INDEX IF NOT EXISTS idx_incident_recommendations_incident_id
                    ON incident_recommendations(incident_id);
                CREATE INDEX IF NOT EXISTS idx_incident_mitre_technique
                    ON incident_mitre_techniques(technique_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_frequency_context
                    ON alerts(rule_id, agent_id, source_ip, username, event_timestamp);
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """)
    finally:
        connection.close()
