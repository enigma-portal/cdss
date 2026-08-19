"""SQLite connection and schema setup for the CDSS project."""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE = BASE_DIR / "data" / "cdss.db"


def get_db_connection():
    """Return a database connection with row names and foreign keys enabled."""
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
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
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """)
    finally:
        connection.close()
