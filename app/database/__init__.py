import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE = BASE_DIR / "data" / "cdss.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule_id TEXT,
            rule_description TEXT,
            severity INTEGER,
            agent_name TEXT,
            source_ip TEXT,
            mitre_id TEXT,
            risk_score REAL,
            decision TEXT,
            recommendation TEXT
        )
    """)

    connection.commit()
    connection.close()