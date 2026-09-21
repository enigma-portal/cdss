"""Phase 1 asset schema, validation, authorization, and exact mapping tests."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from werkzeug.security import generate_password_hash

import app.database as database
from app.database import get_db_connection, initialize_database
from app.services.asset_resolver import backfill_asset_links
from app.services.asset_validation import validate_asset
from app.services.incident_processor import process_alert
from run import app


VALID = {
    "asset_name": "DC <Primary>", "asset_type": "Server", "asset_role": "Domain Controller",
    "os_family": "Windows Server", "os_name": "Windows Server 2022",
    "ip_address": "10.0.0.10", "wazuh_agent_id": "001", "criticality": "critical",
    "is_protected": "1", "description": "Core identity server",
}


class AssetPhaseOneTests(unittest.TestCase):
    def setUp(self):
        self.original = database.DATABASE
        self.directory = tempfile.TemporaryDirectory()
        database.DATABASE = Path(self.directory.name) / "assets.db"
        initialize_database()
        self.client = app.test_client()
        connection = get_db_connection()
        with connection:
            admin = connection.execute(
                "INSERT INTO users(username,password_hash,role) VALUES('admin',?,'admin')",
                (generate_password_hash("StrongPassword123"),),
            ).lastrowid
            analyst = connection.execute(
                "INSERT INTO users(username,password_hash,role) VALUES('analyst',?,'analyst')",
                (generate_password_hash("StrongPassword123"),),
            ).lastrowid
        connection.close()
        self.admin, self.analyst = admin, analyst

    def tearDown(self):
        database.DATABASE = self.original
        self.directory.cleanup()

    def login_as(self, user_id):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id; session["auth_version"] = 1
            session["last_activity"] = 2000000000; session["csrf_token"] = "test-token"

    def create_asset(self, values=None):
        payload = dict(VALID); payload.update(values or {}); payload["csrf_token"] = "test-token"
        return self.client.post("/admin/assets", data=payload, follow_redirects=True)

    def test_admin_crud_required_criticality_and_html_escaping(self):
        self.login_as(self.admin)
        response = self.create_asset()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"DC &lt;Primary&gt;", response.data)
        invalid = self.create_asset({"asset_name": "missing", "criticality": ""})
        self.assertIn(b"Criticality must be explicitly selected", invalid.data)
        connection = get_db_connection(); row = connection.execute("SELECT * FROM assets").fetchone(); connection.close()
        self.assertEqual(row["asset_name"], "DC <Primary>")
        updated = dict(VALID, asset_name="Renamed", criticality="high", csrf_token="test-token")
        response = self.client.post(f"/admin/assets/{row['id']}/edit", data=updated, follow_redirects=True)
        self.assertIn(b"Renamed", response.data)

    def test_non_admin_forbidden(self):
        self.login_as(self.analyst)
        self.assertEqual(self.client.get("/admin/assets").status_code, 403)

    def test_taxonomy_os_dependencies_and_protection(self):
        with self.assertRaises(ValueError):
            validate_asset(dict(VALID, asset_role="Router"))
        with self.assertRaises(ValueError):
            validate_asset(dict(VALID, os_family="macOS", os_name="macOS"))
        cloud = validate_asset(dict(VALID, asset_type="Cloud Asset", asset_role="Object Storage",
                                    os_family="N/A", os_name="N/A", is_protected=""))
        self.assertEqual(cloud["is_protected"], 0)

    def test_nullable_and_unique_non_null_agent_id(self):
        self.login_as(self.admin)
        self.create_asset({"wazuh_agent_id": "", "asset_name": "one"})
        self.create_asset({"wazuh_agent_id": "", "asset_name": "two"})
        self.create_asset({"asset_name": "three", "wazuh_agent_id": "009"})
        response = self.create_asset({"asset_name": "four", "wazuh_agent_id": "009"})
        self.assertIn(b"already assigned", response.data)
        connection = get_db_connection(); count = connection.execute("SELECT COUNT(*) n FROM assets").fetchone()["n"]; connection.close()
        self.assertEqual(count, 3)

    def test_exact_mapping_unmatched_and_incident_inheritance(self):
        connection = get_db_connection()
        with connection:
            asset_id = connection.execute("""INSERT INTO assets(asset_name,asset_type,asset_role,os_family,os_name,wazuh_agent_id,criticality,is_protected)
                VALUES('host','Server','Web Server','Linux','Ubuntu Server','001','high',1)""").lastrowid
        connection.close()
        first = {"id":"mapped","timestamp":"2026-01-01T00:00:00Z","rule":{"id":"1","level":4,"description":"event"},"agent":{"id":"001","name":"wrong-name","ip":"99.1.1.1"}}
        second = {"id":"unmapped","timestamp":"2026-01-01T00:01:00Z","rule":{"id":"2","level":4,"description":"event"},"agent":{"id":"002","name":"host","ip":"10.0.0.10"}}
        process_alert(first); process_alert(second)
        connection = get_db_connection()
        alerts = connection.execute("SELECT wazuh_alert_id,asset_id FROM alerts ORDER BY id").fetchall()
        incidents = connection.execute("SELECT asset_id FROM incidents ORDER BY id").fetchall(); connection.close()
        self.assertEqual(alerts[0]["asset_id"], asset_id); self.assertIsNone(alerts[1]["asset_id"])
        self.assertEqual(incidents[0]["asset_id"], asset_id); self.assertIsNone(incidents[1]["asset_id"])

    def test_historical_exact_backfill_and_foreign_keys(self):
        process_alert({"id":"old","timestamp":"2026-01-01T00:00:00Z","rule":{"id":"1","level":4,"description":"event"},"agent":{"id":"007","name":"x"}})
        connection = get_db_connection()
        with connection:
            asset_id = connection.execute("""INSERT INTO assets(asset_name,asset_type,asset_role,os_family,os_name,wazuh_agent_id,criticality,is_protected)
                VALUES('asset','Other','Other','N/A','N/A','007','low',0)""").lastrowid
            backfill_asset_links(connection, asset_id, "007")
        self.assertEqual(connection.execute("SELECT asset_id FROM alerts").fetchone()[0], asset_id)
        self.assertEqual(connection.execute("SELECT asset_id FROM incidents").fetchone()[0], asset_id)
        with connection:
            connection.execute("DELETE FROM assets WHERE id=?", (asset_id,))
        self.assertIsNone(connection.execute("SELECT asset_id FROM alerts").fetchone()[0])
        self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        connection.close()

    def test_additive_migration_preserves_existing_records(self):
        connection = get_db_connection()
        with connection:
            connection.execute("INSERT INTO alerts(wazuh_alert_id,event_timestamp,rule_id,raw_alert) VALUES('keep','2026-01-01','1','{}')")
            alert_id = connection.execute("SELECT id FROM alerts WHERE wazuh_alert_id='keep'").fetchone()[0]
            connection.execute("INSERT INTO incidents(alert_id,title,detected_at) VALUES(?,'keep','2026-01-01')", (alert_id,))
        connection.close(); initialize_database(); connection = get_db_connection()
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM alerts WHERE wazuh_alert_id='keep'").fetchone()[0], 1)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents WHERE title='keep'").fetchone()[0], 1)
        self.assertIn("asset_id", {r["name"] for r in connection.execute("PRAGMA table_info(alerts)")})
        connection.close()


if __name__ == "__main__":
    unittest.main()
