"""Security and authorization tests for vendor-neutral SIEM administration."""

from pathlib import Path
import tempfile
import unittest

import app.database as database
import app.services.secret_store as secret_store
from app.database import get_db_connection, initialize_database
from app.services.secret_store import unprotect_secret
from run import app


class SiemConnectionTests(unittest.TestCase):
    def setUp(self):
        self.original_database = database.DATABASE
        self.original_key = secret_store.KEY_FILE
        self.directory = tempfile.TemporaryDirectory()
        database.DATABASE = Path(self.directory.name) / "siem-test.db"
        secret_store.KEY_FILE = Path(self.directory.name) / "connector.key"
        initialize_database()
        self.client = app.test_client()
        self.client.get("/setup")
        with self.client.session_transaction() as current:
            token = current["csrf_token"]
        self.client.post("/setup", data={"csrf_token": token, "username": "siem-admin",
            "password": "StrongTesting123", "confirmation": "StrongTesting123"})

    def tearDown(self):
        database.DATABASE = self.original_database
        secret_store.KEY_FILE = self.original_key
        self.directory.cleanup()

    def csrf(self):
        with self.client.session_transaction() as current:
            return current["csrf_token"]

    def test_admin_saves_encrypted_disabled_connection(self):
        response = self.client.post("/admin/siem-connections", data={
            "csrf_token": self.csrf(), "name": "Lab SIEM", "connector_type": "wazuh_indexer",
            "base_url": "https://192.0.2.10", "port": "9200",
            "index_pattern": "wazuh-alerts-*", "username": "reader",
            "password": "NeverStorePlaintext", "verify_tls": "1",
        })
        self.assertEqual(response.status_code, 302)
        connection = get_db_connection()
        row = connection.execute("SELECT encrypted_password, is_enabled FROM siem_connections").fetchone()
        audit = connection.execute("SELECT action, details FROM connector_audit").fetchone()
        connection.close()
        self.assertNotIn(b"NeverStorePlaintext", bytes(row["encrypted_password"]))
        self.assertEqual(unprotect_secret(row["encrypted_password"]), "NeverStorePlaintext")
        self.assertEqual(row["is_enabled"], 0)
        self.assertEqual(audit["action"], "created")
        self.assertNotIn("NeverStorePlaintext", audit["details"])
        page = self.client.get("/admin/siem-connections")
        self.assertIn(b"https://0.0.0.0:9200 (address hidden)", page.data)
        self.assertNotIn(b"192.0.2.10", page.data)

        edit = self.client.post("/admin/siem-connections/1/edit", data={
            "csrf_token": self.csrf(), "action": "details", "name": "Renamed SIEM",
            "base_url": "https://192.0.2.11", "port": "9200",
            "index_pattern": "security-*", "username": "readonly", "verify_tls": "1",
        })
        self.assertEqual(edit.status_code, 302)
        connection = get_db_connection()
        updated = connection.execute("SELECT name, base_url, is_enabled, status FROM siem_connections WHERE id = 1").fetchone()
        connection.close()
        self.assertEqual(updated["name"], "Renamed SIEM")
        self.assertEqual(updated["status"], "not_tested")

        deleted = self.client.post("/admin/siem-connections/1/delete", data={
            "csrf_token": self.csrf(), "confirm_name": "Renamed SIEM",
        })
        self.assertEqual(deleted.status_code, 302)
        connection = get_db_connection()
        remaining = connection.execute("SELECT COUNT(*) AS total FROM siem_connections").fetchone()["total"]
        connection.close()
        self.assertEqual(remaining, 0)

    def test_rejects_non_https_endpoint(self):
        response = self.client.post("/admin/siem-connections", data={
            "csrf_token": self.csrf(), "name": "Unsafe SIEM", "connector_type": "wazuh_indexer",
            "base_url": "http://169.254.169.254", "port": "80", "index_pattern": "alerts-*",
            "username": "reader", "password": "NotSavedHere123",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Use an HTTPS URL", response.data)
        connection = get_db_connection()
        total = connection.execute("SELECT COUNT(*) AS total FROM siem_connections").fetchone()["total"]
        connection.close()
        self.assertEqual(total, 0)


if __name__ == "__main__":
    unittest.main()
