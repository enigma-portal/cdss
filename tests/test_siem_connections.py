"""Security and authorization tests for vendor-neutral SIEM administration."""

from pathlib import Path
import tempfile
import unittest

import app.database as database
import app.services.secret_store as secret_store
from app.database import get_db_connection, initialize_database
from app.services.secret_store import unprotect_secret
from app.routes.auth import _display_endpoint
from run import app


class SiemConnectionTests(unittest.TestCase):
    def test_admin_connector_endpoint_displays_configured_address(self):
        self.assertEqual(
            _display_endpoint("https://192.0.2.10", 9200),
            "https://192.0.2.10:9200",
        )
    def setUp(self):
        self.original_database = database.DATABASE
        self.original_key = secret_store.KEY_FILE
        self.original_polling_enabled = app.config.get('SIEM_REALTIME_ENABLED', True)
        app.config['SIEM_REALTIME_ENABLED'] = True
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
        app.config['SIEM_REALTIME_ENABLED'] = self.original_polling_enabled
        self.directory.cleanup()

    def csrf(self):
        with self.client.session_transaction() as current:
            return current["csrf_token"]

    def test_banner_and_admin_page_share_collection_health(self):
        connection = get_db_connection()
        with connection:
            connection.execute("""INSERT INTO siem_connections
                (name, base_url, port, index_pattern, username, is_enabled, status)
                VALUES ('Test SIEM', 'https://192.0.2.10', 9200, 'alerts-*', 'reader', 1, 'error')""")
        connection.close()
        cases = (
            (1, 'error', "datetime('now')", 'failed', 'SIEM unavailable'),
            (1, 'connected', "datetime('now')", 'active', 'SIEM alert collection active'),
            (1, 'not_tested', 'NULL', 'unknown', 'SIEM alert collection status unknown'),
            (1, 'connected', "datetime('now', '-10 minutes')", 'stale', 'SIEM alert collection stale'),
            (0, 'connected', "datetime('now')", 'disabled', 'SIEM alert collection disabled'),
        )
        for enabled, status, success_sql, state, label in cases:
            with self.subTest(state=state):
                connection = get_db_connection()
                with connection:
                    connection.execute(
                        f"UPDATE siem_connections SET is_enabled=?, status=?, last_success_at={success_sql}",
                        (enabled, status),
                    )
                connection.close()
                overview = self.client.get('/')
                admin = self.client.get('/admin/siem-connections')
                self.assertEqual(overview.status_code, 200)
                self.assertEqual(admin.status_code, 200)
                for response in (overview, admin):
                    rendered = response.get_data(as_text=True)
                    self.assertIn(f'collection-{state}', rendered)
                    self.assertIn(label, rendered)
                    self.assertNotIn('SIEM monitoring', rendered)
                    self.assertNotIn('Realtime', rendered)
                self.assertIn(f'state-{state}', admin.get_data(as_text=True))
                if state == 'failed':
                    self.assertNotIn('collection-active', overview.get_data(as_text=True))

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
        self.assertIn(b"https://192.0.2.10:9200", page.data)
        self.assertNotIn(b"address hidden", page.data)
        self.assertIn(b"Certificate verification enabled", page.data)
        self.assertNotIn(b"TLS verified", page.data)
        self.assertIn(b"Last reported cluster health", page.data)

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

        page = self.client.get("/admin/siem-connections/1/edit")
        self.assertNotIn(b"Replace password", page.data)
        rejected = self.client.post("/admin/siem-connections/1/edit", data={
            "csrf_token": self.csrf(), "action": "password", "password": "DifferentPassword123",
        })
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"cannot be changed here", rejected.data)

        deleted = self.client.post("/admin/siem-connections/1/delete", data={
            "csrf_token": self.csrf(), "confirm_name": "Renamed SIEM",
        })
        self.assertEqual(deleted.status_code, 302)
        connection = get_db_connection()
        remaining = connection.execute("SELECT COUNT(*) AS total FROM siem_connections").fetchone()["total"]
        connection.close()
        self.assertEqual(remaining, 0)

    def test_connection_test_stores_explicit_utc_and_renders_labelled_time(self):
        from unittest.mock import Mock, patch
        connection=get_db_connection()
        with connection:
            cid=connection.execute("""INSERT INTO siem_connections
                (name,base_url,port,index_pattern,username,encrypted_password)
                VALUES('UTC test','https://192.0.2.10',9200,'wazuh-alerts-*','reader',X'01')""").lastrowid
        connection.close()
        connector=Mock();connector.test_connection.return_value={'status':'green'}
        with (patch('app.routes.auth.create_connector',return_value=connector),
              patch('app.routes.auth._validated_siem_endpoint',return_value=('https://192.0.2.10',9200)),
              patch('app.routes.auth.unprotect_secret',return_value='fixture'),
              patch('app.routes.auth.utc_now_text',return_value='2026-10-15T12:02:00Z')):
            response=self.client.post(f'/admin/siem-connections/{cid}/test',data={'csrf_token':self.csrf()})
        self.assertEqual(response.status_code,302)
        connection=get_db_connection()
        self.assertEqual(connection.execute('SELECT last_success_at FROM siem_connections WHERE id=?',
                                           (cid,)).fetchone()[0],'2026-10-15T12:02:00Z')
        connection.close()
        html=self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertIn('datetime="2026-10-15T12:02:00Z"',html)
        self.assertIn('2026-10-15 12:02:00 UTC',html)

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
