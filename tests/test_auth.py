"""End-to-end tests for local CDSS access control."""

from pathlib import Path
import tempfile
import time
import unittest

import app.database as database
from app.database import get_db_connection, initialize_database
from run import app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.original_database = database.DATABASE
        self.directory = tempfile.TemporaryDirectory()
        database.DATABASE = Path(self.directory.name) / "auth-test.db"
        initialize_database()
        self.client = app.test_client()

    def tearDown(self):
        database.DATABASE = self.original_database
        self.directory.cleanup()

    def _csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def _create_admin(self):
        self.client.get("/setup")
        return self.client.post("/setup", data={
            "csrf_token": self._csrf(), "username": "admin-test",
            "password": "StrongTesting123", "confirmation": "StrongTesting123",
        })

    def test_first_admin_login_logout_and_password_hash(self):
        response = self._create_admin()
        self.assertEqual(response.status_code, 302)
        connection = get_db_connection()
        row = connection.execute(
            "SELECT username, password_hash FROM users WHERE username = ?", ("admin-test",)
        ).fetchone()
        connection.close()
        self.assertTrue(row["password_hash"].startswith("scrypt:"))
        self.assertNotIn("StrongTesting123", row["password_hash"])

        logout = self.client.post("/logout", data={"csrf_token": self._csrf()})
        self.assertEqual(logout.status_code, 302)
        self.client.get("/login")
        login = self.client.post("/login", data={
            "csrf_token": self._csrf(), "username": "admin-test",
            "password": "StrongTesting123",
        })
        self.assertEqual(login.status_code, 302)

    def test_admin_creates_analyst_account(self):
        self._create_admin()
        self.client.get("/admin/users")
        response = self.client.post("/admin/users", data={
            "csrf_token": self._csrf(), "username": "soc-analyst",
            "password": "AnalystSecure123", "role": "analyst",
        })
        self.assertEqual(response.status_code, 200)
        connection = get_db_connection()
        role = connection.execute(
            "SELECT role FROM users WHERE username = ?", ("soc-analyst",)
        ).fetchone()["role"]
        connection.close()
        self.assertEqual(role, "analyst")

    def test_user_changes_own_username_with_current_password(self):
        self._create_admin()
        self.client.get("/profile")
        response = self.client.post("/profile", data={
            "csrf_token": self._csrf(), "action": "username",
            "username": "renamed-admin", "current_password": "StrongTesting123",
        })
        self.assertEqual(response.status_code, 302)
        connection = get_db_connection()
        exists = connection.execute(
            "SELECT 1 FROM users WHERE username = ?", ("renamed-admin",)
        ).fetchone()
        connection.close()
        self.assertIsNotNone(exists)

    def test_admin_renames_user_and_resets_password(self):
        self._create_admin()
        self.client.get("/admin/users")
        self.client.post("/admin/users", data={
            "csrf_token": self._csrf(), "username": "soc-analyst",
            "password": "AnalystSecure123", "role": "analyst",
        })
        connection = get_db_connection()
        user_id = connection.execute(
            "SELECT id FROM users WHERE username = ?", ("soc-analyst",)
        ).fetchone()["id"]
        connection.close()
        self.client.get(f"/admin/users/{user_id}/edit")
        response = self.client.post(f"/admin/users/{user_id}/edit", data={
            "csrf_token": self._csrf(), "username": "tier1-analyst",
            "role": "analyst", "password": "ResetSecure456",
        })
        self.assertEqual(response.status_code, 302)
        connection = get_db_connection()
        renamed = connection.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()["username"]
        connection.close()
        self.assertEqual(renamed, "tier1-analyst")

    def test_admin_updates_audited_security_settings(self):
        self._create_admin()
        self.client.get("/admin/security-settings")
        response = self.client.post("/admin/security-settings", data={
            "csrf_token": self._csrf(), "session_timeout_minutes": "30",
            "default_theme": "high-contrast",
        })
        self.assertEqual(response.status_code, 302)
        connection = get_db_connection()
        row = connection.execute("SELECT setting_value, updated_by FROM system_settings WHERE setting_key = 'session_timeout_minutes'").fetchone()
        connection.close()
        self.assertEqual(row["setting_value"], "30")
        self.assertIsNotNone(row["updated_by"])

    def test_user_theme_is_saved_and_applied(self):
        self._create_admin()
        self.client.get("/profile")
        response = self.client.post("/profile", data={
            "csrf_token": self._csrf(), "action": "theme", "theme": "light",
        })
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/profile")
        self.assertIn(b'class="theme-light"', page.data)

    def test_inactive_session_expires_server_side(self):
        self._create_admin()
        with self.client.session_transaction() as session:
            session["last_activity"] = int(time.time()) - 4000
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login?expired=1", response.headers["Location"])

    def test_auth_version_change_invalidates_existing_session(self):
        self._create_admin()
        connection = get_db_connection()
        with connection:
            connection.execute("UPDATE users SET auth_version = auth_version + 1 WHERE username = 'admin-test'")
        connection.close()
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
