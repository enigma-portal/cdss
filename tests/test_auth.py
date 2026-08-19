"""End-to-end tests for local CDSS access control."""

from pathlib import Path
import tempfile
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


if __name__ == "__main__":
    unittest.main()
