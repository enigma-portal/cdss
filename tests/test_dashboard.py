"""Smoke test for the read-only CDSS dashboard."""

import unittest
from werkzeug.security import generate_password_hash

from run import app
from app.database import get_db_connection


class DashboardTests(unittest.TestCase):
    def setUp(self):
        connection = get_db_connection()
        with connection:
            connection.execute("DELETE FROM users WHERE username = 'test-dashboard-user'")
            cursor = connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                ("test-dashboard-user", generate_password_hash("TestingPass123", method="scrypt")),
            )
            self.user_id = cursor.lastrowid
        connection.close()

    def tearDown(self):
        connection = get_db_connection()
        with connection:
            connection.execute("DELETE FROM users WHERE id = ?", (self.user_id,))
        connection.close()

    def authenticated_client(self):
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = self.user_id
        return client

    def test_dashboard_loads(self):
        response = self.authenticated_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Infrastructure overview", response.data)
        self.assertIn(b"Vulnerability coverage", response.data)
        incidents = self.authenticated_client().get("/incidents")
        self.assertEqual(incidents.status_code, 200)
        self.assertIn(b"Security incidents", incidents.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_dashboard_limits_invalid_filter_and_has_detail_route(self):
        client = self.authenticated_client()
        response = client.get("/incidents?severity=invalid&page=not-a-number&q=" + "x" * 500)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get("/incidents/999999").status_code, 404)

    def test_dashboard_requires_login(self):
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_logout_requires_csrf(self):
        client = self.authenticated_client()
        self.assertEqual(client.post("/logout").status_code, 400)


if __name__ == "__main__":
    unittest.main()
