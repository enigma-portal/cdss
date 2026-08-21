"""Smoke test for the read-only CDSS dashboard."""

import unittest
from werkzeug.security import generate_password_hash

from run import app
from app.database import get_db_connection


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.alert_ids = []
        self.incident_ids = []
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
            for incident_id in self.incident_ids:
                connection.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            for alert_id in self.alert_ids:
                connection.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            connection.execute("DELETE FROM users WHERE id = ?", (self.user_id,))
        connection.close()

    def add_incident(self, label, title, sequence):
        connection = get_db_connection()
        with connection:
            alert = connection.execute("""
                INSERT INTO alerts
                    (wazuh_alert_id, event_timestamp, rule_id, rule_description,
                     rule_level, agent_name, raw_alert, processing_status)
                VALUES (?, '2026-08-21T12:00:00Z', ?, ?, 5,
                        'test-endpoint', '{}', 'processed')
            """, (f"dashboard-filter-{sequence}", str(800000 + sequence), title))
            incident = connection.execute("""
                INSERT INTO incidents
                    (alert_id, title, status, severity_label, detected_at, priority)
                VALUES (?, ?, 'open', ?, '2026-08-21T12:00:00Z', ?)
            """, (alert.lastrowid, title, label,
                    {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}[label]))
        connection.close()
        self.alert_ids.append(alert.lastrowid)
        self.incident_ids.append(incident.lastrowid)
        return incident.lastrowid

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
        self.assertIn(b"view=actionable", response.data)
        self.assertIn(b"severity=critical", response.data)
        self.assertGreaterEqual(response.data.count(b'class="help-tip'), 9)
        incidents = self.authenticated_client().get("/incidents")
        self.assertEqual(incidents.status_code, 200)
        self.assertIn(b"Security incidents", incidents.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_dashboard_limits_invalid_filter_and_has_detail_route(self):
        client = self.authenticated_client()
        response = client.get("/incidents?severity=invalid&page=not-a-number&q=" + "x" * 500)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get("/incidents/999999").status_code, 404)

    def test_actionable_dashboard_link_filters_incidents(self):
        self.add_incident("critical", "FILTER-CRITICAL", 1)
        self.add_incident("high", "FILTER-HIGH", 2)
        self.add_incident("low", "FILTER-LOW", 3)
        response = self.authenticated_client().get("/incidents?view=actionable")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Actionable: High + Critical", response.data)
        self.assertIn(b"FILTER-CRITICAL", response.data)
        self.assertIn(b"FILTER-HIGH", response.data)
        self.assertNotIn(b"FILTER-LOW", response.data)
        self.assertNotIn(b'<span class="badge low">', response.data)

    def test_critical_filter_never_includes_lower_severity(self):
        self.add_incident("critical", "ONLY-CRITICAL", 11)
        self.add_incident("high", "NOT-HIGH", 12)
        self.add_incident("low", "NOT-LOW", 13)
        response = self.authenticated_client().get("/incidents?severity=critical")
        self.assertIn(b"Critical only", response.data)
        self.assertIn(b"ONLY-CRITICAL", response.data)
        self.assertNotIn(b"NOT-HIGH", response.data)
        self.assertNotIn(b"NOT-LOW", response.data)

    def test_direct_page_jump_and_out_of_range_clamp(self):
        for sequence in range(1000, 1125):
            self.add_incident("low", f"PAGE-{sequence}", sequence)
        client = self.authenticated_client()
        page_seven = client.get("/incidents?page=7&severity=low")
        self.assertEqual(page_seven.status_code, 200)
        self.assertIn(b'aria-current="page">7</span>', page_seven.data)
        self.assertIn(b'id="page-jump"', page_seven.data)
        self.assertIn(b'name="severity" value="low"', page_seven.data)
        clamped = client.get("/incidents?page=999999&severity=low")
        self.assertIn(b'aria-current="page">7</span>', clamped.data)

    def test_dashboard_requires_login(self):
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_logout_requires_csrf(self):
        client = self.authenticated_client()
        self.assertEqual(client.post("/logout").status_code, 400)


if __name__ == "__main__":
    unittest.main()
