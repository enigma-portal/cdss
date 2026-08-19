"""Smoke test for the read-only CDSS dashboard."""

import unittest

from run import app


class DashboardTests(unittest.TestCase):
    def test_dashboard_loads(self):
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security incidents", response.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_dashboard_limits_invalid_filter_and_has_detail_route(self):
        client = app.test_client()
        response = client.get("/?severity=invalid&page=not-a-number&q=" + "x" * 500)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get("/incidents/999999").status_code, 404)


if __name__ == "__main__":
    unittest.main()
