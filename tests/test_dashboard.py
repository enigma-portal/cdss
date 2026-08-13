"""Smoke test for the read-only CDSS dashboard."""

import unittest

from run import app


class DashboardTests(unittest.TestCase):
    def test_dashboard_loads(self):
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Processed incidents", response.data)


if __name__ == "__main__":
    unittest.main()
