"""End-to-end local test for the CDSS alert-to-decision pipeline."""

from pathlib import Path
import tempfile
import unittest

import app.database as database
from app.database.seed import seed_knowledge_base
from app.services.incident_processor import process_alert


SAMPLE_ALERT = {
    "id": "1776000000.12345",
    "timestamp": "2026-08-12T12:00:00+00:00",
    "rule": {
        "id": "5710",
        "description": "Multiple Windows authentication failures.",
        "level": 10,
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "001", "name": "workstation-01", "ip": "10.0.0.12"},
}


class IncidentProcessorTests(unittest.TestCase):
    def test_successful_login_uses_verification_not_compromise_assumption(self):
        alert = dict(SAMPLE_ALERT)
        alert["id"] = "normal-login"
        alert["rule"] = {"id": "60106", "level": 3,
                         "description": "Windows logon success.",
                         "mitre": {"id": ["T1078"]}}
        original_database = database.DATABASE
        with tempfile.TemporaryDirectory() as directory:
            database.DATABASE = Path(directory) / "cdss-test.db"
            try:
                seed_knowledge_base()
                result = process_alert(alert)
            finally:
                database.DATABASE = original_database
        self.assertEqual(result["severity"], "low")
        self.assertIn("Confirm the login", result["recommendations"][0]["action_text"])
        self.assertNotIn("compromised", result["recommendations"][0]["action_text"])

    def test_event_without_mitre_gets_framework_recommendations(self):
        alert = dict(SAMPLE_ALERT)
        alert["id"] = "no-mitre-alert"
        alert["rule"] = {
            "id": "19007", "level": 7,
            "description": "CIS benchmark configuration policy failed.",
        }
        original_database = database.DATABASE
        with tempfile.TemporaryDirectory() as directory:
            database.DATABASE = Path(directory) / "cdss-test.db"
            try:
                seed_knowledge_base()
                result = process_alert(alert)
            finally:
                database.DATABASE = original_database
        self.assertEqual(len(result["recommendations"]), 3)
        self.assertEqual(result["recommendations"][0]["framework"], "CIS Controls v8")

    def test_creates_one_scored_incident_and_returns_recommendations(self):
        original_database = database.DATABASE
        with tempfile.TemporaryDirectory() as directory:
            database.DATABASE = Path(directory) / "cdss-test.db"
            try:
                seed_knowledge_base()
                result = process_alert(SAMPLE_ALERT)
                duplicate = process_alert(SAMPLE_ALERT)
            finally:
                database.DATABASE = original_database

        self.assertTrue(result["created"])
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["priority"], "P2")
        self.assertIn("CDSS decision-support score", result["explanation"])
        self.assertEqual(len(result["recommendations"]), 2)
        self.assertEqual(result["recommendations"][0]["framework"], "MITRE D3FEND + NIST/CIS")
        self.assertIn("Authentication Monitoring", result["recommendations"][0]["control_reference"])
        self.assertFalse(duplicate["created"])
        self.assertEqual(duplicate["incident_id"], result["incident_id"])


if __name__ == "__main__":
    unittest.main()
