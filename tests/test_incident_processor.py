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
        self.assertEqual(len(result["recommendations"]), 2)
        self.assertFalse(duplicate["created"])
        self.assertEqual(duplicate["incident_id"], result["incident_id"])


if __name__ == "__main__":
    unittest.main()
