"""Tests for the Wazuh alert collector and parser."""

import json
from pathlib import Path
import tempfile
import unittest

from app.services.alert_collector import collect_alerts
from app.services.alert_parser import parse_alert


SAMPLE_ALERT = {
    "id": "1776000000.12345",
    "timestamp": "2026-08-12T12:00:00.000+0000",
    "rule": {
        "id": "5710",
        "description": "Multiple Windows authentication failures.",
        "level": 10,
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "001", "name": "workstation-01", "ip": "10.0.0.12"},
    "data": {"srcip": "203.0.113.8", "dstip": "10.0.0.12"},
}


class AlertPipelineTests(unittest.TestCase):
    def test_collect_and_parse_wazuh_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            alerts_file = Path(directory) / "alerts.json"
            alerts_file.write_text(json.dumps(SAMPLE_ALERT) + "\n", encoding="utf-8")
            alerts = collect_alerts(alerts_file)

        parsed = parse_alert(alerts[0])
        self.assertEqual(parsed.rule_id, "5710")
        self.assertEqual(parsed.rule_level, 10)
        self.assertEqual(parsed.mitre_ids, ("T1110",))
        self.assertEqual(parsed.source_ip, "203.0.113.8")
        self.assertEqual(parsed.as_database_record()["mitre_id"], "T1110")


if __name__ == "__main__":
    unittest.main()
