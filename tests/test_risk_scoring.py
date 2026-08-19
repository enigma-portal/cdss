"""Tests for CDSS risk normalization and final decision bands."""

import unittest

from app.risk_engine.scoring import calculate_risk, severity_for_risk
from app.services.alert_parser import parse_alert
from app.services.incident_processor import _contextual_inputs


class RiskScoringTests(unittest.TestCase):
    def test_routine_success_does_not_become_high_from_technique_and_volume(self):
        parsed = parse_alert({
            "id": "login", "timestamp": "2026-08-19T10:00:00Z",
            "rule": {"id": "60106", "level": 3,
                     "description": "Windows logon success.",
                     "mitre": {"id": ["T1078"]}},
        })
        technique, count, reason = _contextual_inputs(10, parsed, 100)
        risk = calculate_risk(parsed.rule_level, technique, count)
        self.assertEqual(technique, 3.0)
        self.assertEqual(count, 1)
        self.assertEqual(severity_for_risk(risk.final_risk_score), "low")
        self.assertIn("not malicious proof", reason)

    def test_calculates_weighted_risk(self):
        risk = calculate_risk(rule_level=16, technique_risk_score=10, event_count=11)
        self.assertEqual(risk.final_risk_score, 10.0)
        self.assertEqual(severity_for_risk(risk.final_risk_score), "critical")

    def test_first_event_has_low_frequency_factor(self):
        risk = calculate_risk(rule_level=8, technique_risk_score=5, event_count=1)
        self.assertEqual(risk.frequency_score, 1.0)
        self.assertEqual(risk.final_risk_score, 4.2)


if __name__ == "__main__":
    unittest.main()
