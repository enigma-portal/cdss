"""Tests for CDSS risk normalization and final decision bands."""

import unittest

from app.risk_engine.scoring import calculate_risk, severity_for_risk


class RiskScoringTests(unittest.TestCase):
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
