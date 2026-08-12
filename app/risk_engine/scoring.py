"""Transparent, adjustable risk scoring for CDSS incidents."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    rule_level_score: float
    technique_risk_score: float
    frequency_score: float
    final_risk_score: float


def normalize_rule_level(rule_level):
    """Convert Wazuh's 0–16 rule level into the CDSS 0–10 scale."""
    if rule_level is None:
        return 0.0
    return round(max(0, min(int(rule_level), 16)) / 16 * 10, 2)


def normalize_frequency(event_count):
    """Convert same-rule events in the last hour into a 1–10 score."""
    if event_count <= 1:
        return 1.0
    if event_count <= 3:
        return 3.0
    if event_count <= 6:
        return 5.0
    if event_count <= 10:
        return 7.0
    return 10.0


def calculate_risk(rule_level, technique_risk_score, event_count):
    """Combine normalized detection, technique, and frequency indicators."""
    rule_score = normalize_rule_level(rule_level)
    technique_score = max(0.0, min(float(technique_risk_score), 10.0))
    frequency_score = normalize_frequency(event_count)
    final_score = round(
        rule_score * 0.4 + technique_score * 0.4 + frequency_score * 0.2, 2
    )
    return RiskResult(rule_score, technique_score, frequency_score, final_score)


def severity_for_risk(risk_score):
    if risk_score >= 8:
        return "critical"
    if risk_score >= 6:
        return "high"
    if risk_score >= 3:
        return "medium"
    return "low"
