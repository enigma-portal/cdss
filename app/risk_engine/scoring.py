"""Transparent, adjustable risk scoring for CDSS incidents."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    rule_level_score: float
    technique_risk_score: float
    frequency_score: float
    final_risk_score: float
    risk_basis: str


def normalize_rule_level(rule_level):
    """Convert Wazuh's 0–16 rule level into the CDSS 0–10 scale."""
    if rule_level is None:
        return 0.0
    return round(max(0, min(int(rule_level), 16)) / 16 * 10, 2)


def normalize_frequency(event_count, threshold=3):
    """Convert same-rule events in the last hour into a 1–10 score."""
    threshold = max(2, min(int(threshold), 100))
    if event_count < threshold:
        return 1.0
    if event_count <= threshold:
        return 3.0
    if event_count <= threshold * 2:
        return 5.0
    if event_count <= threshold * 3 + 1:
        return 7.0
    return 10.0


def calculate_risk(rule_level, technique_risk_score, event_count, frequency_threshold=3):
    """Calculate mapped or Wazuh-only risk without inventing technique weight."""
    rule_score = normalize_rule_level(rule_level)
    frequency_score = normalize_frequency(event_count, frequency_threshold)
    if technique_risk_score is None:
        technique_score = 0.0
        risk_basis = "WAZUH_ONLY"
        final_score = round(rule_score * 0.8 + frequency_score * 0.2, 2)
    else:
        technique_score = max(0.0, min(float(technique_risk_score), 10.0))
        risk_basis = "WAZUH_PLUS_MITRE"
        final_score = round(
            rule_score * 0.4 + technique_score * 0.4 + frequency_score * 0.2, 2
        )
    return RiskResult(rule_score, technique_score, frequency_score, final_score, risk_basis)


def severity_for_risk(risk_score):
    if risk_score >= 8:
        return "critical"
    if risk_score >= 6:
        return "high"
    if risk_score >= 3:
        return "medium"
    return "low"


def priority_for_risk(risk_score):
    """Translate the CDSS score into an analyst-friendly response priority."""
    if risk_score >= 8:
        return "P1"
    if risk_score >= 6:
        return "P2"
    if risk_score >= 3:
        return "P3"
    return "P4"


def explain_risk(risk):
    """Explain the deterministic calculation without calling it a Wazuh score."""
    if risk.risk_basis == "WAZUH_ONLY":
        return (
            "CDSS decision-support score (WAZUH_ONLY): "
            f"80% normalized SIEM rule level ({risk.rule_level_score:.2f}/10) and "
            f"20% one-hour contextual recurrence ({risk.frequency_score:.2f}/10)."
        )
    return (
        "CDSS decision-support score (WAZUH_PLUS_MITRE): "
        f"40% normalized SIEM rule level ({risk.rule_level_score:.2f}/10), "
        f"40% CDSS Technique Risk Weight ({risk.technique_risk_score:.2f}/10), and "
        f"20% one-hour contextual recurrence ({risk.frequency_score:.2f}/10). "
        "The technique weight is CDSS-defined, not an official MITRE severity score."
    )
