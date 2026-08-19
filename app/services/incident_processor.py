"""Connect parsed Wazuh alerts to CDSS incidents, scoring, and recommendations."""

from datetime import datetime, timedelta, timezone

from app.database import get_db_connection
from app.risk_engine.scoring import (
    calculate_risk, explain_risk, priority_for_risk, severity_for_risk,
)
from app.services.alert_parser import parse_alert
from app.services.recommendation_engine import get_recommendations
from app.services.wazuh_indexer import WazuhIndexerClient


DEFAULT_TECHNIQUE_RISK = 5.0


def _event_window_start(event_timestamp):
    try:
        timestamp = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return (timestamp - timedelta(hours=1)).isoformat()


def _ensure_technique(connection, technique_id):
    if not technique_id:
        return None
    connection.execute("""
        INSERT OR IGNORE INTO mitre_techniques (technique_id, technique_name)
        VALUES (?, ?)
    """, (technique_id, "Technique details awaiting MITRE TAXII synchronization"))
    return technique_id


def _base_technique_risk(connection, technique_id):
    if not technique_id:
        return DEFAULT_TECHNIQUE_RISK
    row = connection.execute(
        "SELECT base_risk_score FROM knowledge_base WHERE technique_id = ?", (technique_id,)
    ).fetchone()
    return row["base_risk_score"] if row else DEFAULT_TECHNIQUE_RISK


def _frequency_count(connection, parsed):
    window_start = _event_window_start(parsed.event_timestamp)
    if not window_start:
        return 1
    row = connection.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE rule_id = ?
          AND COALESCE(agent_id, '') = COALESCE(?, '')
          AND event_timestamp >= ?
    """, (parsed.rule_id, parsed.agent_id, window_start)).fetchone()
    return row["total"] + 1


def process_alert(raw_alert):
    """Store one raw Wazuh alert and return its incident decision result.

    Processing the same Wazuh alert ID more than once is safe; the existing
    incident is returned instead of creating a duplicate.
    """
    parsed = parse_alert(raw_alert)
    technique_id = parsed.mitre_ids[0] if parsed.mitre_ids else None
    connection = get_db_connection()
    try:
        with connection:
            _ensure_technique(connection, technique_id)
            frequency_count = _frequency_count(connection, parsed)
            record = parsed.as_database_record()
            record["mitre_id"] = technique_id
            columns = ", ".join(record)
            placeholders = ", ".join("?" for _ in record)
            cursor = connection.execute(
                f"INSERT OR IGNORE INTO alerts ({columns}) VALUES ({placeholders})",
                tuple(record.values()),
            )
            if cursor.rowcount == 0 and parsed.wazuh_alert_id:
                alert_id = connection.execute(
                    "SELECT id FROM alerts WHERE wazuh_alert_id = ?", (parsed.wazuh_alert_id,)
                ).fetchone()["id"]
                incident = connection.execute(
                    "SELECT id FROM incidents WHERE alert_id = ?", (alert_id,)
                ).fetchone()
                if incident:
                    return {"incident_id": incident["id"], "created": False}
            else:
                alert_id = cursor.lastrowid

            technique_risk = _base_technique_risk(connection, technique_id)
            risk = calculate_risk(parsed.rule_level, technique_risk, frequency_count)
            severity = severity_for_risk(risk.final_risk_score)
            priority = priority_for_risk(risk.final_risk_score)
            explanation = explain_risk(risk)
            title = parsed.rule_description or f"Wazuh rule {parsed.rule_id} incident"
            incident_cursor = connection.execute("""
                INSERT INTO incidents
                    (alert_id, technique_id, title, severity_label, priority,
                     detected_at, summary, decision_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id, technique_id, title, severity, priority,
                parsed.event_timestamp, "Created automatically from a Wazuh Indexer alert.",
                explanation,
            ))
            incident_id = incident_cursor.lastrowid
            connection.execute("""
                INSERT INTO risk_scores
                    (incident_id, rule_level_score, technique_risk_score,
                     frequency_score, final_risk_score, calculation_details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                incident_id, risk.rule_level_score, risk.technique_risk_score,
                risk.frequency_score, risk.final_risk_score,
                "40% Wazuh rule level, 40% MITRE technique base risk, 20% one-hour event frequency.",
            ))
            recommendations = get_recommendations(connection, technique_id, risk.final_risk_score)
            return {
                "incident_id": incident_id,
                "created": True,
                "risk_score": risk.final_risk_score,
                "severity": severity,
                "priority": priority,
                "explanation": explanation,
                "recommendations": [dict(row) for row in recommendations],
            }
    finally:
        connection.close()


def process_indexer_alerts(size=100, since=None, client=None):
    """Fetch a bounded batch from Wazuh Indexer and process each alert."""
    client = client or WazuhIndexerClient.from_environment()
    return [process_alert(alert) for alert in client.fetch_alerts(size=size, since=since)]
