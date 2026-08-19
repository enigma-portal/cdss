"""Recalculate stored decisions after a reviewed scoring-model change."""

import json

from app.database import get_db_connection
from app.risk_engine.scoring import calculate_risk, explain_risk, priority_for_risk, severity_for_risk
from app.services.alert_parser import parse_alert
from app.services.incident_processor import (
    _base_technique_risk, _contextual_inputs, _event_window_start,
)
from app.services.recommendation_engine import rebuild_recommendations


def main():
    connection = get_db_connection()
    try:
        rows = connection.execute("""
            SELECT incidents.id AS incident_id, incidents.technique_id,
                   alerts.raw_alert, alerts.event_timestamp, alerts.rule_id, alerts.agent_id
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            ORDER BY alerts.event_timestamp, alerts.id
        """).fetchall()
        with connection:
            for row in rows:
                parsed = parse_alert(json.loads(row["raw_alert"]))
                window_start = _event_window_start(parsed.event_timestamp)
                event_count = 1
                if window_start:
                    event_count = connection.execute("""
                        SELECT COUNT(*) FROM alerts
                        WHERE rule_id = ? AND COALESCE(agent_id, '') = COALESCE(?, '')
                          AND event_timestamp >= ? AND event_timestamp <= ?
                    """, (parsed.rule_id, parsed.agent_id, window_start,
                          parsed.event_timestamp)).fetchone()[0]
                base_risk = _base_technique_risk(connection, row["technique_id"])
                technique_risk, scoring_count, reason = _contextual_inputs(
                    base_risk, parsed, event_count,
                )
                risk = calculate_risk(parsed.rule_level, technique_risk, scoring_count)
                explanation = f"{explain_risk(risk)} {reason}"
                connection.execute("""
                    UPDATE risk_scores SET rule_level_score = ?, technique_risk_score = ?,
                        frequency_score = ?, final_risk_score = ?, calculation_details = ?,
                        calculated_at = CURRENT_TIMESTAMP WHERE incident_id = ?
                """, (risk.rule_level_score, risk.technique_risk_score,
                      risk.frequency_score, risk.final_risk_score, explanation,
                      row["incident_id"]))
                connection.execute("""
                    UPDATE incidents SET severity_label = ?, priority = ?,
                        decision_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
                """, (severity_for_risk(risk.final_risk_score),
                      priority_for_risk(risk.final_risk_score), explanation,
                      row["incident_id"]))
            rebuild_recommendations(connection)
        print(f"Re-scored {len(rows)} incidents with context-aware confidence.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
