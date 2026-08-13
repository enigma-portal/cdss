"""Read-only dashboard routes for CDSS incidents."""

from flask import Blueprint, render_template

from app.database import get_db_connection
from app.services.recommendation_engine import get_recommendations

dashboard = Blueprint("dashboard", __name__)


def _dashboard_data():
    connection = get_db_connection()
    try:
        totals = connection.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(severity_label = 'critical') AS critical,
                SUM(severity_label = 'high') AS high,
                SUM(status = 'open') AS open
            FROM incidents
        """).fetchone()
        incidents = connection.execute("""
            SELECT incidents.id, incidents.title, incidents.status,
                   incidents.severity_label, incidents.detected_at,
                   incidents.technique_id, alerts.agent_name,
                   alerts.source_ip, risk_scores.final_risk_score
            FROM incidents
            JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            ORDER BY incidents.detected_at DESC, incidents.id DESC
            LIMIT 50
        """).fetchall()
        results = []
        for incident in incidents:
            result = dict(incident)
            result["recommendations"] = [
                dict(row) for row in get_recommendations(
                    connection, incident["technique_id"], incident["final_risk_score"] or 0,
                )
            ]
            results.append(result)
        return dict(totals), results
    finally:
        connection.close()


@dashboard.route("/")
def index():
    totals, incidents = _dashboard_data()
    return render_template("dashboard.html", totals=totals, incidents=incidents)
