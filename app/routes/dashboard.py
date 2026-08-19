"""Read-only dashboard and incident-detail routes."""

from math import ceil

from flask import Blueprint, abort, render_template, request

from app.database import get_db_connection
from app.services.recommendation_engine import get_incident_recommendations

dashboard = Blueprint("dashboard", __name__)
PAGE_SIZE = 20
SEVERITIES = {"low", "medium", "high", "critical"}


def _safe_page():
    try:
        return max(1, min(int(request.args.get("page", "1")), 100000))
    except ValueError:
        return 1


def _filters():
    search = request.args.get("q", "").strip()[:100]
    severity = request.args.get("severity", "").lower()
    return search, severity if severity in SEVERITIES else ""


def _dashboard_data():
    page = _safe_page()
    search, severity = _filters()
    conditions, parameters = [], []
    if severity:
        conditions.append("incidents.severity_label = ?")
        parameters.append(severity)
    if search:
        conditions.append("(incidents.title LIKE ? OR alerts.rule_id LIKE ? OR alerts.agent_name LIKE ? OR alerts.source_ip LIKE ?)")
        value = f"%{search}%"
        parameters.extend([value] * 4)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""

    connection = get_db_connection()
    try:
        totals = connection.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(severity_label = 'critical'), 0) AS critical,
                   COALESCE(SUM(severity_label = 'high'), 0) AS high,
                   COALESCE(SUM(status = 'open'), 0) AS open
            FROM incidents
        """).fetchone()
        filtered_total = connection.execute(
            "SELECT COUNT(*) FROM incidents JOIN alerts ON alerts.id = incidents.alert_id" + where,
            parameters,
        ).fetchone()[0]
        incidents = connection.execute("""
            SELECT incidents.id, incidents.title, incidents.status,
                   incidents.severity_label, incidents.detected_at,
                   incidents.priority, incidents.decision_reason,
                   incidents.technique_id, alerts.agent_name, alerts.rule_id,
                   alerts.source_ip, risk_scores.final_risk_score
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
        """ + where + " ORDER BY incidents.detected_at DESC, incidents.id DESC LIMIT ? OFFSET ?",
            [*parameters, PAGE_SIZE, (page - 1) * PAGE_SIZE],
        ).fetchall()
        return dict(totals), [dict(row) for row in incidents], {
            "page": page, "pages": max(1, ceil(filtered_total / PAGE_SIZE)),
            "total": filtered_total, "q": search, "severity": severity,
        }
    finally:
        connection.close()


@dashboard.route("/")
def index():
    totals, incidents, pagination = _dashboard_data()
    return render_template("dashboard.html", totals=totals, incidents=incidents,
                           pagination=pagination)


@dashboard.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    connection = get_db_connection()
    try:
        incident = connection.execute("""
            SELECT incidents.*, alerts.wazuh_alert_id, alerts.event_timestamp,
                   alerts.rule_id, alerts.rule_description, alerts.rule_level,
                   alerts.agent_id, alerts.agent_name, alerts.agent_ip,
                   alerts.source_ip, alerts.destination_ip, alerts.processing_status,
                   mitre_techniques.technique_name, mitre_techniques.tactic,
                   risk_scores.rule_level_score, risk_scores.technique_risk_score,
                   risk_scores.frequency_score, risk_scores.final_risk_score,
                   risk_scores.calculation_details
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN mitre_techniques ON mitre_techniques.technique_id = incidents.technique_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            WHERE incidents.id = ?
        """, (incident_id,)).fetchone()
        if not incident:
            abort(404)
        recommendations = get_incident_recommendations(connection, incident_id)
        return render_template("incident_detail.html", incident=dict(incident),
                               recommendations=[dict(row) for row in recommendations])
    finally:
        connection.close()


@dashboard.route("/health")
def health():
    connection = get_db_connection()
    try:
        connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    finally:
        connection.close()
