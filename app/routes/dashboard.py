"""Read-only dashboard and incident-detail routes."""

from math import ceil

from flask import Blueprint, abort, render_template, request

from app.database import get_db_connection
from app.auth import login_required
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
    view = request.args.get("view", "").lower()
    return search, severity if severity in SEVERITIES else "", view if view == "actionable" else ""


def _dashboard_data():
    page = _safe_page()
    search, severity, view = _filters()
    conditions, parameters = [], []
    if severity:
        conditions.append("incidents.severity_label = ?")
        parameters.append(severity)
    elif view == "actionable":
        conditions.append("incidents.severity_label IN ('critical', 'high')")
    if search:
        conditions.append("(incidents.title LIKE ? OR incidents.technique_id LIKE ? OR alerts.rule_id LIKE ? OR alerts.agent_name LIKE ? OR alerts.source_ip LIKE ?)")
        value = f"%{search}%"
        parameters.extend([value] * 5)
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
        pages = max(1, ceil(filtered_total / PAGE_SIZE))
        page = min(page, pages)
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
            "page": page, "pages": pages,
            "total": filtered_total, "q": search, "severity": severity, "view": view,
            "page_numbers": list(range(max(1, page - 2), min(pages, page + 2) + 1)),
            "active_label": (
                f"{severity.title()} only" if severity else
                "Actionable: High + Critical" if view == "actionable" else
                "All incidents"
            ),
        }
    finally:
        connection.close()


def _overview_data():
    """Return compact, alert-derived SOC metrics without inventing coverage."""
    connection = get_db_connection()
    try:
        # Wazuh emits offsets such as ``-0400`` which SQLite does not parse.
        # The first 19 characters are stable ISO local time and are sufficient
        # for this lab's rolling analyst view.
        window = "datetime(substr(incidents.detected_at, 1, 19)) >= datetime('now', '-24 hours')"
        metrics = dict(connection.execute(f"""
            SELECT COUNT(*) AS findings,
                   COALESCE(SUM(incidents.severity_label IN ('critical', 'high')), 0) AS actionable,
                   COALESCE(SUM(incidents.severity_label = 'critical'), 0) AS critical,
                   COUNT(DISTINCT NULLIF(alerts.agent_name, '')) AS assets,
                   COALESCE(AVG(risk_scores.final_risk_score), 0) AS average_risk
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            WHERE {window}
        """).fetchone())
        metrics["posture_score"] = (
            max(0, min(100, round(100 - metrics["average_risk"] * 10)))
            if metrics["findings"] else None
        )

        severity = [dict(row) for row in connection.execute(f"""
            SELECT incidents.severity_label AS label, COUNT(*) AS total
            FROM incidents WHERE {window}
            GROUP BY incidents.severity_label
        """)]
        assets = [dict(row) for row in connection.execute(f"""
            SELECT COALESCE(NULLIF(alerts.agent_name, ''), 'Unknown endpoint') AS name,
                   COALESCE(NULLIF(alerts.agent_ip, ''), 'IP not reported') AS ip,
                   COUNT(*) AS findings,
                   SUM(incidents.severity_label IN ('critical', 'high')) AS actionable,
                   MAX(COALESCE(risk_scores.final_risk_score, 0)) AS peak_risk,
                   MAX(incidents.detected_at) AS last_seen
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            WHERE {window}
            GROUP BY alerts.agent_name, alerts.agent_ip
            ORDER BY actionable DESC, peak_risk DESC LIMIT 6
        """)]
        attacks = [dict(row) for row in connection.execute(f"""
            SELECT incidents.technique_id, COALESCE(mitre_techniques.technique_name, incidents.title) AS name,
                   COUNT(*) AS total, MAX(incidents.severity_label) AS severity
            FROM incidents
            LEFT JOIN mitre_techniques ON mitre_techniques.technique_id = incidents.technique_id
            WHERE {window} AND incidents.severity_label IN ('critical', 'high')
            GROUP BY incidents.technique_id, name ORDER BY total DESC LIMIT 5
        """)]
        queue = [dict(row) for row in connection.execute(f"""
            SELECT MAX(incidents.id) AS id, incidents.title, incidents.severity_label,
                   incidents.priority, alerts.rule_id, alerts.agent_name,
                   COUNT(*) AS occurrences, MAX(incidents.detected_at) AS detected_at,
                   MAX(COALESCE(risk_scores.final_risk_score, 0)) AS risk
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            WHERE {window} AND incidents.severity_label IN ('critical', 'high')
            GROUP BY alerts.rule_id, alerts.agent_name
            ORDER BY risk DESC, occurrences DESC LIMIT 6
        """)]
        return metrics, severity, assets, attacks, queue
    finally:
        connection.close()


@dashboard.route("/")
@login_required
def index():
    metrics, severity, assets, attacks, queue = _overview_data()
    return render_template("overview.html", metrics=metrics, severity=severity,
                           assets=assets, attacks=attacks, queue=queue)


@dashboard.route("/incidents")
@login_required
def incidents():
    totals, incidents, pagination = _dashboard_data()
    return render_template("dashboard.html", totals=totals, incidents=incidents,
                           pagination=pagination)


@dashboard.route("/incidents/<int:incident_id>")
@login_required
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
                   risk_scores.calculation_details,
                   knowledge_base.d3fend_technique,
                   knowledge_base.nist_ir_guidance, knowledge_base.cis_control
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            LEFT JOIN mitre_techniques ON mitre_techniques.technique_id = incidents.technique_id
            LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
            LEFT JOIN knowledge_base ON knowledge_base.technique_id = incidents.technique_id
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
