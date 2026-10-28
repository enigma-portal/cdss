"""Connect parsed Wazuh alerts to CDSS incidents, scoring, and recommendations."""

from datetime import timedelta
import json

from app.database import get_db_connection
from app.risk_engine.scoring import (
    calculate_risk, explain_risk, priority_for_risk, severity_for_risk,
)
from app.services.alert_parser import parse_alert
from app.services.classification import classify
from app.services.recommendation_engine import generate_recommendations, save_recommendations
from app.services.wazuh_indexer import WazuhIndexerClient
from app.services.asset_resolver import resolve_asset_id
from app.services.incident_correlation import find_related_incident, link_alert, event_time
from app.services.mitre_mapping import (
    attach_alert_context, ensure_context_technique, record_alert_mappings,
)


def ingest_source_alert(raw_alert, connection_id=None):
    """Production collection path: normalize/store an alert, never open a case.

    Grouping and initial priority are read-only triage views. A human explicitly
    opens an investigation case from a group. The legacy process_alert helper
    below is retained for historical compatibility and isolated regression
    fixtures, but is not called by the production poller or CLI collector.
    """
    parsed = parse_alert(raw_alert)
    from app.services.ingestion_safety import document_identity
    identity = document_identity(raw_alert, connection_id)
    if not parsed.wazuh_alert_id:
        raise ValueError('A Wazuh/source alert identifier is required for safe ingestion.')
    connection = get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            if identity:
                prior = connection.execute('''SELECT a.raw_alert FROM alert_source_documents d
                    JOIN alerts a ON a.id=d.alert_id
                    WHERE d.connection_id=? AND d.source_index=? AND d.source_document_id=?''', identity).fetchone()
                if prior and json.loads(prior['raw_alert']) != json.loads(parsed.raw_alert):
                    raise ValueError('Source document changed; original alert preserved.')
            for technique_id in parsed.mitre_ids:
                ensure_context_technique(connection, technique_id)
            record = parsed.as_database_record()
            record['asset_id'] = resolve_asset_id(connection, parsed.agent_id)
            columns = ', '.join(record)
            placeholders = ', '.join('?' for _ in record)
            cursor = connection.execute(
                f'INSERT OR IGNORE INTO alerts ({columns}) VALUES ({placeholders})',
                tuple(record.values()))
            alert_id = cursor.lastrowid if cursor.rowcount else None
            if alert_id is None:
                existing = connection.execute('SELECT id,raw_alert FROM alerts WHERE wazuh_alert_id=?',
                                              (parsed.wazuh_alert_id,)).fetchone()
                if existing is None:
                    raise RuntimeError('Alert storage failed without a duplicate source identifier.')
                alert_id = existing['id']
                if json.loads(existing['raw_alert']) != json.loads(parsed.raw_alert):
                    raise ValueError('Source identifier collision; original alert preserved.')
                if identity:
                    different = connection.execute('''SELECT 1 FROM alert_source_documents
                        WHERE alert_id=? AND (connection_id<>? OR source_index<>? OR source_document_id<>?)''',
                        (alert_id,*identity)).fetchone()
                    if different:
                        raise ValueError('Source namespace collision; original alert preserved.')
            if identity:
                connection.execute('''INSERT INTO alert_source_documents
                    (connection_id,source_index,source_document_id,alert_id) VALUES(?,?,?,?)
                    ON CONFLICT(connection_id,source_index,source_document_id) DO NOTHING''',(*identity,alert_id))
            record_alert_mappings(connection, alert_id)
            connection.execute("UPDATE alerts SET processing_status='processed' WHERE id=?", (alert_id,))
            return {'alert_id': alert_id, 'created': bool(cursor.rowcount), 'incident_id': None}
    finally:
        connection.close()


def _event_window_start(event_timestamp):
    timestamp = event_time(event_timestamp)
    if timestamp is None:
        return None
    return (timestamp - timedelta(hours=1)).isoformat()


def _ensure_technique(connection, technique_id):
    if not technique_id:
        return None
    ensure_context_technique(connection, technique_id)
    return technique_id


def _base_technique_risk(connection, technique_id):
    if not technique_id:
        return None
    row = connection.execute(
        "SELECT base_risk_score FROM knowledge_base WHERE technique_id = ?", (technique_id,)
    ).fetchone()
    return row["base_risk_score"] if row else None


def _frequency_count(connection, parsed):
    window_start = _event_window_start(parsed.event_timestamp)
    if not window_start:
        return 1
    clauses = ["rule_id = ?", "cdss_event_epoch(event_timestamp) >= cdss_event_epoch(?)", "cdss_event_epoch(event_timestamp) <= cdss_event_epoch(?)"]
    values = [parsed.rule_id, window_start, parsed.event_timestamp]
    # Add only context actually present. This prevents unrelated users/sources
    # from being combined while still degrading safely for sparse events.
    for column, value in (
        ("agent_id", parsed.agent_id), ("source_ip", parsed.source_ip),
        ("username", parsed.username),
    ):
        if value:
            clauses.append(f"{column} = ?")
            values.append(value)
    row = connection.execute(
        f"SELECT COUNT(*) AS total FROM alerts WHERE {' AND '.join(clauses)}",
        values,
    ).fetchone()
    return row["total"] + 1


def _frequency_threshold(connection):
    row = connection.execute("""
        SELECT setting_value FROM system_settings WHERE setting_key = 'correlation_threshold'
    """).fetchone()
    try:
        return max(2, min(int(row["setting_value"]), 100)) if row else 3
    except (TypeError, ValueError):
        return 3


def _contextual_inputs(base_risk, parsed, event_count):
    """Avoid treating an ATT&CK tag alone as proof of malicious activity."""
    description = (parsed.rule_description or "").lower()
    suspicious = any(word in description for word in (
        "failed", "invalid", "non-existent", "brute", "possible", "attack",
        "malware", "dropped", "denied", "tamper", "unauthorized",
    ))
    routine_success = any(phrase in description for phrase in (
        "windows logon success", "login session opened", "login session closed",
        "authentication success",
    ))
    if routine_success and not suspicious and (parsed.rule_level or 0) <= 4:
        return min(base_risk, 3.0), 1, "Routine successful activity; ATT&CK tag retained as context, not malicious proof."
    if not suspicious and (parsed.rule_level or 0) <= 3:
        return min(base_risk, 4.0), event_count, "Low-level detection; technique risk capped pending corroborating evidence."
    if not suspicious and (parsed.rule_level or 0) <= 6:
        return min(base_risk, 6.0), event_count, "Moderate-confidence detection; technique risk limited pending corroboration."
    return base_risk, event_count, "Technique risk applied because alert context contains suspicious evidence."


def process_alert(raw_alert):
    """Store one raw Wazuh alert and return its incident decision result.

    Processing the same Wazuh alert ID more than once is safe; the existing
    incident is returned instead of creating a duplicate.
    """
    parsed = parse_alert(raw_alert)
    if not parsed.wazuh_alert_id:
        raise ValueError("A Wazuh/source alert identifier is required for safe ingestion.")
    classification = classify(parsed.mitre_ids, parsed.rule_groups)
    # Legacy scoring/classification/guidance inputs remain Wazuh-only. Phase 3
    # supplementary context lives in mapping tables and never enters this tuple.
    technique_ids = parsed.mitre_ids
    technique_id = technique_ids[0] if technique_ids else None
    connection = get_db_connection()
    try:
        # Store the validated source first as ``new``. Downstream work occurs in
        # a separate transaction so failures remain visible and retryable.
        with connection:
            for mapped_id in technique_ids:
                _ensure_technique(connection, mapped_id)
            record = parsed.as_database_record()
            record["asset_id"] = resolve_asset_id(connection, parsed.agent_id)
            columns = ", ".join(record)
            placeholders = ", ".join("?" for _ in record)
            cursor = connection.execute(
                f"INSERT OR IGNORE INTO alerts ({columns}) VALUES ({placeholders})",
                tuple(record.values()),
            )
            if cursor.rowcount:
                alert_id = cursor.lastrowid
                record_alert_mappings(connection, alert_id)
            else:
                existing = connection.execute(
                    "SELECT id, raw_alert FROM alerts WHERE wazuh_alert_id = ?", (parsed.wazuh_alert_id,)
                ).fetchone()
                if not existing:
                    raise RuntimeError("Alert storage failed without a duplicate source identifier.")
                alert_id = existing["id"]
                record_alert_mappings(connection, alert_id)
                incident = connection.execute(
                    "SELECT incident_id AS id FROM incident_alerts WHERE alert_id = ?", (alert_id,)
                ).fetchone()
                if incident:
                    attach_alert_context(connection, incident["id"], alert_id)
                    connection.execute(
                        "UPDATE alerts SET processing_status = 'processed' WHERE id = ?", (alert_id,)
                    )
                    return {"incident_id": incident["id"], "created": False}
                # A failed/new duplicate is retried from the immutable stored
                # source, never from potentially different caller content.
                parsed = parse_alert(json.loads(existing["raw_alert"]))
                classification = classify(parsed.mitre_ids, parsed.rule_groups)
                technique_ids = parsed.mitre_ids
                technique_id = technique_ids[0] if technique_ids else None

        asset_id = resolve_asset_id(connection, parsed.agent_id)
        try:
          with connection:
            # Serialize membership selection and writes across pollers/retries.
            connection.execute('BEGIN IMMEDIATE')
            linked = connection.execute('SELECT incident_id FROM incident_alerts WHERE alert_id=?',
                                        (alert_id,)).fetchone()
            if linked:
                return {'incident_id': linked['incident_id'], 'created': False}
            asset_id = resolve_asset_id(connection, parsed.agent_id)
            connection.execute('UPDATE alerts SET asset_id=? WHERE id=?', (asset_id, alert_id))
            related = find_related_incident(connection, alert_id)
            if related:
                incident_id, reason = related
                link_alert(connection, incident_id, alert_id, reason)
                attach_alert_context(connection, incident_id, alert_id)
                connection.execute("UPDATE alerts SET processing_status='processed' WHERE id=?", (alert_id,))
                return {'incident_id': incident_id, 'created': False, 'correlated': True,
                        'correlation_reason': reason}
            frequency_count = _frequency_count(connection, parsed)

            mapped_weights = [
                weight for weight in (
                    _base_technique_risk(connection, mapped_id) for mapped_id in technique_ids
                ) if weight is not None
            ]
            base_risk = max(mapped_weights) if mapped_weights else None
            technique_risk, scoring_count, context_reason = _contextual_inputs(
                base_risk, parsed, frequency_count,
            ) if base_risk is not None else (None, frequency_count, "No verified CDSS technique weight was available; Wazuh-only path used.")
            risk = calculate_risk(
                parsed.rule_level, technique_risk, scoring_count,
                _frequency_threshold(connection),
            )
            severity = severity_for_risk(risk.final_risk_score)
            priority = priority_for_risk(risk.final_risk_score)
            explanation = f"{explain_risk(risk)} {context_reason}"
            title = parsed.rule_description or classification["label"]
            incident_cursor = connection.execute("""
                INSERT INTO incidents
                    (alert_id, technique_id, asset_id, title, severity_label, priority,
                     detected_at, summary, decision_reason, classification_source,
                     classification_label, risk_basis, engine_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '2.0')
            """, (
                alert_id, technique_id, asset_id, title, severity, priority,
                parsed.event_timestamp, "Created automatically from a SIEM alert.",
                explanation, classification["source"], classification["label"], risk.risk_basis,
            ))
            incident_id = incident_cursor.lastrowid
            link_alert(connection, incident_id, alert_id, 'seed')
            attach_alert_context(connection, incident_id, alert_id)
            connection.execute("""
                INSERT INTO risk_scores
                    (incident_id, rule_level_score, technique_risk_score,
                     frequency_score, final_risk_score, calculation_details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                incident_id, risk.rule_level_score, risk.technique_risk_score,
                risk.frequency_score, risk.final_risk_score,
                ("40% normalized SIEM rule level, 40% CDSS Technique Risk Weight, 20% contextual recurrence."
                 if risk.risk_basis == "WAZUH_PLUS_MITRE" else
                 "80% normalized SIEM rule level, 20% contextual recurrence; no MITRE weight used."),
            ))
            recommendations = generate_recommendations(
                connection, technique_ids, risk.final_risk_score,
                parsed.rule_description, parsed.rule_groups, parsed.source_ip,
                parsed.agent_name, parsed.agent_ip,
                classification=classification, username=parsed.username,
            )
            save_recommendations(connection, incident_id, recommendations)
            connection.execute(
                "UPDATE alerts SET processing_status = 'processed' WHERE id = ?", (alert_id,)
            )
            return {
                "incident_id": incident_id,
                "created": True,
                "risk_score": risk.final_risk_score,
                "severity": severity,
                "priority": priority,
                "explanation": explanation,
                "recommendations": recommendations,
            }
        except Exception:
            with connection:
                connection.execute(
                    "UPDATE alerts SET processing_status = 'failed' WHERE id = ?", (alert_id,)
                )
            raise
    finally:
        connection.close()


def process_indexer_alerts(size=100, since=None, client=None, sort_order="desc"):
    """Fetch a bounded batch and store alerts without creating cases."""
    client = client or WazuhIndexerClient.from_environment()
    return [ingest_source_alert(alert) for alert in client.fetch_alerts(
        size=size, since=since, sort_order=sort_order,
    )]
