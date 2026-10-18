"""Deterministic advisory recommendations built from local knowledge."""

import json

from app.services.classification import classify
from app.services.mitre_mapping import source_techniques


def _risk_band(score):
    return "critical" if score >= 8 else "high" if score >= 6 else "medium" if score >= 3 else "low"


def _curated_mitre(connection, technique_ids, risk_score):
    items = []
    for technique_id in technique_ids:
        rows = connection.execute("""
            SELECT r.action_text, r.response_phase, r.priority
            FROM recommendations r JOIN knowledge_base kb ON kb.id = r.knowledge_base_id
            WHERE kb.technique_id = ? AND r.is_active = 1
              AND ? BETWEEN r.minimum_risk_score AND r.maximum_risk_score
            ORDER BY r.priority, r.id
        """, (technique_id, risk_score)).fetchall()
        for row in rows:
            items.append({
                "action_text": row["action_text"], "response_phase": row["response_phase"] or "Analysis",
                "priority": row["priority"], "framework": "CDSS project-defined",
                "control_reference": f"ATT&CK classification {technique_id}",
                "rationale": (f"Candidate action selected for ATT&CK {technique_id}; its wording and "
                              "priority are CDSS-defined unless verified provenance is displayed."),
            })
    unique = {}
    for item in sorted(items, key=lambda value: (value["priority"], value["action_text"])):
        unique.setdefault(item["action_text"], item)
    return list(unique.values())


CATEGORY_ACTIONS = {
    "Authentication Failure": (
        ("Review failed and successful authentication events for the same available user, source, and endpoint.", "Analysis"),
        ("Validate whether the activity was authorized and escalate repeated or high-severity failures.", "Escalation"),
        ("Recommend credential protection or narrow containment only when malicious activity is confirmed.", "Conditional containment")),
    "Authentication Activity": (
        ("Confirm the authentication matches the expected user, endpoint, time, and access method.", "Validation"),
        ("Correlate with preceding failures, unusual remote access, and privilege changes.", "Analysis")),
    "SSH Activity": (
        ("Review the SSH event and available account, source, endpoint, and nearby authentication activity.", "Analysis"),
        ("Escalate or recommend narrow access restriction when unauthorized activity is confirmed.", "Conditional containment")),
    "File Integrity Event": (
        ("Compare the reported file change with an approved deployment or administrator action.", "Validation"),
        ("Preserve available file metadata and compare it with a trusted baseline.", "Evidence"),
        ("Recommend restoration or containment only if the change is confirmed unauthorized.", "Conditional containment")),
    "Host Security Finding": (
        ("Validate the host finding and inspect related endpoint evidence.", "Analysis"),
        ("Prioritize analyst escalation when severity or corroborating evidence indicates impact.", "Escalation")),
    "Malware Detection": (
        ("Validate the detection and inspect available process, file, hash, and parent-child evidence.", "Analysis"),
        ("Preserve evidence and recommend endpoint containment when malicious execution is confirmed.", "Conditional containment"),
        ("Search for matching indicators on related systems after confirmation.", "Investigation")),
}

UNCLASSIFIED_ACTIONS = (
    ("Review the original security event and identify available endpoint, user, and source context.", "Analysis"),
    ("Correlate related logs around the event time and determine whether activity was authorized.", "Validation"),
    ("Escalate when the SIEM rule level or corroborating evidence warrants analyst investigation.", "Escalation"),
)


def _fallback(classification):
    candidates = CATEGORY_ACTIONS.get(classification["label"], UNCLASSIFIED_ACTIONS)
    reason = ("Based on an explicit project-defined Wazuh-group mapping."
              if classification["source"] == "WAZUH_GROUP" else
              "No reliable classification exists; no attack-specific remediation was inferred.")
    return [{"action_text": action, "response_phase": phase, "priority": position,
             "framework": "CDSS project-defined", "control_reference": classification["label"],
             "rationale": reason}
            for position, (action, phase) in enumerate(candidates, 1)]


def _scope(source_ip=None, agent_name=None, agent_ip=None, username=None):
    parts = []
    if source_ip:
        parts.append(f"observed source {source_ip}")
    if agent_name or agent_ip:
        parts.append(f"affected endpoint {agent_name or agent_ip}")
    if username:
        parts.append(f"observed user {username}")
    return "; ".join(parts) or "available event evidence"


def _prioritize(items, risk_score):
    band = _risk_band(risk_score)
    disruptive = {"Containment", "Conditional containment", "Eradication", "Recovery"}
    selected = ([item for item in items if item["response_phase"] not in disruptive][:2]
                if band == "low" else items[:2] if band == "medium" else items[:3])
    for position, item in enumerate(selected, 1):
        item["priority"] = position
        item["rationale"] += f" Risk band: {band}; advisory priority {position}."
    return selected


def generate_recommendations(connection, technique_ids, risk_score, description=None,
                             rule_groups=(), source_ip=None, agent_name=None, agent_ip=None,
                             classification=None, username=None):
    if isinstance(technique_ids, str):
        technique_ids = (technique_ids,) if technique_ids else ()
    classification = classification or classify(technique_ids, rule_groups)
    candidates = _curated_mitre(connection, classification["mitre_ids"], risk_score)
    if classification["source"] == "MITRE" and _risk_band(risk_score) == "low":
        candidates.insert(0, {
            "action_text": "Confirm the login or security event is authorized and validate the available user, endpoint, and time context.",
            "response_phase": "Validation", "priority": 1,
            "framework": "CDSS project-defined", "control_reference": classification["label"],
            "rationale": "A low-risk ATT&CK tag is context, not proof of compromise.",
        })
    items = _prioritize(candidates or _fallback(classification), risk_score)
    scope = _scope(source_ip, agent_name, agent_ip, username)
    for item in items:
        item["rationale"] += f" Scope: {scope}."
    return items


def save_recommendations(connection, incident_id, recommendations):
    for item in recommendations:
        connection.execute("""
            INSERT OR IGNORE INTO incident_recommendations
                (incident_id, action_text, response_phase, priority, framework,
                 control_reference, rationale) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (incident_id, item["action_text"], item["response_phase"], item["priority"],
              item["framework"], item.get("control_reference"), item.get("rationale")))


def get_incident_recommendations(connection, incident_id):
    return connection.execute("""
        SELECT action_text, response_phase, priority, framework, control_reference, rationale
        FROM incident_recommendations WHERE incident_id = ? ORDER BY priority, id
    """, (incident_id,)).fetchall()


def backfill_recommendations(connection):
    rows = connection.execute("""
        SELECT i.id, i.classification_source, i.classification_label,
               a.rule_description, a.rule_groups, a.username, a.source_ip, a.agent_name, a.agent_ip,
               a.raw_alert, a.wazuh_mitre_ids,
               COALESCE(rs.final_risk_score, 0) AS risk_score
        FROM incidents i JOIN alerts a ON a.id = i.alert_id
        LEFT JOIN risk_scores rs ON rs.incident_id = i.id
        WHERE NOT EXISTS (SELECT 1 FROM incident_recommendations ir WHERE ir.incident_id = i.id)
        ORDER BY i.id
    """).fetchall()
    for row in rows:
        # Contextual supplementary mappings must not alter legacy guidance when
        # an administrator rebuilds it. Preserve the original source-only input.
        techniques, _ = source_techniques(row["raw_alert"], row["wazuh_mitre_ids"])
        try:
            groups = tuple(json.loads(row["rule_groups"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            groups = ()
        classification = {"source": row["classification_source"],
                          "label": row["classification_label"], "mitre_ids": techniques}
        items = generate_recommendations(
            connection, techniques, row["risk_score"], row["rule_description"], groups,
            row["source_ip"], row["agent_name"], row["agent_ip"], classification, row["username"])
        save_recommendations(connection, row["id"], items)
    return len(rows)


def rebuild_recommendations(connection):
    """Regenerate the same output from the same stored evidence and engine."""
    connection.execute("DELETE FROM incident_recommendations")
    return backfill_recommendations(connection)
