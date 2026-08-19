"""Explainable MITRE, NIST and CIS defensive recommendation engine."""


def _curated_mitre(connection, technique_id, risk_score):
    if not technique_id:
        return []
    rows = connection.execute("""
        SELECT recommendations.action_text, recommendations.response_phase,
               recommendations.priority, knowledge_base.nist_ir_guidance,
               knowledge_base.cis_control, knowledge_base.d3fend_technique
        FROM recommendations
        JOIN knowledge_base ON knowledge_base.id = recommendations.knowledge_base_id
        WHERE knowledge_base.technique_id = ? AND recommendations.is_active = 1
          AND ? BETWEEN recommendations.minimum_risk_score AND recommendations.maximum_risk_score
        ORDER BY recommendations.priority, recommendations.id
    """, (technique_id, risk_score)).fetchall()
    return [{
        "action_text": row["action_text"],
        "response_phase": row["response_phase"] or "Analysis",
        "priority": row["priority"],
        "framework": "MITRE D3FEND + NIST/CIS",
        "control_reference": " / ".join(filter(None, [
            row["d3fend_technique"], row["nist_ir_guidance"], row["cis_control"],
        ])),
        "rationale": f"Curated defensive mapping for ATT&CK {technique_id}.",
    } for row in rows]


def _fallback(description, rule_groups=()):
    context = " ".join([description or "", *rule_groups]).lower()
    if any(phrase in context for phrase in (
        "windows logon success", "login session opened", "login session closed",
        "authentication success",
    )) and not any(word in context for word in ("possible", "attack", "failed", "invalid")):
        return [
            ("Confirm the login matches the expected user, endpoint, time, and access method.", "Validation", 1, "NIST SP 800-61", "Detection and Analysis"),
            ("Correlate the session with preceding failures, unusual remote access, or privilege changes.", "Analysis", 2, "NIST CSF", "DE.AE / RS.AN"),
            ("Take containment action only if the session is unauthorized or corroborating evidence is found.", "Conditional containment", 3, "CIS Controls v8", "Controls 5, 6 and 8"),
        ]
    if any(word in context for word in ("login", "authentication", "password", "brute", "credential")):
        return [
            ("Review authentication logs and identify failed and successful logins from the same source.", "Analysis", 1, "NIST CSF", "DE.AE / RS.AN"),
            ("Temporarily restrict the suspicious account or source when malicious activity is confirmed.", "Containment", 2, "NIST SP 800-61", "Containment"),
            ("Enforce MFA, account lockout, and least-privilege access for affected accounts.", "Prevention", 3, "CIS Controls v8", "Controls 5 and 6"),
        ]
    if any(word in context for word in ("malware", "rootkit", "virus", "trojan", "anomaly")):
        return [
            ("Validate the detection and inspect related processes, files, hashes, and parent-child activity.", "Analysis", 1, "NIST SP 800-61", "Detection and Analysis"),
            ("Isolate the endpoint if malicious execution is confirmed while preserving forensic evidence.", "Containment", 2, "NIST SP 800-61", "Containment"),
            ("Update anti-malware controls and investigate persistence across the environment.", "Eradication", 3, "CIS Controls v8", "Control 10"),
        ]
    if any(word in context for word in ("benchmark", "configuration", "policy", "compliance", "partition")):
        return [
            ("Confirm whether the reported configuration deviates from the approved secure baseline.", "Analysis", 1, "CIS Controls v8", "Control 4"),
            ("Create a tested remediation change and obtain system-owner approval before applying it.", "Remediation", 2, "NIST CSF", "PR.IP / GV.PO"),
            ("Re-scan the host after remediation and record accepted exceptions with business justification.", "Recovery", 3, "CIS Controls v8", "Controls 4 and 7"),
        ]
    if any(word in context for word in ("network", "firewall", "port", "connection", "packet", "dns")):
        return [
            ("Correlate source, destination, port, protocol, and surrounding network events.", "Analysis", 1, "NIST SP 800-61", "Detection and Analysis"),
            ("Block or rate-limit confirmed malicious traffic using the narrowest effective rule.", "Containment", 2, "CIS Controls v8", "Controls 12 and 13"),
            ("Review segmentation and monitoring coverage for the affected network path.", "Prevention", 3, "NIST CSF", "PR.PT / DE.CM"),
        ]
    if any(word in context for word in ("file", "integrity", "permission", "modified")):
        return [
            ("Verify the file change against an approved deployment or administrator action.", "Analysis", 1, "NIST SP 800-61", "Detection and Analysis"),
            ("Preserve file metadata and compare the current hash with the trusted baseline.", "Evidence", 2, "CIS Controls v8", "Control 3"),
            ("Restore the trusted version and review permissions if the change is unauthorized.", "Recovery", 3, "CIS Controls v8", "Controls 3 and 4"),
        ]
    return [
        ("Validate the alert against the affected host and correlate events around the detection time.", "Analysis", 1, "NIST SP 800-61", "Detection and Analysis"),
        ("Preserve relevant logs and document the analyst's findings before changing the system.", "Evidence", 2, "NIST SP 800-61", "Incident Documentation"),
        ("Escalate to the system owner when impact is unclear or activity remains unexplained.", "Escalation", 3, "NIST CSF", "RS.CO / RS.AN"),
    ]


def _scope(source_ip=None, agent_name=None, agent_ip=None):
    endpoint = agent_name or agent_ip
    parts = []
    if source_ip:
        parts.append(f"observed source {source_ip}")
    if endpoint:
        parts.append(f"affected endpoint {endpoint}")
    return "; ".join(parts) or "the affected system"


def generate_recommendations(
    connection, technique_id, risk_score, description=None, rule_groups=(),
    source_ip=None, agent_name=None, agent_ip=None,
):
    context = " ".join([description or "", *rule_groups]).lower()
    routine_success = any(phrase in context for phrase in (
        "windows logon success", "login session opened", "login session closed",
        "authentication success",
    )) and not any(word in context for word in ("possible", "attack", "failed", "invalid"))
    recommendations = [] if routine_success else _curated_mitre(
        connection, technique_id, risk_score,
    )
    scope = _scope(source_ip, agent_name, agent_ip)
    if recommendations:
        for item in recommendations:
            item["rationale"] += f" Scope: {scope}."
        return recommendations
    fallback_reason = (
        "Verification-first guidance because successful activity is not malicious proof."
        if routine_success else
        "Context-based fallback because no curated ATT&CK mapping was present."
    )
    return [{
        "action_text": action, "response_phase": phase, "priority": priority,
        "framework": framework, "control_reference": reference,
        "rationale": f"{fallback_reason} Scope: {scope}.",
    } for action, phase, priority, framework, reference in _fallback(description, rule_groups)]


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
        SELECT incidents.id, incidents.technique_id, alerts.rule_description,
               alerts.source_ip, alerts.agent_name, alerts.agent_ip,
               COALESCE(risk_scores.final_risk_score, 0) AS risk_score
        FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
        LEFT JOIN risk_scores ON risk_scores.incident_id = incidents.id
        WHERE NOT EXISTS (SELECT 1 FROM incident_recommendations ir WHERE ir.incident_id = incidents.id)
    """).fetchall()
    for row in rows:
        items = generate_recommendations(
            connection, row["technique_id"], row["risk_score"], row["rule_description"], (),
            row["source_ip"], row["agent_name"], row["agent_ip"],
        )
        save_recommendations(connection, row["id"], items)
    return len(rows)


def rebuild_recommendations(connection):
    """Explicitly refresh stored decisions after a reviewed framework update."""
    connection.execute("DELETE FROM incident_recommendations")
    return backfill_recommendations(connection)
