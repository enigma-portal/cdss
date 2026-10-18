"""Source-aware ATT&CK context; deliberately independent from legacy scoring."""

import json
from datetime import datetime
from urllib.parse import urlsplit

from app.services.classification import valid_mitre_ids


def source_techniques(raw_alert, normalized_ids="[]"):
    """Read stored source evidence, falling back only if raw JSON is unavailable.

    Raw evidence containing no mapping takes precedence over a stale normalized
    array. Syntax validity is not a claim of membership in the official catalogue.
    """
    try:
        source = json.loads(raw_alert)
    except (TypeError, ValueError):
        source = None
    if isinstance(source, dict):
        rule = source.get("rule")
        mitre = rule.get("mitre") if isinstance(rule, dict) else None
        values = mitre.get("id") if isinstance(mitre, dict) else None
        reference = "raw_alert:rule.mitre.id"
    else:
        try:
            values = json.loads(normalized_ids)
        except (TypeError, ValueError):
            values = []
        reference = "alerts.wazuh_mitre_ids (retained source IDs; raw JSON unavailable)"
    if isinstance(values, str):
        values = [values]
    return valid_mitre_ids(values if isinstance(values, list) else []), reference


def ensure_context_technique(connection, technique_id):
    """Retain a syntax-valid source ID without inventing name, tactic or weight."""
    if valid_mitre_ids([technique_id]) != (technique_id,):
        raise ValueError("Invalid ATT&CK technique identifier.")
    connection.execute("""
        INSERT OR IGNORE INTO mitre_techniques
            (technique_id, technique_name, catalogue_source)
        VALUES (?, 'Technique details unavailable; catalogue verification pending', 'placeholder')
    """, (technique_id,))


def _approved_rule(row):
    """Require explicit approval, verification and both reference documents."""
    if not (row["enabled"] and row["verification_status"] == "verified"
            and row["approval_status"] == "approved"):
        return False
    if valid_mitre_ids([row["technique_id"]]) != (row["technique_id"],):
        return False
    try:
        for field in ("verified_at", "approved_at"):
            datetime.fromisoformat(row[field].replace("Z", "+00:00"))
        for field in ("wazuh_reference", "mitre_reference"):
            url = urlsplit(row[field])
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                return False
        mitre_url = urlsplit(row["mitre_reference"])
        expected_path = "/techniques/" + row["technique_id"].replace(".", "/")
        if mitre_url.hostname != "attack.mitre.org" or mitre_url.path.rstrip("/") != expected_path:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    return bool(row["rationale"].strip())


def record_alert_mappings(connection, alert_id, *, allow_supplementary=True):
    """Record mappings from immutable stored evidence; never map via keywords."""
    alert = connection.execute(
        "SELECT raw_alert, wazuh_mitre_ids, rule_id FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    if alert is None:
        raise ValueError("Alert does not exist.")
    technique_ids, reference = source_techniques(alert["raw_alert"], alert["wazuh_mitre_ids"])
    if technique_ids:
        candidates = [(technique_id, "wazuh", reference, None)
                      for technique_id in technique_ids]
    elif allow_supplementary:
        rows = connection.execute("""
            SELECT * FROM supplementary_mitre_mappings
            WHERE wazuh_rule_id = ? ORDER BY id
        """, (alert["rule_id"],)).fetchall()
        candidates = [
            (row["technique_id"], "supplementary",
             f"supplementary_mitre_mappings:{row['id']}; Wazuh: {row['wazuh_reference']}; ATT&CK: {row['mitre_reference']}",
             row["rationale"])
            for row in rows if _approved_rule(row)
        ]
    else:
        candidates = []
    for ordinal, (technique_id, mapping_source, source_reference, rationale) in enumerate(candidates):
        ensure_context_technique(connection, technique_id)
        connection.execute("""
            INSERT INTO alert_mitre_techniques
                (alert_id, technique_id, mapping_source, ordinal, source_reference, mapping_rationale)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_id, technique_id, mapping_source) DO NOTHING
        """, (alert_id, technique_id, mapping_source, ordinal, source_reference, rationale))
    return get_alert_mitre_context(connection, alert_id)


def get_alert_mitre_context(connection, alert_id):
    mappings = [dict(row) for row in connection.execute("""
        SELECT am.*, mt.technique_name, mt.tactic, mt.catalogue_source
        FROM alert_mitre_techniques am
        JOIN mitre_techniques mt ON mt.technique_id = am.technique_id
        WHERE am.alert_id = ? ORDER BY am.ordinal, am.technique_id, am.mapping_source
    """, (alert_id,))]
    return {"status": "Mapped" if mappings else "Not Mapped", "mappings": mappings}


def attach_alert_context(connection, incident_id, alert_id):
    """Aggregate known context; caller supplies membership, no correlation here.

    A future Phase 4 caller can call this for each explicitly linked alert. Each
    incident technique is unique while all contributing alert sources are kept.
    """
    mappings = get_alert_mitre_context(connection, alert_id)["mappings"]
    for mapping in mappings:
        ordinal = connection.execute("""
            SELECT COALESCE(MAX(ordinal), -1) + 1 FROM incident_mitre_techniques
            WHERE incident_id = ?
        """, (incident_id,)).fetchone()[0]
        connection.execute("""
            INSERT INTO incident_mitre_techniques (incident_id, technique_id, ordinal)
            VALUES (?, ?, ?) ON CONFLICT(incident_id, technique_id) DO NOTHING
        """, (incident_id, mapping["technique_id"], ordinal))
        connection.execute("""
            INSERT INTO incident_mitre_sources
                (incident_id, technique_id, source_alert_id, mapping_source)
            VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING
        """, (incident_id, mapping["technique_id"], alert_id, mapping["mapping_source"]))


def get_incident_mitre_context(connection, incident_id):
    techniques = []
    for row in connection.execute("""
        SELECT imt.technique_id, mt.technique_name, mt.tactic, mt.catalogue_source
        FROM incident_mitre_techniques imt
        JOIN mitre_techniques mt ON mt.technique_id = imt.technique_id
        WHERE imt.incident_id = ? ORDER BY imt.ordinal, imt.technique_id
    """, (incident_id,)):
        item = dict(row)
        item["sources"] = [dict(source) for source in connection.execute("""
            SELECT s.source_alert_id, s.mapping_source, am.source_reference,
                   am.mapping_rationale
            FROM incident_mitre_sources s JOIN alert_mitre_techniques am
              ON am.alert_id = s.source_alert_id AND am.technique_id = s.technique_id
             AND am.mapping_source = s.mapping_source
            WHERE s.incident_id = ? AND s.technique_id = ?
            ORDER BY s.source_alert_id, am.ordinal, s.mapping_source
        """, (incident_id, row["technique_id"]))]
        # Legacy associations without source evidence remain traceable as
        # unavailable, never falsely labelled Wazuh or verified supplementary.
        techniques.append(item)
    return {"status": "Mapped" if techniques else "Not Mapped", "techniques": techniques}
