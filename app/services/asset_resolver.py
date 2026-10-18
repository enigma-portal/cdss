"""Exact Wazuh-agent asset association for Phase 1."""


def resolve_asset_id(connection, wazuh_agent_id):
    if not wazuh_agent_id:
        return None
    row = connection.execute(
        "SELECT id FROM assets WHERE wazuh_agent_id = ?", (wazuh_agent_id,)
    ).fetchone()
    return row["id"] if row else None


def backfill_asset_links(connection, asset_id, wazuh_agent_id):
    """Refresh only exact-agent links and unambiguous legacy incidents."""
    connection.execute(
        "UPDATE alerts SET asset_id = NULL WHERE asset_id = ? AND (agent_id IS NULL OR agent_id <> ?)",
        (asset_id, wazuh_agent_id or ""),
    )
    if wazuh_agent_id:
        connection.execute(
            "UPDATE alerts SET asset_id = ? WHERE agent_id = ?", (asset_id, wazuh_agent_id)
        )
    connection.execute("""
        UPDATE incidents
           SET asset_id = (
               SELECT CASE WHEN COUNT(*) = COUNT(a.asset_id) AND COUNT(DISTINCT a.asset_id)=1
                           THEN MIN(a.asset_id) ELSE NULL END
               FROM case_alert_members ia JOIN alerts a ON a.id=ia.alert_id
               WHERE ia.incident_id=incidents.id)
         WHERE asset_id = ? OR EXISTS (
               SELECT 1 FROM case_alert_members ia JOIN alerts a ON a.id=ia.alert_id
               WHERE ia.incident_id=incidents.id AND a.asset_id=?)
    """, (asset_id, asset_id))


def observed_agent_context(connection):
    """Latest stored source identity, not a claim that an agent is online."""
    return [dict(row) for row in connection.execute("""WITH latest AS (
        SELECT agent_id,agent_name,agent_ip,event_timestamp,
               ROW_NUMBER() OVER (PARTITION BY agent_id
                   ORDER BY cdss_event_epoch(event_timestamp) DESC,id DESC) AS ordinal
        FROM alerts WHERE agent_id IS NOT NULL AND agent_id<>''
    )
    SELECT l.agent_id,l.agent_name,l.agent_ip,l.event_timestamp AS last_seen,
           a.id AS asset_id,a.asset_name,a.ip_address AS configured_ip,
           a.criticality,a.is_protected
    FROM latest l LEFT JOIN assets a ON a.wazuh_agent_id=l.agent_id
    WHERE l.ordinal=1 ORDER BY l.agent_id""")]
