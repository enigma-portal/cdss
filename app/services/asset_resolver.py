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
           SET asset_id = (SELECT alerts.asset_id FROM alerts WHERE alerts.id = incidents.alert_id)
         WHERE alert_id IS NOT NULL
           AND (asset_id = ? OR EXISTS (
               SELECT 1 FROM alerts WHERE alerts.id = incidents.alert_id AND alerts.asset_id = ?
           ))
    """, (asset_id, asset_id))
