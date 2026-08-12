"""Retrieve curated CDSS response actions for an incident."""


def get_recommendations(connection, technique_id, risk_score):
    """Return active actions whose configured risk range includes this incident."""
    if not technique_id:
        return []
    return connection.execute("""
        SELECT recommendations.action_text, recommendations.response_phase,
               recommendations.priority
        FROM recommendations
        JOIN knowledge_base ON knowledge_base.id = recommendations.knowledge_base_id
        WHERE knowledge_base.technique_id = ?
          AND recommendations.is_active = 1
          AND ? BETWEEN recommendations.minimum_risk_score AND recommendations.maximum_risk_score
        ORDER BY recommendations.priority, recommendations.id
    """, (technique_id, risk_score)).fetchall()
