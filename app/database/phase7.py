"""Separate contextual guidance and append-only human decisions from legacy rows."""


def migrate_contextual_guidance(connection):
    connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS assessment_incident_pair ON risk_assessments(id,incident_id)')
    connection.execute('''CREATE TABLE IF NOT EXISTS contextual_recommendations (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL,
        assessment_id INTEGER NOT NULL,
        rule_key TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('Investigation','Containment','Remediation','Monitoring')),
        priority INTEGER NOT NULL CHECK(priority>0),
        action_text TEXT NOT NULL,
        source_reference TEXT NOT NULL,
        rationale TEXT NOT NULL,
        evidence_snapshot TEXT NOT NULL CHECK(json_valid(evidence_snapshot)),
        methodology_version TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(assessment_id,incident_id) REFERENCES risk_assessments(id,incident_id) ON DELETE CASCADE,
        UNIQUE(assessment_id,methodology_version,rule_key),
        UNIQUE(id,incident_id,assessment_id))''')
    connection.execute('''CREATE TABLE IF NOT EXISTS analyst_decisions (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL,
        assessment_id INTEGER NOT NULL,
        incident_recommendation_id INTEGER,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        analyst_name_snapshot TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('accept','reject','further_investigation_required')),
        comments TEXT NOT NULL DEFAULT '' CHECK(length(comments)<=4000),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(assessment_id,incident_id) REFERENCES risk_assessments(id,incident_id) ON DELETE CASCADE,
        FOREIGN KEY(incident_recommendation_id,incident_id,assessment_id)
            REFERENCES contextual_recommendations(id,incident_id,assessment_id) ON DELETE CASCADE)''')
    connection.execute('CREATE INDEX IF NOT EXISTS decisions_incident_history ON analyst_decisions(incident_id,id)')
