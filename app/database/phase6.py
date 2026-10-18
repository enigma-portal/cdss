"""Add contextual assessment history without converting legacy numeric scores."""


def migrate_risk_assessments(connection):
    connection.execute('''CREATE UNIQUE INDEX IF NOT EXISTS investigation_incident_pair
        ON investigations(id,incident_id)''')
    connection.execute('''CREATE TABLE IF NOT EXISTS risk_assessments (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        investigation_id INTEGER,
        assessment_stage TEXT NOT NULL CHECK(assessment_stage IN ('initial','contextual')),
        evidence_state TEXT CHECK(evidence_state IN ('T1','T2','T3','T4','Inconclusive')),
        asset_criticality_snapshot TEXT CHECK(asset_criticality_snapshot IN ('low','medium','high','critical')),
        risk_level TEXT CHECK(risk_level IN ('low','medium','high','critical')),
        confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
        rationale TEXT NOT NULL,
        assessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        methodology_version TEXT NOT NULL,
        inputs_snapshot TEXT NOT NULL CHECK(json_valid(inputs_snapshot)),
        FOREIGN KEY(investigation_id,incident_id) REFERENCES investigations(id,incident_id) ON DELETE CASCADE,
        UNIQUE(investigation_id,assessment_stage,methodology_version),
        CHECK((assessment_stage='initial' AND evidence_state IS NULL AND risk_level IS NULL)
           OR (assessment_stage='contextual' AND investigation_id IS NOT NULL AND evidence_state IS NOT NULL)),
        CHECK(risk_level IS NULL OR (asset_criticality_snapshot IS NOT NULL
              AND evidence_state IN ('T1','T2','T3','T4'))))''')
    connection.execute('''CREATE INDEX IF NOT EXISTS assessment_incident_history
        ON risk_assessments(incident_id,assessment_stage,id)''')
