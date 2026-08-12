"""Starter reference data for the CDSS knowledge base.

Run with: python -m app.database.seed
"""

from app.database import get_db_connection, initialize_database


REFERENCE_SOURCES = (
    ("Wazuh Documentation", "Alert structure and rule-level information."),
    ("MITRE ATT&CK", "Attack technique and tactic classification."),
    ("MITRE D3FEND", "Defensive countermeasure mapping."),
    ("NIST SP 800-61", "Incident-response guidance."),
    ("CIS Controls v8", "Preventive security-control guidance."),
)


TECHNIQUES = (
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "risk": 9,
        "d3fend": "Authentication Monitoring / Credential Hardening",
        "nist": "Contain and reset credentials",
        "cis": "Control 6",
        "recommendations": (
            ("Enable multi-factor authentication.", "Containment", 1),
            ("Lock the suspicious account and investigate failed login attempts.", "Containment", 2),
        ),
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter (PowerShell)",
        "tactic": "Execution",
        "risk": 9,
        "d3fend": "Process Analysis",
        "nist": "Analyze and contain",
        "cis": "Control 2",
        "recommendations": (
            ("Restrict PowerShell to approved administrative use.", "Containment", 1),
            ("Investigate the executed scripts and their parent process.", "Analysis", 2),
        ),
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "risk": 10,
        "d3fend": "Credential Hardening",
        "nist": "Contain affected system",
        "cis": "Control 5",
        "recommendations": (
            ("Isolate the affected host from the network.", "Containment", 1),
            ("Reset potentially compromised credentials.", "Recovery", 2),
        ),
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation",
        "risk": 10,
        "d3fend": "User Account Permissions",
        "nist": "Credential recovery",
        "cis": "Control 6",
        "recommendations": (
            ("Disable the compromised account.", "Containment", 1),
            ("Review the account's login history and active sessions.", "Analysis", 2),
        ),
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation / Defense Evasion",
        "risk": 9,
        "d3fend": "System Configuration Hardening",
        "nist": "Eradication",
        "cis": "Control 4",
        "recommendations": (
            ("Remove the unauthorized elevated access.", "Containment", 1),
            ("Audit privilege assignments and elevation settings.", "Eradication", 2),
        ),
    },
)


def seed_knowledge_base():
    """Add the agreed starter mappings without duplicating existing records."""
    initialize_database()
    connection = get_db_connection()
    try:
        with connection:
            for source_name, purpose in REFERENCE_SOURCES:
                connection.execute(
                    "INSERT OR IGNORE INTO reference_sources (source_name, purpose) VALUES (?, ?)",
                    (source_name, purpose),
                )

            source_id = connection.execute(
                "SELECT id FROM reference_sources WHERE source_name = ?",
                ("MITRE ATT&CK",),
            ).fetchone()["id"]

            for technique in TECHNIQUES:
                connection.execute("""
                    INSERT OR IGNORE INTO mitre_techniques
                        (technique_id, technique_name, tactic, source_id)
                    VALUES (?, ?, ?, ?)
                """, (technique["id"], technique["name"], technique["tactic"], source_id))
                connection.execute("""
                    INSERT OR IGNORE INTO knowledge_base
                        (technique_id, base_risk_score, d3fend_technique, nist_ir_guidance, cis_control)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    technique["id"], technique["risk"], technique["d3fend"],
                    technique["nist"], technique["cis"],
                ))

                knowledge_base_id = connection.execute(
                    "SELECT id FROM knowledge_base WHERE technique_id = ?",
                    (technique["id"],),
                ).fetchone()["id"]
                for action_text, response_phase, priority in technique["recommendations"]:
                    exists = connection.execute("""
                        SELECT 1 FROM recommendations
                        WHERE knowledge_base_id = ? AND action_text = ?
                    """, (knowledge_base_id, action_text)).fetchone()
                    if not exists:
                        connection.execute("""
                            INSERT INTO recommendations
                                (knowledge_base_id, action_text, response_phase, priority)
                            VALUES (?, ?, ?, ?)
                        """, (knowledge_base_id, action_text, response_phase, priority))
    finally:
        connection.close()


if __name__ == "__main__":
    seed_knowledge_base()
    print("CDSS starter knowledge base is ready.")
