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
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "risk": 9,
        "d3fend": "Process Analysis",
        "nist": "Analyze and contain",
        "cis": "Control 2",
        "recommendations": (
            ("Identify the interpreter, command line, script, user, and parent process.", "Analysis", 1),
            ("Restrict unapproved interpreters or scripts when malicious execution is confirmed.", "Containment", 2),
            ("Apply script allowlisting and retain process command-line audit logs.", "Prevention", 3),
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
    {
        "id": "T1565.001", "name": "Stored Data Manipulation", "tactic": "Impact",
        "risk": 9, "d3fend": "File Hashing / Database Activity Monitoring",
        "nist": "Analyze integrity impact and restore trusted data", "cis": "Controls 3 and 8",
        "recommendations": (
            ("Compare affected data with a trusted baseline and preserve integrity evidence.", "Analysis", 1),
            ("Restrict write access and restore validated data when unauthorized modification is confirmed.", "Containment", 2),
            ("Enable integrity monitoring and protected backups for the affected data store.", "Recovery", 3),
        ),
    },
    {
        "id": "T1087", "name": "Account Discovery", "tactic": "Discovery",
        "risk": 6, "d3fend": "Process Analysis / Command Auditing",
        "nist": "Correlate discovery with subsequent activity", "cis": "Controls 5 and 8",
        "recommendations": (
            ("Review the initiating process, command line, user, and parent process.", "Analysis", 1),
            ("Correlate account discovery with privilege escalation or lateral movement.", "Analysis", 2),
            ("Restrict unnecessary account-enumeration tools and audit privileged commands.", "Prevention", 3),
        ),
    },
    {
        "id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
        "risk": 8, "d3fend": "Network Traffic Analysis / File Analysis",
        "nist": "Contain transfer path and analyze payload", "cis": "Controls 12 and 13",
        "recommendations": (
            ("Identify the transferred file, hash, source host, destination host, and transfer mechanism.", "Analysis", 1),
            ("Quarantine the payload and restrict the confirmed malicious transfer path.", "Containment", 2),
            ("Hunt for the same hash and transfer pattern on peer systems.", "Eradication", 3),
        ),
    },
    {
        "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
        "risk": 9, "d3fend": "Network Traffic Analysis / Executable Allowlisting",
        "nist": "Analyze payload and contain ingress channel", "cis": "Controls 9, 10 and 13",
        "recommendations": (
            ("Collect the downloaded file hash, URL, process lineage, and network destination.", "Analysis", 1),
            ("Block the confirmed malicious source and isolate the endpoint if execution occurred.", "Containment", 2),
            ("Apply executable allowlisting and hunt for matching payload indicators.", "Eradication", 3),
        ),
    },
    {
        "id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access",
        "risk": 9, "d3fend": "Authentication Event Thresholding / Credential Hardening",
        "nist": "Contain source and protect affected identity", "cis": "Controls 5, 6 and 8",
        "recommendations": (
            ("Correlate failed attempts with any later successful login for the same account or source.", "Analysis", 1),
            ("Rate-limit or block the confirmed source and protect the targeted account.", "Containment", 2),
            ("Enforce MFA, lockout thresholds, and centralized authentication monitoring.", "Prevention", 3),
        ),
    },
    {
        "id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation / Defense Evasion",
        "risk": 8, "d3fend": "User Account Permissions / Process Analysis",
        "nist": "Validate and contain unauthorized elevation", "cis": "Controls 5 and 6",
        "recommendations": (
            ("Verify the sudo command, requesting user, target account, and authorization context.", "Analysis", 1),
            ("Terminate unauthorized elevation and revoke unnecessary sudo privileges.", "Containment", 2),
            ("Review sudoers policy, command logging, and privileged session controls.", "Prevention", 3),
        ),
    },
    {
        "id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
        "risk": 9, "d3fend": "Script Execution Analysis / Process Analysis",
        "nist": "Analyze script and contain malicious execution", "cis": "Controls 2, 8 and 10",
        "recommendations": (
            ("Review the full PowerShell command, script block, parent process, and user context.", "Analysis", 1),
            ("Isolate the endpoint when encoded or malicious execution is confirmed.", "Containment", 2),
            ("Enable script-block logging, constrained language mode, and approved-script controls.", "Prevention", 3),
        ),
    },
    {
        "id": "T1562.001", "name": "Impair Defenses", "tactic": "Defense Evasion",
        "risk": 10, "d3fend": "Security Configuration Monitoring / Process Analysis",
        "nist": "Restore defenses and contain affected endpoint", "cis": "Controls 4, 8 and 10",
        "recommendations": (
            ("Identify which security control changed, by whom, and through which process.", "Analysis", 1),
            ("Restore the affected defensive control and isolate the host if tampering is malicious.", "Containment", 2),
            ("Protect security tooling from unauthorized modification and alert on control stoppage.", "Prevention", 3),
        ),
    },
    {
        "id": "T1136", "name": "Create Account", "tactic": "Persistence",
        "risk": 8, "d3fend": "User Account Permissions / Account Monitoring",
        "nist": "Disable unauthorized identity and investigate creator", "cis": "Controls 5 and 6",
        "recommendations": (
            ("Validate the new account against an approved identity-management request.", "Analysis", 1),
            ("Disable unauthorized accounts and revoke associated sessions and credentials.", "Containment", 2),
            ("Audit the creator account and enforce account-provisioning approval controls.", "Eradication", 3),
        ),
    },
    {
        "id": "T1543.003", "name": "Windows Service", "tactic": "Persistence / Privilege Escalation",
        "risk": 8, "d3fend": "Service Binary Verification / Process Analysis",
        "nist": "Contain malicious service and preserve binary", "cis": "Controls 2, 4 and 10",
        "recommendations": (
            ("Inspect the service name, binary path, signer, creator, and start configuration.", "Analysis", 1),
            ("Disable confirmed malicious services and quarantine their binaries.", "Containment", 2),
            ("Baseline authorized services and monitor service-creation events.", "Prevention", 3),
        ),
    },
    {
        "id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion",
        "risk": 7, "d3fend": "Registry Key Configuration / Registry Analysis",
        "nist": "Analyze registry impact and restore baseline", "cis": "Controls 4 and 8",
        "recommendations": (
            ("Compare the modified key, previous value, process, and user with the trusted baseline.", "Analysis", 1),
            ("Restore unauthorized registry changes after preserving evidence.", "Eradication", 2),
            ("Restrict sensitive registry permissions and monitor persistence-related keys.", "Prevention", 3),
        ),
    },
    {
        "id": "T1070.004", "name": "File Deletion", "tactic": "Defense Evasion",
        "risk": 7, "d3fend": "File Analysis / File Carving",
        "nist": "Preserve evidence and assess deleted content", "cis": "Controls 3 and 8",
        "recommendations": (
            ("Identify the deleted path, deleting process, user, and related activity.", "Analysis", 1),
            ("Preserve filesystem and endpoint evidence before recovery attempts.", "Evidence", 2),
            ("Recover required files from a trusted backup and restrict unauthorized deletion.", "Recovery", 3),
        ),
    },
    {
        "id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution",
        "risk": 7, "d3fend": "Process Analysis / Command Auditing",
        "nist": "Analyze command and contain malicious execution", "cis": "Controls 2 and 8",
        "recommendations": (
            ("Review the command line, parent process, user, and subsequent child processes.", "Analysis", 1),
            ("Terminate malicious execution and isolate the host when impact is confirmed.", "Containment", 2),
            ("Restrict command-shell use and retain process-creation command-line logging.", "Prevention", 3),
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
                    INSERT INTO mitre_techniques
                        (technique_id, technique_name, tactic, source_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(technique_id) DO UPDATE SET
                        technique_name = excluded.technique_name,
                        tactic = excluded.tactic,
                        source_id = excluded.source_id
                """, (technique["id"], technique["name"], technique["tactic"], source_id))
                connection.execute("""
                    INSERT INTO knowledge_base
                        (technique_id, base_risk_score, d3fend_technique, nist_ir_guidance, cis_control)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(technique_id) DO UPDATE SET
                        base_risk_score = excluded.base_risk_score,
                        d3fend_technique = excluded.d3fend_technique,
                        nist_ir_guidance = excluded.nist_ir_guidance,
                        cis_control = excluded.cis_control,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    technique["id"], technique["risk"], technique["d3fend"],
                    technique["nist"], technique["cis"],
                ))

                knowledge_base_id = connection.execute(
                    "SELECT id FROM knowledge_base WHERE technique_id = ?",
                    (technique["id"],),
                ).fetchone()["id"]
                connection.execute(
                    "DELETE FROM recommendations WHERE knowledge_base_id = ?",
                    (knowledge_base_id,),
                )
                for action_text, response_phase, priority in technique["recommendations"]:
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
