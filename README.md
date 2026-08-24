# Cyber Incident Decision Support System (CDSS)

Implementation-focused PGD Cybersecurity project that converts read-only Wazuh
Indexer alerts into explainable incident decisions:

`alert → validated context → evidence-based classification → local knowledge → risk → advisory action`

The risk score is project-specific, not an official SIEM or MITRE score. Mapped
events combine normalized SIEM rule level (40%), CDSS Technique Risk Weight
(40%), and contextual recurrence (20%). Unmapped events use normalized SIEM
rule level (80%) and recurrence (20%); they never receive a fabricated technique
weight. Priority
bands are P1 critical (8–10), P2 high (6–7.99), P3 medium (3–5.99), and P4 low.
An ATT&CK tag is treated as context, not proof of compromise: routine successful
authentication is confidence-capped and does not escalate merely because it is
frequent, while failure/attack indicators allow the reviewed technique risk.

## Setup

Create a virtual environment, install `requirements.txt`, and copy `.env.example`
to `.env`. Never commit real Indexer credentials. Export the values from `.env`
in the terminal used to run CDSS.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Demonstration

Seed the defensive knowledge base, optionally import history, then start the
dashboard. The approved web entry point remains `run.py`. When realtime
collection is enabled, the app uses an ascending OpenSearch `search_after`
cursor saved in SQLite, preventing silent gaps while retaining deduplication.

```bash
python -m app.services.ingest --size 500 --order asc
python -m app.services.ingest --size 500 --order desc
python run.py
```

Open `http://127.0.0.1:5000`. On first run, create the administrator through
the setup page; later visits use the login page. Every user can securely update
their username or password from Profile settings. Administrators can create,
rename, reset, enable, disable, and assign roles to local accounts. The compact
account dropdown and navy/black/orange responsive dashboard keep these controls
separate from incident investigation. The analyst overview groups repeated
high/critical findings and summarizes 24-hour posture, endpoint exposure,
severity mix, and attack signals. Full searchable, paginated history lives on
the separate Incidents page. Every incident opens into a detail view
with scoring evidence and persisted defensive actions. Known ATT&CK techniques
use local technique-specific candidate actions. Existing defensive mappings are
labelled `project_defined` until exact authoritative references are verified.
Without ATT&CK, recognized Wazuh groups use explicit local categories; unknown
events remain `Unclassified Security Event` with conservative guidance.

Optional MITRE catalogue refresh:

```bash
python -m app.mitre.taxii_sync
```

## Security and limitations

- Indexer integration only performs GET/POST search requests; it never modifies Wazuh.
- SQLite and the Flask development server are appropriate for this lab prototype,
  not a multi-user production deployment.
- TLS verification should remain enabled outside a self-signed isolated lab.
- Multiple valid ATT&CK IDs are preserved relationally; Wazuh groups enrich them.
- Missing/unverified ATT&CK uses Wazuh-only risk without a fake technique score.
- SIEM redirects and unsafe loopback/link-local/reserved targets are blocked.
- Controlled attacks must only be performed against authorized lab systems.
- The app binds to loopback only, uses security headers, limits filter input,
  parameterizes database queries, and never displays or logs Indexer credentials.
- Passwords use scrypt hashing; state-changing forms use CSRF protection;
  sessions are HttpOnly/SameSite; `CDSS_HTTPS_ENABLED=true` enables Secure cookies,
  and role checks protect administration.
