# Cyber Incident Decision Support System (CDSS)

Implementation-focused PGD Cybersecurity project that converts read-only Wazuh
Indexer alerts into explainable incident decisions:

`alert → context → MITRE ATT&CK → CDSS risk score → priority → decision → action`

The risk score is a project-specific decision-support score, not an official
Wazuh score. It combines normalized Wazuh rule level (40%), MITRE technique base
risk (40%), and same-rule recurrence during the previous hour (20%). Priority
bands are P1 critical (8–10), P2 high (6–7.99), P3 medium (3–5.99), and P4 low.

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

Seed the defensive knowledge base, ingest a small read-only batch, then start the
dashboard. The approved web entry point remains `run.py`.

```bash
python -m app.services.ingest --size 20
python run.py
```

Open `http://127.0.0.1:5000`. The dashboard shows severity, priority, score,
reasoning, affected agent/source, MITRE ID, and defensive recommendations.

Optional MITRE catalogue refresh:

```bash
python -m app.mitre.taxii_sync
```

## Security and limitations

- Indexer integration only performs GET/POST search requests; it never modifies Wazuh.
- SQLite and the Flask development server are appropriate for this lab prototype,
  not a multi-user production deployment.
- TLS verification should remain enabled outside a self-signed isolated lab.
- Unknown MITRE techniques receive a neutral default risk and no invented advice.
- Controlled attacks must only be performed against authorized lab systems.
