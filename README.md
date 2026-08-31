# Cyber Incident Decision Support System (CDSS)

## Overview

CDSS is a postgraduate cybersecurity prototype that integrates with Wazuh SIEM
and uses MITRE ATT&CK context, where available, to support security analysts
with incident prioritization, contextual risk assessment, and explainable
advisory recommendations.

CDSS complements Wazuh rather than replacing the SIEM. Wazuh remains the
detection and event source, while CDSS provides project-defined decision
support. Missing security context is not fabricated, and the system does not
claim autonomous intelligence or response.

## High-Level Architecture

`Wazuh SIEM → CDSS Processing Engine → Risk Assessment → Recommendation Engine → Dashboard`

## Core Technologies

- Python
- Flask
- SQLite
- Wazuh
- MITRE ATT&CK

## Basic Setup

1. Create a Python virtual environment:

   ```bash
   python -m venv venv
   ```

2. Activate the environment.

   Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

   Linux or macOS:

   ```bash
   source venv/bin/activate
   ```

3. Install the required packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and configure the required environment
   variables with authorized lab values. Do not commit credentials or secrets.
5. Start the application:

   ```bash
   python run.py
   ```

6. Open `http://127.0.0.1:5000` and complete the first-run administrator setup
   if required.

## Academic / Prototype Scope

CDSS is a cybersecurity decision-support prototype intended for authorized
laboratory and testing environments. Its contextual risk score is
project-defined, and its recommendations are advisory. CDSS does not
automatically execute containment or remediation actions.
