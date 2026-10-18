"""Synchronize Enterprise ATT&CK techniques from MITRE's TAXII 2.1 service."""

import json
import hashlib
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.database import get_db_connection, initialize_database
from app.services.classification import valid_mitre_ids

TAXII_API_ROOT = "https://attack-taxii.mitre.org/api/v21"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
OFFICIAL_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


class OfficialStixClient:
    """Import the complete official Enterprise bundle, online or from a local copy."""

    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.transport = "local_stix" if path else "official_stix"
        self.source_url = OFFICIAL_STIX_URL
        self.sha256 = None

    def fetch_enterprise_objects(self):
        try:
            if self.path:
                payload = self.path.read_bytes()
            else:
                with urlopen(OFFICIAL_STIX_URL, timeout=45,
                             context=ssl.create_default_context(cafile=os.getenv('MITRE_TAXII_CA_BUNDLE') or None)) as response:
                    payload = response.read(100 * 1024 * 1024 + 1)
            if len(payload) > 100 * 1024 * 1024:
                raise TaxiiSyncError("ATT&CK bundle exceeds the import size limit.")
            bundle = json.loads(payload)
            if (not isinstance(bundle, dict) or bundle.get('type') != 'bundle'
                    or not isinstance(bundle.get('objects'), list)
                    or not all(isinstance(item, dict) for item in bundle['objects'])):
                raise TaxiiSyncError("Invalid ATT&CK STIX bundle.")
            if not extract_techniques(bundle['objects']):
                raise TaxiiSyncError("Bundle has no active Enterprise ATT&CK techniques.")
            self.sha256 = hashlib.sha256(payload).hexdigest()
            return bundle['objects']
        except (OSError, ValueError) as error:
            raise TaxiiSyncError("Could not load the official Enterprise ATT&CK STIX bundle.") from error


class TaxiiSyncError(RuntimeError):
    """Raised when ATT&CK TAXII content cannot be retrieved or understood."""


class AttackTaxiiClient:
    """Small read-only client for the official ATT&CK TAXII 2.1 API."""

    def __init__(self, api_root=TAXII_API_ROOT, timeout_seconds=30, ca_bundle=None):
        self.api_root = api_root.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl.create_default_context(cafile=ca_bundle)

    @classmethod
    def from_environment(cls):
        """Use a custom trusted CA bundle only when the local network requires it."""
        return cls(ca_bundle=os.getenv("MITRE_TAXII_CA_BUNDLE") or None)

    def _get_json(self, path):
        request = Request(
            f"{self.api_root}{path}",
            headers={"Accept": TAXII_ACCEPT},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise TaxiiSyncError(f"MITRE TAXII returned HTTP {error.code}.") from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            if isinstance(getattr(error, "reason", None), ssl.SSLCertVerificationError):
                raise TaxiiSyncError(
                    "MITRE TAXII certificate verification failed. Configure MITRE_TAXII_CA_BUNDLE "
                    "with your trusted CA certificate path."
                ) from error
            raise TaxiiSyncError("Could not retrieve valid data from MITRE ATT&CK TAXII.") from error

    def fetch_enterprise_objects(self):
        """Return all STIX objects in the Enterprise ATT&CK collection."""
        collections = self._get_json("/collections/").get("collections", [])
        enterprise = next(
            (item for item in collections if item.get("title") == "Enterprise ATT&CK"),
            None,
        )
        if not enterprise or not enterprise.get("id"):
            raise TaxiiSyncError("The Enterprise ATT&CK collection was not found.")

        path = f"/collections/{enterprise['id']}/objects/?{urlencode({'limit': 1000})}"
        objects = []
        while path:
            page = self._get_json(path)
            objects.extend(page.get("objects", []))
            next_token = page.get("next") if page.get("more") else None
            path = (
                f"/collections/{enterprise['id']}/objects/?{urlencode({'limit': 1000, 'next': next_token})}"
                if next_token else None
            )
        return objects


def _attack_id(stix_object):
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _tactics(stix_object, official_names=None):
    phases = stix_object.get("kill_chain_phases", [])
    names = [
        (official_names or {}).get(phase["phase_name"], phase["phase_name"].replace("-", " ").title())
        for phase in phases
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]
    return " / ".join(dict.fromkeys(names)) or None


def extract_techniques(stix_objects):
    """Extract active Enterprise attack-pattern STIX objects for the CDSS schema."""
    techniques = []
    official_names = {item['x_mitre_shortname']: item['name'] for item in stix_objects
                      if item.get('type') == 'x-mitre-tactic'
                      and item.get('x_mitre_shortname') and item.get('name')}
    for item in stix_objects:
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        if "enterprise-attack" not in item.get("x_mitre_domains", []):
            continue
        identifiers = valid_mitre_ids((_attack_id(item),))
        if identifiers:
            techniques.append({
                "technique_id": identifiers[0],
                "technique_name": item.get("name", identifiers[0]),
                "tactic": _tactics(item, official_names),
                "description": item.get("description"),
            })
    return techniques


def sync_enterprise_attack(client=None):
    """Update the local technique catalogue while preserving CDSS knowledge-base data."""
    if client is None:
        client = AttackTaxiiClient.from_environment()
        try:
            objects = client.fetch_enterprise_objects()
        except TaxiiSyncError:
            client = OfficialStixClient(os.getenv('MITRE_ENTERPRISE_STIX_FILE') or None)
            objects = client.fetch_enterprise_objects()
    else:
        objects = client.fetch_enterprise_objects()
    techniques = extract_techniques(objects)
    if not techniques:
        raise TaxiiSyncError("No active Enterprise ATT&CK techniques were returned.")
    initialize_database()
    connection = get_db_connection()
    try:
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS attack_catalogue_imports (
                id INTEGER PRIMARY KEY, transport TEXT NOT NULL, source_url TEXT NOT NULL,
                sha256 TEXT, technique_count INTEGER NOT NULL,
                imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
            columns = {row['name'] for row in connection.execute('PRAGMA table_info(mitre_techniques)')}
            if 'catalogue_import_id' not in columns:
                connection.execute('ALTER TABLE mitre_techniques ADD COLUMN catalogue_import_id INTEGER REFERENCES attack_catalogue_imports(id)')
            # catalogue_source=taxii is the legacy synchronizer ownership marker;
            # the import relation records the actual TAXII/STIX transport.
            is_stix = isinstance(client, OfficialStixClient)
            import_id = connection.execute("""INSERT INTO attack_catalogue_imports
                (transport,source_url,sha256,technique_count) VALUES(?,?,?,?)""",
                (client.transport if is_stix else 'taxii',
                 client.source_url if is_stix else TAXII_API_ROOT,
                 client.sha256 if is_stix else None, len(techniques))).lastrowid
            connection.execute("""
                INSERT INTO reference_sources (source_name, source_url, purpose)
                VALUES (?, ?, ?)
                ON CONFLICT(source_name) DO UPDATE SET source_url = excluded.source_url
            """, (
                "MITRE ATT&CK", "https://attack.mitre.org/",
                "Attack technique and tactic classification.",
            ))
            source_id = connection.execute(
                "SELECT id FROM reference_sources WHERE source_name = ?", ("MITRE ATT&CK",)
            ).fetchone()["id"]
            for technique in techniques:
                connection.execute("""
                    INSERT INTO mitre_techniques
                        (technique_id, technique_name, tactic, description, source_id,
                         catalogue_source, catalogue_synced_at, catalogue_import_id)
                    VALUES (?, ?, ?, ?, ?, 'taxii', CURRENT_TIMESTAMP, ?)
                    ON CONFLICT(technique_id) DO UPDATE SET
                        technique_name = excluded.technique_name,
                        tactic = excluded.tactic,
                        description = excluded.description,
                        source_id = excluded.source_id,
                        catalogue_source = excluded.catalogue_source,
                        catalogue_synced_at = excluded.catalogue_synced_at,
                        catalogue_import_id = excluded.catalogue_import_id
                """, (
                    technique["technique_id"], technique["technique_name"],
                    technique["tactic"], technique["description"], source_id, import_id,
                ))
    finally:
        connection.close()
    return len(techniques)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Synchronize the full Enterprise ATT&CK catalogue.')
    parser.add_argument('--stix-file', help='Local copy of the official Enterprise STIX bundle')
    parser.add_argument('--official-stix', action='store_true', help='Bootstrap directly from the official MITRE STIX repository')
    args = parser.parse_args()
    client = OfficialStixClient(args.stix_file) if args.stix_file or args.official_stix else None
    count = sync_enterprise_attack(client)
    print(f"Synchronized {count} active Enterprise ATT&CK techniques.")
