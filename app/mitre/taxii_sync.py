"""Synchronize Enterprise ATT&CK techniques from MITRE's TAXII 2.1 service."""

import json
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.database import get_db_connection, initialize_database

TAXII_API_ROOT = "https://attack-taxii.mitre.org/api/v21"
TAXII_ACCEPT = "application/taxii+json;version=2.1"


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


def _tactics(stix_object):
    phases = stix_object.get("kill_chain_phases", [])
    names = [
        phase["phase_name"].replace("-", " ").title()
        for phase in phases
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]
    return " / ".join(dict.fromkeys(names)) or None


def extract_techniques(stix_objects):
    """Extract active Enterprise attack-pattern STIX objects for the CDSS schema."""
    techniques = []
    for item in stix_objects:
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        if "enterprise-attack" not in item.get("x_mitre_domains", []):
            continue
        technique_id = _attack_id(item)
        if technique_id:
            techniques.append({
                "technique_id": technique_id,
                "technique_name": item.get("name", technique_id),
                "tactic": _tactics(item),
                "description": item.get("description"),
            })
    return techniques


def sync_enterprise_attack(client=None):
    """Update the local technique catalogue while preserving CDSS knowledge-base data."""
    client = client or AttackTaxiiClient.from_environment()
    techniques = extract_techniques(client.fetch_enterprise_objects())
    initialize_database()
    connection = get_db_connection()
    try:
        with connection:
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
                        (technique_id, technique_name, tactic, description, source_id)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(technique_id) DO UPDATE SET
                        technique_name = excluded.technique_name,
                        tactic = excluded.tactic,
                        description = excluded.description,
                        source_id = excluded.source_id
                """, (
                    technique["technique_id"], technique["technique_name"],
                    technique["tactic"], technique["description"], source_id,
                ))
    finally:
        connection.close()
    return len(techniques)


if __name__ == "__main__":
    count = sync_enterprise_attack()
    print(f"Synchronized {count} active Enterprise ATT&CK techniques.")
