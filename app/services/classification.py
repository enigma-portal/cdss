"""Deterministic evidence-based alert classification."""

import re


MITRE_ID_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")

# Project-defined fallback mappings. These keys are limited to Wazuh groups
# observed in the project's alert fixtures/lab data; they are not MITRE claims.
WAZUH_GROUP_CATEGORIES = {
    "authentication_failed": "Authentication Failure",
    "authentication_success": "Authentication Activity",
    "sshd": "SSH Activity",
    "syscheck": "File Integrity Event",
    "rootcheck": "Host Security Finding",
    "malware": "Malware Detection",
}


def valid_mitre_ids(values):
    """Return unique, normalized ATT&CK technique IDs in source order."""
    seen = set()
    result = []
    for value in values or ():
        if not isinstance(value, str):
            continue
        technique_id = value.strip().upper()
        if MITRE_ID_PATTERN.fullmatch(technique_id) and technique_id not in seen:
            seen.add(technique_id)
            result.append(technique_id)
    return tuple(result)


def recognized_groups(groups):
    """Return normalized Wazuh groups that have explicit local mappings."""
    result = []
    for group in groups or ():
        if isinstance(group, str):
            normalized = group.strip().lower()
            if normalized in WAZUH_GROUP_CATEGORIES and normalized not in result:
                result.append(normalized)
    return tuple(result)


def classify(mitre_ids, groups):
    """Return classification source, label, and supporting context."""
    techniques = valid_mitre_ids(mitre_ids)
    known_groups = recognized_groups(groups)
    group_context = tuple(WAZUH_GROUP_CATEGORIES[group] for group in known_groups)
    if techniques:
        return {
            "source": "MITRE",
            "label": " / ".join(techniques),
            "context": group_context,
            "mitre_ids": techniques,
            "recognized_groups": known_groups,
        }
    if known_groups:
        return {
            "source": "WAZUH_GROUP",
            "label": group_context[0],
            "context": group_context,
            "mitre_ids": (),
            "recognized_groups": known_groups,
        }
    return {
        "source": "UNCLASSIFIED",
        "label": "Unclassified Security Event",
        "context": (),
        "mitre_ids": (),
        "recognized_groups": (),
    }
