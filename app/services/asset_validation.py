"""Deterministic Phase 1 asset catalogue and validation."""

import ipaddress
import re


ASSET_CATALOGUE = {
    "Endpoint": {
        "roles": ["End User Workstation", "Administrator Workstation", "Developer Workstation", "Other"],
        "os": {"Windows": ["Windows 10", "Windows 11", "Other Windows"],
               "macOS": ["macOS", "Other macOS"],
               "Linux": ["Ubuntu", "Debian", "Red Hat Enterprise Linux", "Other Linux"],
               "Other": ["Other"]},
    },
    "Server": {
        "roles": ["Domain Controller", "Database Server", "Application Server", "Web Server", "File Server", "Authentication Server", "Other"],
        "os": {"Windows Server": ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Other Windows Server"],
               "Linux": ["Ubuntu Server", "Debian", "Red Hat Enterprise Linux", "Other Linux"],
               "Unix": ["Other Unix"], "Other": ["Other"]},
    },
    "Network Device": {
        "roles": ["Firewall", "Router", "Switch", "VPN Gateway", "WAF", "Other"],
        "os": {"Network OS": ["Cisco IOS", "Junos", "FortiOS", "PAN-OS", "Other Network OS"],
               "Other": ["Other"], "N/A": ["N/A"]},
    },
    "Security Appliance": {
        "roles": ["SIEM", "IDS/IPS", "PAM", "Vulnerability Scanner", "Other"],
        "os": {"Appliance OS": ["Vendor Appliance OS", "Other Appliance OS"],
               "Linux": ["Ubuntu Server", "Red Hat Enterprise Linux", "Other Linux"],
               "Other": ["Other"], "N/A": ["N/A"]},
    },
    "Cloud Asset": {
        "roles": ["Virtual Machine", "Container", "Managed Database", "Object Storage", "Serverless", "Other"],
        "os_by_role": {
            "Virtual Machine": {"Windows Server": ["Windows Server 2019", "Windows Server 2022", "Other Windows Server"], "Linux": ["Ubuntu Server", "Debian", "Red Hat Enterprise Linux", "Other Linux"], "Other": ["Other"]},
            "Container": {"Linux": ["Linux Container", "Other Linux"], "Other": ["Other"]},
            "Managed Database": {"N/A": ["N/A"]}, "Object Storage": {"N/A": ["N/A"]},
            "Serverless": {"N/A": ["N/A"]}, "Other": {"Other": ["Other"], "N/A": ["N/A"]},
        },
    },
    "Other": {"roles": ["Other"], "os": {"Other": ["Other"], "N/A": ["N/A"]}},
}
CRITICALITIES = ("low", "medium", "high", "critical")
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def allowed_os(asset_type, asset_role):
    entry = ASSET_CATALOGUE.get(asset_type, {})
    return entry.get("os_by_role", {}).get(asset_role, entry.get("os", {}))


def validate_asset(form):
    """Return normalized values or raise ValueError with a safe user message."""
    value = lambda name: (form.get(name) or "").strip()
    data = {name: value(name) for name in (
        "asset_name", "asset_type", "asset_role", "os_family", "os_name",
        "ip_address", "wazuh_agent_id", "criticality", "description",
    )}
    if not data["asset_name"] or len(data["asset_name"]) > 255:
        raise ValueError("Asset name is required and must be at most 255 characters.")
    catalogue = ASSET_CATALOGUE.get(data["asset_type"])
    if not catalogue or data["asset_role"] not in catalogue["roles"]:
        raise ValueError("Select a valid asset type and role combination.")
    os_options = allowed_os(data["asset_type"], data["asset_role"])
    if data["os_family"] not in os_options or data["os_name"] not in os_options[data["os_family"]]:
        raise ValueError("Select an operating system valid for this asset type and role.")
    if data["criticality"] not in CRITICALITIES:
        raise ValueError("Criticality must be explicitly selected.")
    if data["ip_address"]:
        try:
            ipaddress.ip_address(data["ip_address"])
        except ValueError as error:
            raise ValueError("Enter a valid IPv4 or IPv6 address, or leave it blank.") from error
    if data["wazuh_agent_id"] and not AGENT_ID_RE.fullmatch(data["wazuh_agent_id"]):
        raise ValueError("Wazuh agent ID may contain letters, numbers, dots, dashes, or underscores.")
    if len(data["description"]) > 2000:
        raise ValueError("Description must be at most 2000 characters.")
    data["ip_address"] = data["ip_address"] or None
    data["wazuh_agent_id"] = data["wazuh_agent_id"] or None
    data["description"] = data["description"] or None
    data["is_protected"] = 1 if form.get("is_protected") in {"1", "on", "true"} else 0
    return data
