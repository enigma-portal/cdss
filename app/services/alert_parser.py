"""Extract the CDSS-required fields from a raw Wazuh alert."""

from dataclasses import asdict, dataclass
from datetime import datetime
import ipaddress
import json

from app.services.classification import valid_mitre_ids


@dataclass(frozen=True)
class ParsedAlert:
    wazuh_alert_id: str | None
    event_timestamp: str
    rule_id: str
    rule_description: str | None
    rule_level: int | None
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    source_ip: str | None
    destination_ip: str | None
    mitre_ids: tuple[str, ...]
    rule_groups: tuple[str, ...]
    username: str | None
    raw_alert: str

    def as_database_record(self):
        """Return names matching the columns in the alerts database table."""
        record = asdict(self)
        mitre_ids = record.pop("mitre_ids")
        groups = record.pop("rule_groups")
        record["mitre_id"] = mitre_ids[0] if mitre_ids else None
        record["wazuh_mitre_ids"] = json.dumps(mitre_ids, separators=(",", ":"))
        record["rule_groups"] = json.dumps(groups, separators=(",", ":"))
        return record


def _as_mitre_ids(value):
    if isinstance(value, str):
        return valid_mitre_ids((value,))
    if isinstance(value, list):
        return valid_mitre_ids(value)
    return ()


def _text(value, maximum, field, required=False):
    if value is None:
        if required:
            raise ValueError(f"{field} is required.")
        return None
    if not isinstance(value, (str, int)):
        raise ValueError(f"{field} has an invalid type.")
    result = str(value).strip()
    if required and not result:
        raise ValueError(f"{field} is required.")
    if len(result) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters.")
    return result or None


def _ip(value, field):
    value = _text(value, 45, field)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError(f"{field} is not a valid IP address.") from error


def _groups(value):
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValueError("rule.groups must be a list when present.")
    result = []
    for item in value:
        group = _text(item, 64, "rule.groups item")
        if group and group not in result:
            result.append(group)
    return tuple(result[:64])


def parse_alert(raw_alert):
    """Parse a Wazuh alert dictionary into a stable CDSS alert structure."""
    if not isinstance(raw_alert, dict):
        raise TypeError("A raw Wazuh alert must be a dictionary.")

    rule = raw_alert.get("rule") or {}
    agent = raw_alert.get("agent") or {}
    data = raw_alert.get("data") or {}
    if not all(isinstance(item, dict) for item in (rule, agent, data)):
        raise ValueError("Wazuh rule, agent, and data fields must be objects when present.")
    mitre = rule.get("mitre") or {}
    if not isinstance(mitre, dict):
        raise ValueError("rule.mitre must be an object when present.")

    event_timestamp = raw_alert.get("timestamp")
    rule_id = rule.get("id")
    if not event_timestamp or rule_id is None:
        raise ValueError("A Wazuh alert needs both timestamp and rule.id.")
    event_timestamp = _text(event_timestamp, 64, "timestamp", required=True)
    try:
        datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Wazuh timestamp must be ISO-8601.") from error

    level = rule.get("level")
    try:
        rule_level = int(level) if level is not None else None
    except (TypeError, ValueError) as error:
        raise ValueError("Wazuh rule.level must be a number when present.") from error
    if rule_level is not None and not 0 <= rule_level <= 16:
        raise ValueError("Wazuh rule.level must be between 0 and 16.")

    username = data.get("srcuser") or data.get("dstuser") or data.get("user")

    return ParsedAlert(
        wazuh_alert_id=_text(raw_alert.get("id"), 256, "id"),
        event_timestamp=event_timestamp,
        rule_id=_text(rule_id, 64, "rule.id", required=True),
        rule_description=_text(rule.get("description"), 2048, "rule.description"),
        rule_level=rule_level,
        agent_id=_text(agent.get("id"), 64, "agent.id"),
        agent_name=_text(agent.get("name"), 255, "agent.name"),
        agent_ip=_ip(agent.get("ip"), "agent.ip"),
        source_ip=_ip(data.get("srcip") or raw_alert.get("srcip"), "source IP"),
        destination_ip=_ip(data.get("dstip") or raw_alert.get("dstip"), "destination IP"),
        mitre_ids=_as_mitre_ids(mitre.get("id")),
        rule_groups=_groups(rule.get("groups")),
        username=_text(username, 255, "username"),
        raw_alert=json.dumps(raw_alert, separators=(",", ":"), ensure_ascii=False),
    )
