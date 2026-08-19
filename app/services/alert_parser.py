"""Extract the CDSS-required fields from a raw Wazuh alert."""

from dataclasses import asdict, dataclass
import json


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
    raw_alert: str

    def as_database_record(self):
        """Return names matching the columns in the alerts database table."""
        record = asdict(self)
        mitre_ids = record.pop("mitre_ids")
        record["mitre_id"] = mitre_ids[0] if mitre_ids else None
        return record


def _as_mitre_ids(value):
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def parse_alert(raw_alert):
    """Parse a Wazuh alert dictionary into a stable CDSS alert structure."""
    if not isinstance(raw_alert, dict):
        raise TypeError("A raw Wazuh alert must be a dictionary.")

    rule = raw_alert.get("rule") or {}
    agent = raw_alert.get("agent") or {}
    data = raw_alert.get("data") or {}
    mitre = rule.get("mitre") or {}

    event_timestamp = raw_alert.get("timestamp")
    rule_id = rule.get("id")
    if not event_timestamp or rule_id is None:
        raise ValueError("A Wazuh alert needs both timestamp and rule.id.")

    level = rule.get("level")
    try:
        rule_level = int(level) if level is not None else None
    except (TypeError, ValueError) as error:
        raise ValueError("Wazuh rule.level must be a number when present.") from error

    return ParsedAlert(
        wazuh_alert_id=raw_alert.get("id"),
        event_timestamp=event_timestamp,
        rule_id=str(rule_id),
        rule_description=rule.get("description"),
        rule_level=rule_level,
        agent_id=agent.get("id"),
        agent_name=agent.get("name"),
        agent_ip=agent.get("ip"),
        source_ip=data.get("srcip") or raw_alert.get("srcip"),
        destination_ip=data.get("dstip") or raw_alert.get("dstip"),
        mitre_ids=_as_mitre_ids(mitre.get("id")),
        raw_alert=json.dumps(raw_alert, separators=(",", ":")),
    )
