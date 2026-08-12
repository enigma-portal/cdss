"""Read raw JSON alerts written by Wazuh."""

import json
from pathlib import Path


class AlertCollectionError(ValueError):
    """Raised when an alerts.json file cannot be read as JSON lines."""


def collect_alerts(alerts_file, limit=None):
    """Return raw Wazuh alerts from a JSON-lines alerts.json file.

    ``limit`` is useful during development so only the newest/sample number of
    alerts is passed into the rest of the CDSS pipeline.
    """
    path = Path(alerts_file)
    if not path.is_file():
        raise FileNotFoundError(f"Wazuh alerts file was not found: {path}")

    alerts = []
    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError as error:
                raise AlertCollectionError(
                    f"Invalid JSON alert on line {line_number} in {path}."
                ) from error
            if not isinstance(alert, dict):
                raise AlertCollectionError(
                    f"Alert on line {line_number} in {path} is not a JSON object."
                )
            alerts.append(alert)
            if limit is not None and len(alerts) >= limit:
                break
    return alerts
