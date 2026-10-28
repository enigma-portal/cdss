"""One analyst-facing collection status for connector cards and the global banner.

The stored last_success_at is a successful SIEM contact: both a manual connection
test and a poll can update it. Do not describe it as collection-only telemetry.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from app.time_utils import parse_timestamp


LABELS = {
    'disabled': 'SIEM alert collection disabled',
    'active': 'SIEM alert collection active',
    'partial': 'SIEM collection partial — source documents need review',
    'failed': 'SIEM unavailable — alert collection interrupted',
    'unknown': 'SIEM alert collection status unknown',
    'stale': 'SIEM alert collection stale',
}
PRECEDENCE = ('failed', 'partial', 'unknown', 'stale', 'active')


@dataclass(frozen=True)
class CollectionStatus:
    state: str
    label: str
    last_success_at: datetime | None = None
    enabled_count: int = 0


def _utc_timestamp(value):
    return parse_timestamp(value, sqlite_utc=True)


def _interval_seconds(value):
    try:
        interval = int(value)
    except (TypeError, ValueError):
        return 30
    return interval if 10 <= interval <= 3600 else 30


def connector_collection_status(row, poll_interval_seconds=30, *, now=None,
                                polling_enabled=True):
    """Fail closed: enabled alone or a historical success never means active.

    A successful contact older than three configured polling intervals (minimum
    60 seconds) is stale. The grace covers ordinary scheduling and short polls;
    it is a UI freshness threshold, not an ingestion or risk rule.
    """
    enabled = bool(row['is_enabled']) and polling_enabled
    if not enabled:
        state = 'disabled'
    elif row['status'] == 'error':
        state = 'failed'
    elif row['status'] not in ('connected','partial'):
        state = 'unknown'
    else:
        current = parse_timestamp(now) if now is not None else datetime.now(timezone.utc)
        success = _utc_timestamp(row['last_success_at'])
        age = (current - success).total_seconds() if success and current else None
        if age is None or age < 0:
            state = 'unknown'
        elif age > max(60, 3 * _interval_seconds(poll_interval_seconds)):
            state = 'stale'
        else:
            state = 'partial' if row['status']=='partial' else 'active'
    return CollectionStatus(state, LABELS[state], _utc_timestamp(row['last_success_at']), int(enabled))


def overall_collection_status(rows, poll_interval_seconds=30, *, now=None,
                              polling_enabled=True):
    statuses = [connector_collection_status(row, poll_interval_seconds, now=now,
                                            polling_enabled=polling_enabled)
                for row in rows]
    enabled = [item for item in statuses if item.enabled_count]
    if not enabled:
        return CollectionStatus('disabled', LABELS['disabled'])
    state = next(name for name in PRECEDENCE if any(item.state == name for item in enabled))
    # A single connector has an unambiguous contact timestamp. With several,
    # avoid presenting one source's success as the health of every source.
    last_success = enabled[0].last_success_at if len(enabled) == 1 else None
    return CollectionStatus(state, LABELS[state], last_success, len(enabled))
