"""One analyst-facing collection status for connector cards and the global banner.

Only persisted poll evidence proves collection; generic SIEM contact does not.
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
    pending_rejections: int = 0


def collection_status_rows(connection):
    from app.services.ingestion_safety import source_namespace
    rows = connection.execute('''SELECT id,name,connector_type,base_url,port,index_pattern,
        username,verify_tls,is_enabled,status,last_success_at,last_error,response_time_ms,
        cluster_health,last_alert_at,poll_status,last_poll_success_at,last_poll_error
        FROM siem_connections ORDER BY name''').fetchall()
    rejections = connection.execute('''SELECT connection_id,source_namespace,COUNT(*) AS pending
        FROM rejected_source_events GROUP BY connection_id,source_namespace''').fetchall()
    result = []
    for row in rows:
        try:
            namespace = source_namespace(row)
        except ValueError:
            namespace = None
        pending = sum(item['pending'] for item in rejections
                      if item['connection_id']==row['id'] or
                      (namespace is not None and item['source_namespace']==namespace))
        result.append(dict(row) | {'pending_rejections':pending})
    return result


def _label(state, pending):
    label = LABELS[state]
    if pending and state != 'partial':
        label += ' — source documents need review'
    return label


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
    fields = dict(row)
    poll_status = fields.get('poll_status')
    pending = fields.get('pending_rejections', 0)
    if not enabled:
        state = 'disabled'
    elif poll_status == 'error':
        state = 'failed'
    elif poll_status not in ('connected','partial'):
        state = 'unknown'
    else:
        current = parse_timestamp(now) if now is not None else datetime.now(timezone.utc)
        success = _utc_timestamp(fields.get('last_poll_success_at'))
        age = (current - success).total_seconds() if success and current else None
        if age is None or age < 0:
            state = 'unknown'
        elif age > max(60, 3 * _interval_seconds(poll_interval_seconds)):
            state = 'stale'
        else:
            state = 'partial' if pending or poll_status=='partial' else 'active'
    return CollectionStatus(state, _label(state, pending),
                            _utc_timestamp(fields.get('last_poll_success_at')), int(enabled), pending)


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
    pending = sum(item.pending_rejections for item in enabled)
    return CollectionStatus(state, _label(state, pending), last_success, len(enabled), pending)
