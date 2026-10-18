"""Conservative evidence grouping, independent of risk and attack outcomes."""

import ipaddress
import json
from app.time_utils import parse_timestamp

DEFAULT_WINDOW_MINUTES = 15
WINDOW_SETTING = 'incident_correlation_window_minutes'


def event_time(value):
    return parse_timestamp(value)


def correlation_window(connection):
    row = connection.execute('SELECT setting_value FROM system_settings WHERE setting_key=?',
                             (WINDOW_SETTING,)).fetchone()
    try:
        minutes = int(row[0]) if row else DEFAULT_WINDOW_MINUTES
        return minutes if 1 <= minutes <= 1440 else DEFAULT_WINDOW_MINUTES
    except (TypeError, ValueError):
        return DEFAULT_WINDOW_MINUTES


def meaningful_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_unspecified or address.is_multicast or address.is_loopback)
    except (ValueError, TypeError):
        return False


def file_entity(raw):
    """Use the explicit FIM path, not descriptions or arbitrary raw strings."""
    try:
        source = json.loads(raw)
        syscheck = source.get('syscheck')
        path = syscheck.get('path') if isinstance(syscheck, dict) else None
        return path if isinstance(path, str) and path.strip() and len(path) <= 4096 else None
    except (TypeError, ValueError, AttributeError):
        return None


def matching_reason(new, old, asset_ip):
    source = (meaningful_ip(new['source_ip']) and new['source_ip'] == old['source_ip'])
    user = (bool(new['username']) and new['username'] == old['username'])
    if source and user:
        return 'same_asset_source_ip_and_username'
    if source:
        return 'same_asset_and_source_ip'
    if user:
        return 'same_asset_and_username'
    destination = new['destination_ip']
    # An endpoint's own address repeats its asset identity, not extra evidence.
    own_addresses = {asset_ip, new['agent_ip'], old['agent_ip']}
    if (meaningful_ip(destination) and destination == old['destination_ip']
            and destination not in own_addresses):
        return 'same_asset_and_destination_ip'
    path = file_entity(new['raw_alert'])
    if path and path == file_entity(old['raw_alert']):
        return 'same_asset_and_syscheck_path'
    return None


def find_related_incident(connection, alert_id):
    new = connection.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
    if new is None or new['asset_id'] is None:
        return None
    asset = connection.execute('SELECT * FROM assets WHERE id=? AND is_protected=1',
                               (new['asset_id'],)).fetchone()
    timestamp = event_time(new['event_timestamp'])
    if asset is None or timestamp is None:
        return None
    window_seconds = correlation_window(connection) * 60
    rows = connection.execute("""
        SELECT i.id AS incident_id, a.* FROM incidents i
        JOIN incident_alerts ia ON ia.incident_id=i.id
        JOIN alerts a ON a.id=ia.alert_id
        WHERE i.asset_id=? AND i.status IN ('open','investigating')
          AND NOT EXISTS (
              SELECT 1 FROM incident_alerts other JOIN alerts oa ON oa.id=other.alert_id
              WHERE other.incident_id=i.id AND (oa.asset_id IS NULL OR oa.asset_id<>i.asset_id))
        ORDER BY i.id, ia.ordinal, a.id
    """, (new['asset_id'],)).fetchall()
    latest = {}
    matches = {}
    for old in rows:
        observed = event_time(old['event_timestamp'])
        if observed is None:
            continue
        incident_id = old['incident_id']
        latest[incident_id] = max(latest.get(incident_id, observed), observed)
        if abs((timestamp - observed).total_seconds()) <= window_seconds:
            reason = matching_reason(new, old, asset['ip_address'])
            if reason:
                matches.setdefault(incident_id, reason)
    if not matches:
        return None
    # Most recently active by event time; lowest ID is the stable tie-breaker.
    selected = max(matches, key=lambda identifier: (latest[identifier], -identifier))
    return selected, matches[selected]


def link_alert(connection, incident_id, alert_id, reason):
    ordinal = connection.execute('SELECT COALESCE(MAX(ordinal),-1)+1 FROM incident_alerts WHERE incident_id=?',
                                 (incident_id,)).fetchone()[0]
    connection.execute('INSERT INTO incident_alerts(incident_id,alert_id,correlation_reason,ordinal) VALUES(?,?,?,?)',
                       (incident_id, alert_id, reason, ordinal))
    times = [event_time(row[0]) for row in connection.execute('''
        SELECT a.event_timestamp FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id
        WHERE ia.incident_id=?''', (incident_id,))]
    known = [value for value in times if value is not None]
    connection.execute('''UPDATE incidents SET last_activity_at=?, updated_at=CURRENT_TIMESTAMP
                          WHERE id=?''', (max(known).isoformat() if known else None, incident_id))
