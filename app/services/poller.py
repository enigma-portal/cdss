"""Fault-tolerant polling for enabled vendor-neutral SIEM connectors."""

import logging
import json
import sqlite3
from threading import Event, Lock, Thread

from app.database import get_db_connection
from app.time_utils import utc_now_text
from app.services.connectors import create_connector
from app.services.incident_processor import ingest_source_alert
from app.services.secret_store import unprotect_secret
from app.services.wazuh_indexer import WazuhIndexerError
from app.single_instance import acquire_poller_lock, AlreadyRunningError
from app.services.ingestion_safety import (
    preserve_rejection, SourceEventError, require_connector_snapshot, connector_matches_snapshot,
)

LOGGER = logging.getLogger(__name__)
_START_LOCK = Lock()
_THREAD = None
_STOP = Event()


def _bounded_integer(value, default, minimum, maximum):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _poll_configuration(connection):
    settings = dict(connection.execute("SELECT setting_key, setting_value FROM system_settings").fetchall())
    return (
        _bounded_integer(settings.get("poll_interval_seconds"), 30, 10, 3600),
        _bounded_integer(settings.get("poll_batch_size"), 100, 1, 1000),
        _bounded_integer(settings.get("minimum_rule_level"), 5, 0, 16),
    )


def _safe_poll_error(error):
    """Return diagnostic categories without echoing arbitrary secret-bearing text."""
    if isinstance(error, WazuhIndexerError):
        return str(error)[:240]
    if isinstance(error, sqlite3.DatabaseError):
        return "CDSS database operation failed while handling the SIEM batch."
    if isinstance(error, (TypeError, ValueError)):
        return "SIEM event validation failed: malformed event or connector configuration."
    return "Unexpected SIEM polling failure; review protected application logs."


def _poll_once(batch_size, minimum_level):
    connection = get_db_connection()
    try:
        rows = connection.execute("SELECT * FROM siem_connections WHERE is_enabled = 1").fetchall()
    finally:
        connection.close()
    for row in rows:
        try:
            connector = create_connector(row["connector_type"],
                base_url=f'{row["base_url"]}:{row["port"]}', username=row["username"],
                password=unprotect_secret(row["encrypted_password"]), index_name=row["index_pattern"],
                verify_tls=bool(row["verify_tls"]), timeout_seconds=10)
            connection = get_db_connection()
            try:
                cursor = connection.execute("""
                    SELECT event_timestamp, document_id, sort_values_json FROM ingestion_cursors
                    WHERE connection_id = ?
                """, (row["id"],)).fetchone()
            finally:
                connection.close()
            if cursor and cursor['sort_values_json']:
                search_after = json.loads(cursor['sort_values_json'])
            else:
                # Legacy cursors had TEXT affinity. Never guess that an old
                # string was originally a numeric OpenSearch sort value.
                search_after = ((cursor['event_timestamp'], cursor['document_id'])
                                if cursor and cursor['event_timestamp'] and cursor['document_id'] else None)
            alerts, next_cursor = connector.fetch_event_page(
                size=batch_size, search_after=search_after,
            )
            connection = get_db_connection()
            try:
                require_connector_snapshot(connection, row)
            finally:
                connection.close()
            accepted_count = 0
            rejected_error = None
            for alert in alerts:
                try:
                    rule = alert.get("rule") if isinstance(alert, dict) else None
                    if not isinstance(rule, dict):
                        raise ValueError("SIEM event rule must be an object.")
                    # Missing severity is only treated as zero for filtering;
                    # the parser/storage retain NULL, not invented telemetry.
                    level = int(rule['level']) if rule.get('level') is not None else 0
                    if level < minimum_level:
                        continue
                    ingest_source_alert(alert, connection_id=row['id'], expected_connector=row)
                    accepted_count += 1
                except (TypeError, ValueError) as error:
                    LOGGER.warning("Malformed SIEM event skipped for connector %s: %s",
                                   row["id"], _safe_poll_error(error))
                    reason = error.reason_code if isinstance(error, SourceEventError) else 'malformed_event'
                    if preserve_rejection(alert, row['id'], reason, expected_connector=row):
                        continue
                    rejected_error = error
                    break
            if rejected_error:
                # Without a rejected-event store, advancing would silently lose
                # this source record. Keep the prior cursor for explicit review.
                raise ValueError(str(rejected_error))
            connection = get_db_connection()
            try:
                with connection:
                    connection.execute('BEGIN IMMEDIATE')
                    require_connector_snapshot(connection, row)
                    contacted_at = utc_now_text()
                    connection.execute("""UPDATE siem_connections SET status = 'connected',
                        poll_status = 'connected', last_poll_success_at = ?, last_poll_error = NULL,
                        last_success_at = ?, last_error = NULL,
                        last_alert_at = CASE WHEN ? > 0 THEN ? ELSE last_alert_at END
                        WHERE id = ?""", (contacted_at, contacted_at, accepted_count, contacted_at, row["id"]))
                    pending = connection.execute('SELECT COUNT(*) FROM rejected_source_events WHERE connection_id=?',
                                                 (row['id'],)).fetchone()[0]
                    if pending:
                        connection.execute("UPDATE siem_connections SET status='partial',poll_status='partial',last_error=? WHERE id=?",
                            (f'{pending} source document(s) preserved for operator review; collection continues.',row['id']))
                    if next_cursor:
                        connection.execute("""
                            INSERT INTO ingestion_cursors
                                (connection_id, event_timestamp, document_id, sort_values_json, updated_at)
                            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(connection_id) DO UPDATE SET
                                event_timestamp = excluded.event_timestamp,
                                document_id = excluded.document_id,
                                sort_values_json = excluded.sort_values_json,
                                updated_at = CURRENT_TIMESTAMP
                        """, (row["id"], str(next_cursor[0]), next_cursor[1],
                              json.dumps(list(next_cursor), allow_nan=False, separators=(',', ':'))))
            finally:
                connection.close()
        except Exception as error:
            safe_error = _safe_poll_error(error)
            LOGGER.warning("SIEM polling failed for connector %s: %s", row["id"], safe_error)
            connection = get_db_connection()
            try:
                with connection:
                    connection.execute('BEGIN IMMEDIATE')
                    if not connector_matches_snapshot(connection, row):
                        continue
                    connection.execute("UPDATE siem_connections SET status = 'error', last_error = ?, poll_status='error',last_poll_error=? WHERE id = ?",
                                       (safe_error, safe_error, row["id"]))
            finally:
                connection.close()


def _poll_loop():
    interval = 30
    while not _STOP.is_set():
        try:
            connection = get_db_connection()
            try:
                interval, batch_size, minimum_level = _poll_configuration(connection)
            finally:
                connection.close()
            _poll_once(batch_size, minimum_level)
        except Exception as error:
            LOGGER.warning("SIEM polling cycle failed: %s", _safe_poll_error(error))
        _STOP.wait(interval)


def start_realtime_poller(enabled=True):
    global _THREAD
    if not enabled:
        return None
    with _START_LOCK:
        if _THREAD and _THREAD.is_alive():
            return _THREAD
        try:
            acquire_poller_lock()
        except AlreadyRunningError:
            LOGGER.info('SIEM collection worker is already owned by another CDSS process.')
            return None
        _STOP.clear()
        _THREAD = Thread(target=_poll_loop, daemon=True, name="cdss-siem-poller")
        _THREAD.start()
        return _THREAD
