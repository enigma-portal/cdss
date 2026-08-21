"""Fault-tolerant polling for enabled vendor-neutral SIEM connectors."""

import logging
from threading import Event, Lock, Thread

from app.database import get_db_connection
from app.services.connectors import create_connector
from app.services.incident_processor import process_alert
from app.services.secret_store import unprotect_secret

LOGGER = logging.getLogger(__name__)
_START_LOCK = Lock()
_THREAD = None
_STOP = Event()


def _bounded_integer(value, default, minimum, maximum):
    try:
        value = int(value)
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _poll_configuration(connection):
    settings = dict(connection.execute("SELECT setting_key, setting_value FROM system_settings").fetchall())
    return (
        _bounded_integer(settings.get("poll_interval_seconds"), 30, 10, 3600),
        _bounded_integer(settings.get("poll_batch_size"), 100, 1, 1000),
        _bounded_integer(settings.get("minimum_rule_level"), 5, 0, 16),
    )


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
            alerts = connector.fetch_events(size=batch_size, sort_order="desc")
            accepted = [alert for alert in alerts if int((alert.get("rule") or {}).get("level", 0)) >= minimum_level]
            for alert in accepted:
                process_alert(alert)
            connection = get_db_connection()
            try:
                with connection:
                    connection.execute("""UPDATE siem_connections SET status = 'connected',
                        last_success_at = CURRENT_TIMESTAMP, last_error = NULL,
                        last_alert_at = CASE WHEN ? > 0 THEN CURRENT_TIMESTAMP ELSE last_alert_at END
                        WHERE id = ?""", (len(accepted), row["id"]))
            finally:
                connection.close()
        except Exception as error:
            LOGGER.warning("SIEM polling failed for connector %s: %s", row["id"], error)
            connection = get_db_connection()
            try:
                with connection:
                    connection.execute("UPDATE siem_connections SET status = 'error', last_error = ? WHERE id = ?",
                                       (str(error)[:240], row["id"]))
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
            LOGGER.warning("SIEM polling cycle failed: %s", error)
        _STOP.wait(interval)


def start_realtime_poller():
    global _THREAD
    with _START_LOCK:
        if _THREAD and _THREAD.is_alive():
            return _THREAD
        _STOP.clear()
        _THREAD = Thread(target=_poll_loop, daemon=True, name="cdss-siem-poller")
        _THREAD.start()
        return _THREAD
