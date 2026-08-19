"""Fault-tolerant background polling for new Wazuh Indexer alerts."""

import logging
import os
from threading import Event, Lock, Thread

from app.services.incident_processor import process_indexer_alerts

LOGGER = logging.getLogger(__name__)
_START_LOCK = Lock()
_THREAD = None
_STOP = Event()


def _bounded_integer(name, default, minimum, maximum):
    try:
        value = int(os.getenv(name, default))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _poll_loop(interval, batch_size):
    while not _STOP.is_set():
        try:
            process_indexer_alerts(size=batch_size, sort_order="desc")
        except Exception as error:
            LOGGER.warning("Wazuh polling failed: %s", error)
        _STOP.wait(interval)


def start_realtime_poller():
    global _THREAD
    if os.getenv("CDSS_REALTIME_ENABLED", "true").lower() not in {"1", "true", "yes"}:
        return None
    with _START_LOCK:
        if _THREAD and _THREAD.is_alive():
            return _THREAD
        _STOP.clear()
        interval = _bounded_integer("CDSS_POLL_INTERVAL_SECONDS", 30, 10, 3600)
        batch_size = _bounded_integer("CDSS_POLL_BATCH_SIZE", 100, 1, 1000)
        _THREAD = Thread(target=_poll_loop, args=(interval, batch_size), daemon=True,
                         name="cdss-wazuh-poller")
        _THREAD.start()
        return _THREAD
