"""Background services: event receiver and retention pruning.

Extracted from main.py so the API layer stays thin. Each service owns its
own thread lifecycle (start/stop) and logs under "fda.services.*".
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from app_shared.unified_store import prune_events, store_events_batch
from app_shared.text_utils import now_utc

logger = logging.getLogger("fda.services.event_receiver")

_event_queue: list[dict[str, Any]] = []
_event_queue_lock = threading.Lock()
_event_receiver_thread: threading.Thread | None = None
_event_receiver_running = threading.Event()

_prune_thread: threading.Thread | None = None
_prune_running = threading.Event()


def _event_receiver_loop() -> None:
    """Background thread: drain event queue and store + publish to ZeroClaw."""
    from backend.app.core.orchestrator import publish_event_all

    while _event_receiver_running.is_set():
        with _event_queue_lock:
            batch = list(_event_queue)
            _event_queue.clear()

        if batch:
            try:
                store_events_batch(batch)
                for ev in batch:
                    publish_event_all(ev)
            except Exception as exc:
                logger.warning("Event receiver error: %s", exc)

        time.sleep(0.5)


def start_event_receiver() -> None:
    global _event_receiver_thread
    if _event_receiver_thread and _event_receiver_thread.is_alive():
        return
    _event_receiver_running.set()
    _event_receiver_thread = threading.Thread(
        target=_event_receiver_loop, daemon=True, name="event-receiver"
    )
    _event_receiver_thread.start()
    logger.info("Event receiver started (Go agent -> HTTP -> SQLite)")


def stop_event_receiver() -> None:
    _event_receiver_running.clear()
    if _event_receiver_thread:
        _event_receiver_thread.join(timeout=5)
    logger.info("Event receiver stopped")


def ingest_event(event: dict[str, Any], run_id: str | None) -> dict[str, Any]:
    """Queue a single event from the Go agent (called by the HTTP endpoint)."""
    event["run_id"] = run_id
    event["timestamp"] = event.get("timestamp") or now_utc()
    with _event_queue_lock:
        _event_queue.append(event)
    return {"status": "ok", "queued": True}


def event_queue_size() -> int:
    with _event_queue_lock:
        return len(_event_queue)


def event_receiver_running() -> bool:
    return _event_receiver_running.is_set()


def _prune_loop() -> None:
    while _prune_running.is_set():
        try:
            hours = int(os.environ.get("RETENTION_HOURS", "24"))
            prune_events(hours)
        except Exception as exc:
            logger.warning("Prune error: %s", exc)
        time.sleep(3600)


def start_prune_loop() -> None:
    global _prune_thread
    if _prune_thread and _prune_thread.is_alive():
        return
    _prune_running.set()
    _prune_thread = threading.Thread(target=_prune_loop, daemon=True, name="retention-prune")
    _prune_thread.start()
    logger.info("Retention prune loop started (hourly)")


def stop_prune_loop() -> None:
    _prune_running.clear()
    logger.info("Retention prune loop stopped")
