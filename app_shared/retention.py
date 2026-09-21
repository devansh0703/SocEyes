"""Log retention and real-time window management for standalone mode.

The platform runs on a rolling time window. Raw events older than
RETENTION_HOURS (default 24h) are pruned on a schedule so that
memory and disk stay bounded.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app_shared.unified_store import prune_events as _store_prune

logger = logging.getLogger("soceyes.retention")


def read_retention_hours() -> int:
    """Read retention window from env or state_kv, default 24h."""
    import os
    env_hours = os.environ.get("RETENTION_HOURS")
    if env_hours:
        try:
            return int(env_hours)
        except (ValueError, TypeError):
            pass
    
    try:
        from app_shared.unified_store import get_kv
        val = get_kv("retention_hours")
        if val:
            return int(val)
    except Exception:
        pass
    
    return 24


def prune_old_events(retention_hours: int | None = None) -> dict:
    """Delete events older than retention_hours from the rolling window."""
    if retention_hours is None:
        retention_hours = read_retention_hours()
    
    result = _store_prune(retention_hours)
    logger.info("Pruned %d events (cutoff %s)", result.get("events_removed", 0), result.get("cutoff", ""))
    return result


def retention_status() -> dict:
    """Return current retention window and total event count."""
    retention_hours = read_retention_hours()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=retention_hours)).isoformat()
    
    try:
        from app_shared.unified_store import get_conn
        conn = get_conn()
        total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
    except Exception:
        total = 0
    
    return {
        "retention_hours": retention_hours,
        "cutoff": cutoff,
        "total_events": total,
        "mode": "sqlite",
    }


def set_retention_window(hours: int) -> dict:
    """Update retention window and immediately prune."""
    try:
        from app_shared.unified_store import set_kv
        set_kv("retention_hours", str(hours))
    except Exception:
        pass
    
    result = prune_old_events(hours)
    result["settings"] = {"retention_hours": hours, "updated_at": datetime.now(timezone.utc).isoformat()}
    return result
