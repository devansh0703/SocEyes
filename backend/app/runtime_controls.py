"""Live response control plane: blocklists, disabled accounts and rate limits.

Design notes
------------
* Control files are written by `scripts/apply_response_control.py` (a separate
  process) and only ever read here. Reads are cached briefly and invalidated by
  file mtime, so a request never pays for a fresh `stat` + JSON parse.
* Rate-limit counters live in memory for the current minute window. The previous
  implementation rewrote a JSON file on *every* request, which is both a
  correctness problem (read-modify-write races between workers) and a needless
  I/O cost. Counters reset on window rollover and are capped, so memory cannot
  grow without bound.

The API runs with a single uvicorn worker, so per-process counters are exact for
this deployment; scaling out would need a shared store (Redis) instead.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.responses import JSONResponse

from app_shared.state_paths import read_json, state_path


STATE_DIR = state_path("response", "runtime")
BLOCKED_IPS_FILE = STATE_DIR / "blocked_ips.json"
RATE_LIMITS_FILE = STATE_DIR / "rate_limits.json"
DISABLED_ACCOUNTS_FILE = STATE_DIR / "disabled_accounts.json"
ISOLATED_HOSTS_FILE = STATE_DIR / "isolated_hosts.json"
QUARANTINED_ENDPOINTS_FILE = STATE_DIR / "quarantined_endpoints.json"

# Reuse a control-file read for this long before re-checking its mtime.
CACHE_TTL_SECONDS = float(os.environ.get("FDA_CONTROL_CACHE_TTL_SECONDS", "2.0"))
# Safety valve for pathological counter cardinality within a single window.
MAX_COUNTER_KEYS = int(os.environ.get("FDA_RATE_LIMIT_MAX_KEYS", "10000"))

_cache_lock = threading.Lock()
_list_cache: dict[Path, tuple[float, float, list[dict[str, Any]]]] = {}

_counter_lock = threading.Lock()
_counter_bucket = ""
_counters: dict[str, int] = {}


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_list(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def load_list(path: Path) -> list[dict[str, Any]]:
    """Return the JSON list at *path*, cached by mtime for `CACHE_TTL_SECONDS`."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        with _cache_lock:
            _list_cache.pop(path, None)
        return []

    now = datetime.now(UTC).timestamp()
    with _cache_lock:
        cached = _list_cache.get(path)
        if cached and cached[0] == mtime and now - cached[1] < CACHE_TTL_SECONDS:
            return cached[2]

    entries = _normalize_list(read_json(path, default=[]))
    with _cache_lock:
        _list_cache[path] = (mtime, now, entries)
    return entries


def load_controls() -> dict[str, list[dict[str, Any]]]:
    return {
        "blocked_ips": load_list(BLOCKED_IPS_FILE),
        "rate_limits": load_list(RATE_LIMITS_FILE),
        "disabled_accounts": load_list(DISABLED_ACCOUNTS_FILE),
        "isolated_hosts": load_list(ISOLATED_HOSTS_FILE),
        "quarantined_endpoints": load_list(QUARANTINED_ENDPOINTS_FILE),
    }


def client_ip_from_request(request: Any) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return str(request.client.host or "")
    return ""


def is_blocked_ip(ip: str) -> bool:
    return any(entry.get("ip") == ip for entry in load_list(BLOCKED_IPS_FILE))


def is_disabled_account(username: str) -> bool:
    return any(entry.get("username") == username for entry in load_list(DISABLED_ACCOUNTS_FILE))


def matching_rate_limit(path: str, client_ip: str) -> dict[str, Any] | None:
    matches = []
    for rule in load_list(RATE_LIMITS_FILE):
        target_path = str(rule.get("path") or "")
        source_ip = str(rule.get("source_ip") or "")
        if target_path and not path.startswith(target_path):
            continue
        if source_ip and source_ip != client_ip:
            continue
        matches.append(rule)
    matches.sort(key=lambda item: len(str(item.get("path") or "")), reverse=True)
    return matches[0] if matches else None


def _current_bucket() -> str:
    """Minute-resolution window key, clearing counters when the window rolls."""
    global _counter_bucket
    bucket = datetime.now(UTC).strftime("%Y%m%d%H%M")
    if bucket != _counter_bucket:
        _counter_bucket = bucket
        _counters.clear()
    return bucket


def counter_snapshot() -> dict[str, int]:
    """Current window counters (used by tests and diagnostics)."""
    with _counter_lock:
        return dict(_counters)


def check_and_count_rate_limit(path: str, client_ip: str) -> tuple[bool, int, dict[str, Any] | None]:
    rule = matching_rate_limit(path, client_ip)
    if not rule:
        return True, 0, None

    rpm = int(rule.get("requests_per_minute") or 60)
    with _counter_lock:
        bucket = _current_bucket()
        key = f"{client_ip}:{path}:{bucket}"
        if len(_counters) >= MAX_COUNTER_KEYS and key not in _counters:
            _counters.clear()
        current = _counters.get(key, 0) + 1
        _counters[key] = current
    return current <= rpm, max(rpm - current, 0), rule


def enforcement_response(detail: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"status": "blocked", "detail": detail})
