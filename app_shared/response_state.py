"""Shared response control-file state.

Both the response engine (``agents/response_engine.py``) and the operator CLI
(``scripts/apply_response_control.py``) persist enforcement decisions as JSON
lists under ``state/response/runtime/``. This module owns that state so the
two entry points cannot drift apart.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app_shared.state_paths import read_json, state_path, write_json

STATE_DIR = state_path("response", "runtime")
ACTION_LOG = state_path("response", "control_actions.jsonl")

# Control file per action; the runtime controls middleware reads these.
FILES: dict[str, Path] = {
    "block_source_ip": STATE_DIR / "blocked_ips.json",
    "throttle_service": STATE_DIR / "rate_limits.json",
    "disable_account": STATE_DIR / "disabled_accounts.json",
    "isolate_host": STATE_DIR / "isolated_hosts.json",
    "quarantine_endpoint": STATE_DIR / "quarantined_endpoints.json",
    "block_egress": STATE_DIR / "egress_blocks.json",
}


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def load_list(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path, default=[])
    return payload if isinstance(payload, list) else []


def save_list(path: Path, payload: list[dict[str, Any]]) -> None:
    write_json(path, payload)


def upsert(
    path: Path,
    key_name: str,
    key_value: str,
    entry: dict[str, Any],
    persist: bool = True,
) -> dict[str, Any]:
    """Insert or update an entry keyed by ``key_name`` in a JSON list file.

    ``persist=False`` (dry-run) computes the result without touching disk,
    so dry-run enforcement never activates the runtime controls middleware.
    """
    current = load_list(path)
    for index, item in enumerate(current):
        if str(item.get(key_name) or "") == key_value:
            current[index] = {**item, **entry}
            if persist:
                save_list(path, current)
            return {"updated": True, "count": len(current)}
    current.append(entry)
    if persist:
        save_list(path, current)
    return {"updated": False, "count": len(current)}


def append_action_log(entry: dict[str, Any]) -> None:
    from app_shared.state_paths import append_jsonl

    append_jsonl(ACTION_LOG, entry)
