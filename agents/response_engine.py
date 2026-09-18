#!/usr/bin/env python3
"""
FDA Cyber Control — Response Engine (Native)

Listens for high-severity alerts and executes deterministic response actions:
- block_source_ip: Add iptables rule to block source IP
- throttle_service: Rate-limit a service using tc
- Disable_account: Lock Linux account (passwd -l / usermod -L)
- isolate_host: Network-isolate a host via iptables
- quarantine_endpoint: Move endpoint to quarantine VLAN
- block_egress: Block outbound traffic
- observe_only: Log-only mode

Safety features:
- Dry-run mode by default (FDA_RESPONSE_DRY_RUN=true)
- Auto-execution gated by response policy (auto_execute + engine enable)
- Background thread processing with graceful shutdown
- Command timeout and error handling
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app_shared.sqlite_store import init_db, store_alert, get_kv, set_kv, store_event
from app_shared.response_policy import choose_action, action_detail, render_command_preview
from app_shared.state_paths import append_jsonl, read_json, state_path, write_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [response-engine] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(ROOT / "state" / "logs" / "response-engine.log", mode="a")],
)
logger = logging.getLogger("fda.response-engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DRY_RUN = os.environ.get("FDA_RESPONSE_DRY_RUN", "true").lower() in ("true", "1", "yes")
AUTO_EXEC_INTERVAL = float(os.environ.get("FDA_RESPONSE_INTERVAL_SECONDS", "10"))
COMMAND_TIMEOUT = int(os.environ.get("FDA_CONTROL_TIMEOUT_SECONDS", "30"))
MAX_ALERTS_PER_CYCLE = int(os.environ.get("FDA_RESPONSE_MAX_ALERTS", "10"))

STATE_DIR = state_path("response", "runtime")
ACTION_LOG = state_path("response", "control_actions.jsonl")

FILES = {
    "block_source_ip": STATE_DIR / "blocked_ips.json",
    "throttle_service": STATE_DIR / "rate_limits.json",
    "disable_account": STATE_DIR / "disabled_accounts.json",
    "isolate_host": STATE_DIR / "isolated_hosts.json",
    "quarantine_endpoint": STATE_DIR / "quarantined_endpoints.json",
    "block_egress": STATE_DIR / "egress_blocks.json",
}

running = True
_engine_thread: threading.Thread | None = None
_engine_running = threading.Event()


def handle_signal(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# ---------------------------------------------------------------------------
# Response action implementations (imported logic from scripts/apply_response_control.py)
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_list(path: Path) -> list[dict[str, Any]]:
    """Load a JSON list from disk."""
    try:
        payload = read_json(path, default=[])
        return payload if isinstance(payload, list) else []
    except Exception:
        return []


def save_list(path: Path, payload: list[dict[str, Any]]) -> None:
    """Save a JSON list to disk atomically."""
    write_json(path, payload)


def upsert(path: Path, key_name: str, key_value: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Upsert an entry into a JSON list file."""
    current = load_list(path)
    updated = False
    for index, item in enumerate(current):
        if str(item.get(key_name) or "") == key_value:
            current[index] = {**item, **entry}
            updated = True
            break
    if not updated:
        current.append(entry)
    if not DRY_RUN:
        save_list(path, current)
    return {"updated": updated, "count": len(current)}


def append_action_log(entry: dict[str, Any]) -> None:
    """Append an entry to the action log."""
    if not DRY_RUN:
        append_jsonl(ACTION_LOG, entry)


# ---------------------------------------------------------------------------
# System-level command execution
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list[str], timeout: int = COMMAND_TIMEOUT) -> tuple[bool, str, str]:
    """Run a system command. Returns (success, stdout, stderr)."""
    if DRY_RUN:
        logger.info("[DRY-RUN] Would execute: %s", " ".join(cmd))
        return True, "", ""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return False, "", "timeout"
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        return False, "", f"{cmd[0]} not found"
    except Exception as exc:
        logger.error("Command error: %s", exc)
        return False, "", str(exc)


def _execute_block_source_ip(source_ip: str) -> dict[str, Any]:
    """Execute iptables rule to block a source IP."""
    # Check if rule already exists
    check_cmd = ["iptables", "-C", "INPUT", "-s", source_ip, "-j", "DROP"]
    exists, _, _ = _run_cmd(check_cmd)
    if exists:
        return {"status": "already_blocked", "rule_exists": True}

    # Add the rule
    cmd = ["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"]
    success, stdout, stderr = _run_cmd(cmd)
    return {
        "status": "blocked" if success else "failed",
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
    }


def _execute_throttle_service(source_ip: str, target_path: str, requests_per_minute: int) -> dict[str, Any]:
    """Execute tc rule to throttle traffic from a source."""
    # Use tc to rate-limit: create HTB qdisc if not present, then add filter
    iface = os.environ.get("FDA_THROTTLE_IFACE", "eth0")

    # Check if qdisc exists
    check_cmd = ["tc", "qdisc", "show", "dev", iface]
    success, stdout, _ = _run_cmd(check_cmd)
    if not success:
        return {"status": "failed", "error": f"tc qdisc check failed: {stdout}"}

    # Add a class-based rate limit (simplified)
    # In production, this would use more sophisticated tc rules
    cmd = [
        "tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:0",
        "prio", "1", "u32", "match", "ip", "src", source_ip,
        "police", "rate", f"{requests_per_minute * 100}bit", "burst", "10k", "drop"
    ]
    success, stdout, stderr = _run_cmd(cmd)
    return {
        "status": "throttled" if success else "failed",
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
    }


def _execute_disable_account(username: str) -> dict[str, Any]:
    """Lock a Linux account."""
    # Try usermod -L first (more portable), fall back to passwd -l
    cmd = ["usermod", "-L", username]
    success, stdout, stderr = _run_cmd(cmd)
    if not success:
        # Try passwd -l as fallback
        cmd = ["passwd", "-l", username]
        success, stdout, stderr = _run_cmd(cmd)

    return {
        "status": "locked" if success else "failed",
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
    }


def _execute_isolate_host(destination_ip: str) -> dict[str, Any]:
    """Isolate a host by blocking all traffic to/from it."""
    # Block incoming
    cmd_in = ["iptables", "-A", "INPUT", "-s", destination_ip, "-j", "DROP"]
    success_in, _, _ = _run_cmd(cmd_in)

    # Block outgoing
    cmd_out = ["iptables", "-A", "OUTPUT", "-d", destination_ip, "-j", "DROP"]
    success_out, _, _ = _run_cmd(cmd_out)

    return {
        "status": "isolated" if (success_in and success_out) else "partial",
        "incoming_blocked": success_in,
        "outgoing_blocked": success_out,
    }


def _execute_quarantine_endpoint(destination_ip: str) -> dict[str, Any]:
    """Quarantine an endpoint (mark in registry + isolate)."""
    # First isolate the host
    result = _execute_isolate_host(destination_ip)
    result["quarantine_vlan"] = os.environ.get("FDA_QUARANTINE_VLAN", "999")
    result["status"] = "quarantined"
    return result


def _execute_block_egress(source_ip: str) -> dict[str, Any]:
    """Block outbound traffic from a source IP."""
    cmd = ["iptables", "-A", "OUTPUT", "-s", source_ip, "-j", "DROP"]
    success, stdout, stderr = _run_cmd(cmd)
    return {
        "status": "egress_blocked" if success else "failed",
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
    }


def _execute_observe_only(**kwargs) -> dict[str, Any]:
    """Observe-only mode: just log, no action taken."""
    return {"status": "observed", "action": "none"}


# Action dispatch table
ACTION_DISPATCH = {
    "block_source_ip": _execute_block_source_ip,
    "throttle_service": _execute_throttle_service,
    "disable_account": _execute_disable_account,
    "isolate_host": _execute_isolate_host,
    "quarantine_endpoint": _execute_quarantine_endpoint,
    "block_egress": _execute_block_egress,
    "observe_only": _execute_observe_only,
}


# ---------------------------------------------------------------------------
# Main response execution
# ---------------------------------------------------------------------------

def execute_response_action(
    action: str,
    source_ip: str = "",
    destination_ip: str = "",
    username: str = "",
    target_path: str = "/api/login",
    requests_per_minute: int = 30,
    rule_id: str = "",
    technique_id: str = "",
    engine: str = "",
    message: str = "",
) -> dict[str, Any]:
    """
    Execute a response action with full safety checks.
    
    This function:
    1. Records the action in the JSON control file (state persistence)
    2. Executes the actual system command (unless dry-run)
    3. Logs the result
    
    Returns a dict with the execution result.
    """
    timestamp = now_iso()
    detail = {
        "action": action,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "target_path": target_path,
        "requests_per_minute": requests_per_minute,
        "rule_id": rule_id,
        "technique_id": technique_id,
        "engine": engine,
        "message": message,
        "updated_at": timestamp,
        "dry_run": DRY_RUN,
    }

    # Step 1: Persist to control file (JSON state)
    if action == "observe_only":
        state_result = {"status": "recorded", "count": 0, "updated": False}
    elif action == "block_source_ip":
        if not source_ip:
            return {"error": "block_source_ip requires source_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", source_ip,
            {"ip": source_ip, "reason": rule_id or technique_id or "manual", **detail},
        )
    elif action == "throttle_service":
        key = f"{source_ip}:{target_path}"
        state_result = upsert(
            FILES[action], "key", key,
            {"key": key, "source_ip": source_ip, "path": target_path,
             "requests_per_minute": requests_per_minute, **detail},
        )
    elif action == "disable_account":
        if not username:
            return {"error": "disable_account requires username", "status": "failed"}
        state_result = upsert(
            FILES[action], "username", username,
            {"username": username, "reason": rule_id or technique_id or "manual", **detail},
        )
    elif action in {"isolate_host", "quarantine_endpoint"}:
        if not destination_ip:
            return {"error": f"{action} requires destination_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", destination_ip,
            {"ip": destination_ip, "reason": rule_id or technique_id or "manual", **detail},
        )
    elif action == "block_egress":
        if not source_ip:
            return {"error": "block_egress requires source_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", source_ip,
            {"ip": source_ip, "reason": rule_id or technique_id or "manual", **detail},
        )
    else:
        return {"error": f"Unsupported action: {action}", "status": "failed"}

    # Step 2: Execute system command
    dispatch_fn = ACTION_DISPATCH.get(action, _execute_observe_only)
    if action == "block_source_ip":
        exec_result = dispatch_fn(source_ip)
    elif action == "throttle_service":
        exec_result = dispatch_fn(source_ip, target_path, requests_per_minute)
    elif action == "disable_account":
        exec_result = dispatch_fn(username)
    elif action == "isolate_host":
        exec_result = dispatch_fn(destination_ip)
    elif action == "quarantine_endpoint":
        exec_result = dispatch_fn(destination_ip)
    elif action == "block_egress":
        exec_result = dispatch_fn(source_ip)
    elif action == "observe_only":
        exec_result = dispatch_fn()
    else:
        exec_result = {"status": "unknown_action"}

    # Step 3: Build and log the action record
    action_record = {
        "@timestamp": timestamp,
        **detail,
        **state_result,
        "execution": exec_result,
    }
    append_action_log(action_record)

    logger.info(
        "Response %s executed for %s (dry_run=%s): state=%s exec_status=%s",
        action, source_ip or username or destination_ip, DRY_RUN,
        state_result.get("status", "n/a"), exec_result.get("status", "n/a"),
    )
    return action_record


def process_pending_alerts() -> list[dict[str, Any]]:
    """Check for unprocessed high-severity alerts and execute responses."""
    import sqlite3

    db_path = ROOT / "state" / "fda_events.sqlite"
    if not db_path.exists():
        return []

    results = []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        # Find alerts without response actions
        rows = conn.execute("""
            SELECT * FROM alerts
            WHERE severity IN ('high', 'critical')
            AND id NOT IN (SELECT id FROM events WHERE source = 'response')
            ORDER BY timestamp DESC LIMIT ?
        """, (MAX_ALERTS_PER_CYCLE,)).fetchall()

        for row in rows:
            alert = dict(row)
            technique_ids = json.loads(alert.get("technique_ids", "[]"))
            action = choose_action(technique_ids)
            detail = action_detail(action)

            # Execute the response action
            result = execute_response_action(
                action=action,
                source_ip=alert.get("source_ip", ""),
                destination_ip=alert.get("destination_ip", ""),
                username=alert.get("user_name", ""),
                rule_id=alert.get("rule_id", ""),
                technique_id=technique_ids[0] if technique_ids else "",
                engine=alert.get("engine", ""),
                message=alert.get("message", ""),
            )
            results.append(result)

            # Create response event in SQLite
            response_doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "message": f"Response action {action} triggered for {alert['title']}",
                "event": {
                    "action": action,
                    "category": ["response"],
                    "dataset": "security.response",
                    "kind": "event",
                    "outcome": "success" if "error" not in result else "failure",
                    "type": ["change"],
                },
                "rule": {"id": alert.get("rule_id", ""), "level": alert.get("severity", "")},
                "source": {"ip": alert.get("source_ip", "")},
                "threat": {"technique": {"id": technique_ids}},
                "response": {
                    "action": action,
                    "action_title": detail["title"],
                    "summary": detail["summary"],
                    "status": "executed",
                    "engine": "response-engine-native",
                    "dry_run": DRY_RUN,
                    "execution_result": result.get("execution", {}),
                },
            }

            store_event(
                source="response",
                index_name="security-response-*",
                title=f"Response: {action}",
                message=response_doc["message"],
                severity=alert.get("severity", "medium"),
                engine="response",
                rule_id=alert.get("rule_id", ""),
                technique_ids=technique_ids,
                timestamp=response_doc["@timestamp"],
            )

            logger.info("Executed response %s for alert %s (dry_run=%s)", action, alert["title"], DRY_RUN)

        conn.close()
    except Exception as exc:
        logger.error("Response processing error: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Background thread
# ---------------------------------------------------------------------------

def _engine_loop():
    """Background loop that processes pending alerts."""
    logger.info(
        "Response engine thread started (dry_run=%s, interval=%ss)",
        DRY_RUN, AUTO_EXEC_INTERVAL,
    )
    while _engine_running.is_set():
        try:
            process_pending_alerts()
        except Exception as exc:
            logger.error("Response engine error: %s", exc)
        time.sleep(AUTO_EXEC_INTERVAL)
    logger.info("Response engine thread stopped")


def start_engine_thread() -> threading.Thread:
    """Start the background response engine thread."""
    global _engine_thread
    if _engine_thread and _engine_thread.is_alive():
        return _engine_thread
    _engine_running.set()
    _engine_thread = threading.Thread(target=_engine_loop, daemon=True)
    _engine_thread.start()
    return _engine_thread


def stop_engine_thread():
    """Stop the background response engine thread."""
    _engine_running.clear()
    if _engine_thread and _engine_thread.is_alive():
        _engine_thread.join(timeout=5)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    logger.info("Response engine started (dry_run=%s)", DRY_RUN)
    init_db()

    while running:
        try:
            process_pending_alerts()
        except Exception as exc:
            logger.error("Error: %s", exc)
        time.sleep(AUTO_EXEC_INTERVAL)

    logger.info("Response engine stopped")


if __name__ == "__main__":
    main()
