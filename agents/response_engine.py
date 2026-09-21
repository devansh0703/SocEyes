#!/usr/bin/env python3
"""
SocEyes — Response Engine (Native)

Consumes high-severity alerts and runs the AI-assisted response loop:

1. AI triage (`app_shared/nvidia_ai.ai_triage`) produces a verdict,
   confidence, and recommended action from packet context, timeline, and
   MITRE techniques. Falls back to deterministic severity-based triage when
   the LLM is unavailable.
2. Policy gate: auto-execution requires the operator's response policy
   (`auto_execute` + engine gate) AND a true-positive verdict.
3. Enforcement via nftables (`backend/app.core.enforce`) with TTL rollback,
   plus the JSON control files the API runtime-controls middleware reads.
4. Audit: every decision is recorded in `control_actions.jsonl` and as a
   response event, so the UI shows what the AI decided and why.

Safety features:
- Dry-run mode by default (SOC_RESPONSE_DRY_RUN=true)
- Auto-execution gated by response policy (auto_execute + engine enable)
- Alerts are processed exactly once (processed-set persisted in state_kv)
- Control-file entries expire with the enforcement TTL
- Background thread processing with graceful shutdown
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in (__import__("sys").path or []):
    __import__("sys").path.insert(0, str(ROOT))

from app_shared.nvidia_ai import ai_triage
from app_shared.response_policy import action_detail, choose_action, is_auto_execution_enabled
from app_shared.response_state import FILES, append_action_log, load_list, now_iso, save_list, upsert
from app_shared.state_paths import state_path
from app_shared.unified_store import get_kv, init_db, search_alerts, set_kv, store_event, update_alert_preview

# Real enforcement via nftables (backend/app/core/enforce.py)
from backend.app.core.enforce import EnforceAction, EnforcementPolicy, start_rollback_sweeper, stop_rollback_sweeper

logger = logging.getLogger("soceyes.response-engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AUTO_EXEC_INTERVAL = float(os.environ.get("SOC_RESPONSE_INTERVAL_SECONDS", "10"))
MAX_ALERTS_PER_CYCLE = int(os.environ.get("SOC_RESPONSE_MAX_ALERTS", "10"))
MIN_CONFIDENCE = float(os.environ.get("SOC_RESPONSE_MIN_CONFIDENCE", "0.5"))
PROCESSED_KEY = "response_engine.processed_alerts"
PROCESSED_CAP = 1000


def dry_run() -> bool:
    """Dry-run is the safe default; SOC_RESPONSE_DRY_RUN=false enables live enforcement."""
    return os.environ.get("SOC_RESPONSE_DRY_RUN", "true").lower() in ("true", "1", "yes")


_engine_thread: threading.Thread | None = None
_engine_running = threading.Event()


# ---------------------------------------------------------------------------
# Alert dedup
# ---------------------------------------------------------------------------

def _load_processed() -> set[str]:
    raw = get_kv(PROCESSED_KEY, "")
    if not raw:
        return set()
    return {item for item in str(raw).split(",") if item}


def _save_processed(processed: set[str]) -> None:
    if len(processed) > PROCESSED_CAP:
        processed = set(sorted(processed)[-PROCESSED_CAP:])
    set_kv(PROCESSED_KEY, ",".join(sorted(processed)))


def _auto_execution_allowed(engine: str) -> bool:
    """Operator policy gate: auto_execute plus a per-engine switch when defined."""
    from app_shared.response_policy import load_policy

    policy = load_policy()
    if not policy.get("auto_execute"):
        return False
    engines = policy.get("engines") or {}
    if engine in engines:
        return bool(engines.get(engine))
    return True  # engine has no dedicated gate; global switch applies


# ---------------------------------------------------------------------------
# Control-file TTL pruning (keeps API runtime controls in sync with nft TTLs)
# ---------------------------------------------------------------------------

def _prune_expired_controls() -> int:
    """Drop control-file entries whose enforcement TTL has elapsed."""
    now = datetime.now(timezone.utc)
    removed = 0
    for action, path in FILES.items():
        entries = load_list(path)
        kept = []
        for entry in entries:
            ttl = entry.get("ttl_seconds")
            updated_at = entry.get("updated_at", "")
            if not ttl or not updated_at:
                kept.append(entry)
                continue
            try:
                expires = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00")) + timedelta(seconds=int(ttl))
            except ValueError:
                kept.append(entry)
                continue
            if expires <= now:
                removed += 1
                logger.info("Control entry expired: %s (%s)", action, entry.get("ip") or entry.get("username") or entry.get("key"))
            else:
                kept.append(entry)
        if len(kept) != len(entries) and not dry_run():
            save_list(path, kept)
    return removed


# ---------------------------------------------------------------------------
# Response execution
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
    """Execute a response action with full safety checks.

    1. Records the action in the JSON control file (runtime controls state)
    2. Executes the actual system command (nftables / usermod) unless dry-run
    3. Logs the result to the audit log
    """
    is_dry_run = dry_run()
    persist = not is_dry_run
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
        "dry_run": is_dry_run,
        "ttl_seconds": int(os.environ.get("SOC_RESPONSE_TTL_SECONDS", "1800")),
    }

    # Step 1: persist to the control file the API middleware reads
    if action == "observe_only":
        state_result = {"status": "recorded", "count": 0, "updated": False}
    elif action == "block_source_ip":
        if not source_ip:
            return {"error": "block_source_ip requires source_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", source_ip,
            {"ip": source_ip, "reason": rule_id or technique_id or "manual", **detail},
            persist=persist,
        )
    elif action == "throttle_service":
        key = f"{source_ip}:{target_path}"
        state_result = upsert(
            FILES[action], "key", key,
            {"key": key, "source_ip": source_ip, "path": target_path,
             "requests_per_minute": requests_per_minute, **detail},
            persist=persist,
        )
    elif action == "disable_account":
        if not username:
            return {"error": "disable_account requires username", "status": "failed"}
        state_result = upsert(
            FILES[action], "username", username,
            {"username": username, "reason": rule_id or technique_id or "manual", **detail},
            persist=persist,
        )
    elif action in {"isolate_host", "quarantine_endpoint"}:
        if not destination_ip:
            return {"error": f"{action} requires destination_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", destination_ip,
            {"ip": destination_ip, "reason": rule_id or technique_id or "manual", **detail},
            persist=persist,
        )
    elif action == "block_egress":
        if not source_ip:
            return {"error": "block_egress requires source_ip", "status": "failed"}
        state_result = upsert(
            FILES[action], "ip", source_ip,
            {"ip": source_ip, "reason": rule_id or technique_id or "manual", **detail},
            persist=persist,
        )
    else:
        return {"error": f"Unsupported action: {action}", "status": "failed"}

    # Step 2: execute the system command
    exec_result = _dispatch(action, source_ip=source_ip, destination_ip=destination_ip,
                            username=username, target_path=target_path,
                            requests_per_minute=requests_per_minute, rule_id=rule_id)

    # The caller owns the audit trail (process_alert logs AI decisions,
    # the manual endpoint logs operator actions) — one entry per action.
    action_record = {
        "@timestamp": timestamp,
        **detail,
        **state_result,
        "execution": exec_result,
    }

    logger.info(
        "Response %s executed for %s (dry_run=%s): state=%s exec_status=%s",
        action, source_ip or username or destination_ip, is_dry_run,
        state_result.get("status", "n/a"), exec_result.get("status", "n/a"),
    )
    return action_record


def _dispatch(
    action: str,
    source_ip: str,
    destination_ip: str,
    username: str,
    target_path: str,
    requests_per_minute: int,
    rule_id: str,
) -> dict[str, Any]:
    """Run the kernel-level enforcement for an action."""
    policy_args: dict[str, Any] = {"rule_id": rule_id, "dry_run": dry_run()}
    if action in ("block_source_ip", "block_egress"):
        policy = EnforcementPolicy(action=action, source_ip=source_ip, **policy_args)
    elif action == "throttle_service":
        policy = EnforcementPolicy(
            action=action, source_ip=source_ip, target_path=target_path,
            requests_per_minute=requests_per_minute, **policy_args,
        )
    elif action == "disable_account":
        policy = EnforcementPolicy(action=action, source_ip=username, **policy_args)
    elif action in ("isolate_host", "quarantine_endpoint"):
        policy = EnforcementPolicy(action=action, destination_ip=destination_ip, **policy_args)
    else:  # observe_only
        return {"status": "observed", "action": "none"}

    result = EnforceAction(policy)
    return {
        "status": "executed" if result.success else "failed",
        "command": result.executed_command,
        "stderr": result.error,
        "dry_run": result.dry_run,
        "rollback_at": result.rollback_at,
        "ttl_seconds": result.ttl_seconds,
    }


# ---------------------------------------------------------------------------
# AI-assisted alert processing loop
# ---------------------------------------------------------------------------

def process_alert(alert: dict[str, Any]) -> dict[str, Any] | None:
    """Run AI triage + policy-gated response for one alert."""
    technique_ids = alert.get("technique_ids") or []
    if isinstance(technique_ids, str):
        technique_ids = [technique_ids]
    action = choose_action(technique_ids)
    detail = action_detail(action)
    engine = alert.get("engine", "") or "correlated"

    triage = ai_triage({
        "title": alert.get("title", ""),
        "message": alert.get("message", ""),
        "severity": alert.get("severity", "medium"),
        "source_ip": alert.get("source_ip", ""),
        "destination_ip": alert.get("destination_ip", ""),
        "rule_id": alert.get("rule_id", ""),
        "engine": engine,
        "technique_ids": technique_ids,
    })

    allowed = _auto_execution_allowed(engine)
    enforceable = (
        allowed
        and action != "observe_only"
        and triage.get("verdict") == "true_positive"
        and float(triage.get("confidence", 0.0)) >= MIN_CONFIDENCE
    )

    executed_action = action if enforceable else "observe_only"
    if enforceable:
        result = execute_response_action(
            action=action,
            source_ip=alert.get("source_ip", ""),
            destination_ip=alert.get("destination_ip", ""),
            rule_id=alert.get("rule_id", ""),
            technique_id=technique_ids[0] if technique_ids else "",
            engine=engine,
            message=alert.get("message", ""),
        )
    else:
        result = {
            "status": "recorded",
            "reason": (
                "policy gate disabled auto-execution"
                if not allowed
                else f"AI verdict {triage.get('verdict')} (confidence {triage.get('confidence')})"
            ),
        }

    # Audit trail: what the AI decided and whether it acted
    record = {
        "@timestamp": now_iso(),
        "action": executed_action,
        "recommended_action": action,
        "source_ip": alert.get("source_ip", ""),
        "destination_ip": alert.get("destination_ip", ""),
        "rule_id": alert.get("rule_id", ""),
        "engine": engine,
        "technique_id": technique_ids[0] if technique_ids else "",
        "severity": alert.get("severity", ""),
        "alert_id": alert.get("id", ""),
        "ai_triage": triage,
        "auto_execution_allowed": allowed,
        "status": "executed" if enforceable else "observed",
        "message": (
            f"AI triage: {triage.get('verdict')} (confidence {triage.get('confidence')}). "
            f"Recommended {action}; {'executed' if enforceable else 'held for operator review'}. "
            f"{triage.get('summary', '')}"
        ),
        "updated_at": now_iso(),
        "dry_run": dry_run(),
    }
    # Audit trail: what the AI decided and whether it acted.
    # Dry-run still records decisions (marked dry_run) so the operator sees them;
    # only live enforcement touches control files / kernel state.
    append_action_log(record)

    if alert.get("id"):
        update_alert_preview(alert["id"], {
            "status": record["status"],
            "recommended_action": action,
            "ai_triage": triage,
            "policy_allowed": allowed,
            "updated_at": record["updated_at"],
        })

    store_event(
        source="response",
        index_name="security-response-*",
        title=f"Response: {executed_action}",
        message=record["message"],
        severity=alert.get("severity", "medium"),
        engine="ai-triage",
        rule_id=alert.get("rule_id", ""),
        technique_ids=technique_ids,
        source_ip=alert.get("source_ip", ""),
        destination_ip=alert.get("destination_ip", ""),
        raw={
            "ai_triage": triage,
            "recommended_action": action,
            "executed": enforceable,
            "policy_allowed": allowed,
        },
    )
    logger.info("Processed alert %s: verdict=%s action=%s executed=%s",
                alert.get("id", "?"), triage.get("verdict"), executed_action, enforceable)
    return record


def process_pending_alerts() -> list[dict[str, Any]]:
    """AI-triage and (policy-gated) respond to unprocessed high-severity alerts."""
    processed = _load_processed()
    candidates = [
        a for a in search_alerts(limit=100)
        if a.get("severity") in ("high", "critical") and a.get("id") and a["id"] not in processed
    ][:MAX_ALERTS_PER_CYCLE]
    if not candidates:
        return []

    results = []
    for alert in candidates:
        try:
            record = process_alert(alert)
        except Exception as exc:
            logger.error("Alert %s processing failed: %s", alert.get("id", "?"), exc)
            record = None
        if record:
            results.append(record)
        processed.add(alert["id"])

    _save_processed(processed)
    return results


# ---------------------------------------------------------------------------
# Background thread
# ---------------------------------------------------------------------------

def _engine_loop() -> None:
    logger.info(
        "Response engine thread started (dry_run=%s, interval=%ss)",
        dry_run(), AUTO_EXEC_INTERVAL,
    )
    start_rollback_sweeper()
    while _engine_running.is_set():
        try:
            _prune_expired_controls()
            process_pending_alerts()
        except Exception as exc:
            logger.error("Response engine error: %s", exc)
        _engine_running.wait(AUTO_EXEC_INTERVAL)
    stop_rollback_sweeper()
    logger.info("Response engine thread stopped")


def start_engine_thread() -> threading.Thread:
    """Start the background response engine thread (idempotent)."""
    global _engine_thread
    if _engine_thread and _engine_thread.is_alive():
        return _engine_thread
    init_db()
    _engine_running.set()
    _engine_thread = threading.Thread(target=_engine_loop, daemon=True, name="response-engine")
    _engine_thread.start()
    return _engine_thread


def stop_engine_thread() -> None:
    """Stop the background response engine thread."""
    _engine_running.clear()
    if _engine_thread and _engine_thread.is_alive():
        _engine_thread.join(timeout=5)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [response-engine] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(ROOT / "state" / "logs" / "response-engine.log", mode="a"),
        ],
    )

    def _handle_signal(signum: int, _frame: Any) -> None:
        logger.info("Received signal %s, stopping", signum)
        stop_engine_thread()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("Response engine started (dry_run=%s)", dry_run())
    init_db()
    start_engine_thread()
    try:
        while _engine_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_engine_thread()
    logger.info("Response engine stopped")


if __name__ == "__main__":
    main()
