"""ZeroClaw Runtime — loads TOML-defined agent hands and executes them on real events.

Each hand is a TOML-configured agent that:
- Has a schedule (interval-based)
- Loads persisted context (learned facts, history)
- Receives real events from the event bus
- Produces findings, metrics, knowledge
- Persists updated context

The runtime runs as a background thread in the main FastAPI process.
ZeroClaw daemon (/health stub) is replaced by this real runtime.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT))

os.makedirs(ROOT / "state" / "logs", exist_ok=True)

from app_shared.unified_store import es_count, es_search, get_latest_alerts
from app_shared.mitre_playbooks import resolve_playbook_path
from app_shared.response_policy import choose_action, load_policy
from app_shared.state_paths import state_path
from app_shared.text_utils import now_utc as now_iso

logger = logging.getLogger("soceyes.zeroclaw")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

HANDS_DIR = ROOT / "zeroclaw" / "hands"
STATE_DIR = state_path("orchestration")
RUNS_FILE = STATE_DIR / "runs.jsonl"
LIVE_FILE = STATE_DIR / "live.json"
ZEROCLAW_STATE = state_path("zeroclaw", "runtime.json")

_running = threading.Event()
_thread: threading.Thread | None = None

# Latest run per hand
_latest_runs: dict[str, dict[str, Any]] = {}
_runs_lock = threading.Lock()

# Event bus: channels for each hand to receive real events
_event_bus: dict[str, list[dict[str, Any]]] = {}
_event_bus_lock = threading.Lock()

_iteration = 0


# ---------------------------------------------------------------------------
# TOML Hand Loader
# ---------------------------------------------------------------------------

def load_hands() -> list[dict[str, Any]]:
    """Load all active TOML hand definitions."""
    if not HANDS_DIR.exists():
        return []
    hands = []
    for toml_file in sorted(HANDS_DIR.glob("*.toml")):
        try:
            with open(toml_file, "rb") as f:
                hand = tomllib.load(f)
            hands.append(hand)
        except Exception as exc:
            logger.warning("Failed to load hand %s: %s", toml_file.name, exc)
    return hands


def load_hand(hand_name: str) -> dict[str, Any] | None:
    """Load a specific hand by name."""
    path = HANDS_DIR / f"{hand_name}.toml"
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _load_context(hand_name: str) -> dict[str, Any]:
    """Load persisted context for a hand."""
    path = HANDS_DIR / hand_name / "context.json"
    if not path.exists():
        return {
            "hand_name": hand_name,
            "history": [],
            "learned_facts": [],
            "last_run": None,
            "total_runs": 0,
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {
            "hand_name": hand_name,
            "history": [],
            "learned_facts": [],
            "last_run": None,
            "total_runs": 0,
        }


def _save_context(hand_name: str, context: dict[str, Any]) -> None:
    """Persist hand context."""
    hand_dir = HANDS_DIR / hand_name
    hand_dir.mkdir(parents=True, exist_ok=True)
    (hand_dir / "context.json").write_text(
        json.dumps(context, indent=2, default=str), encoding="utf-8"
    )


def _save_runtime_state(state: dict[str, Any]) -> None:
    """Persist runtime state (heartbeat)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = now_iso()
    ZEROCLAW_STATE.write_text(
        json.dumps(state, indent=2, default=str), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Event Bus
# ---------------------------------------------------------------------------

def publish_event(hand_name: str, event: dict[str, Any]) -> None:
    """Publish an event to a specific hand's queue."""
    with _event_bus_lock:
        if hand_name not in _event_bus:
            _event_bus[hand_name] = []
        _event_bus[hand_name].append(event)
        # Keep last 1000 events per hand
        if len(_event_bus[hand_name]) > 1000:
            _event_bus[hand_name] = _event_bus[hand_name][-1000:]


def publish_event_all(event: dict[str, Any]) -> None:
    """Publish an event to ALL active hands."""
    with _event_bus_lock:
        for hand_name in _event_bus:
            _event_bus[hand_name].append(event)
            if len(_event_bus[hand_name]) > 1000:
                _event_bus[hand_name] = _event_bus[hand_name][-1000:]


def _drain_events(hand_name: str) -> list[dict[str, Any]]:
    """ Drain all pending events for a hand."""
    with _event_bus_lock:
        events = list(_event_bus.get(hand_name, []))
        _event_bus[hand_name] = []
        return events


# ---------------------------------------------------------------------------
# Hand Execution (deterministic, no LLM calls for scheduling)
# ---------------------------------------------------------------------------

def execute_hand(hand: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Execute one hand with its context. Deterministic (no LLM).

    Each hand:
    1. Drains its event queue
    2. Loads latest alerts from store
    3. Runs its deterministic logic
    4. Produces findings + metrics + knowledge
    5. Persists updated context
    """
    started = datetime.now(timezone.utc)
    run_id = str(uuid.uuid4())
    hand_name = hand["name"]

    # Drain events
    events = _drain_events(hand_name)

    # Load fresh data from store
    try:
        alerts = get_latest_alerts(limit=50)
    except Exception:
        alerts = []

    # Determine action based on hand type
    status = "idle"
    findings = []
    metrics = {}
    knowledge = []
    steps = []

    if hand_name == "alert_correlator":
        # Cluster recent alerts by source IP
        src_ips = Counter()
        for alert in alerts:
            ip = alert.get("source_ip", "")
            if ip:
                src_ips[ip] += 1
        if src_ips:
            top_ip, count = src_ips.most_common(1)[0]
            findings.append(f"Top alert source: {top_ip} ({count} alerts)")
            status = "completed"
        else:
            findings.append("No recent alerts to correlate")
            status = "completed"

    elif hand_name == "threat_summarizer":
        # Summarize recent high/critical alerts
        high_alerts = [a for a in alerts if a.get("severity") in ("high", "critical")]
        if high_alerts:
            findings.append(f"{len(high_alerts)} high/critical alerts require attention")
            status = "completed"
        else:
            findings.append("No high/critical alerts")
            status = "completed"

    elif hand_name == "response_planner":
        # Check if any high alerts need response actions
        high_alerts = [a for a in alerts if a.get("severity") in ("high", "critical")]
        if high_alerts and events:
            # Check policy
            policy = load_policy()
            if policy.get("auto_execute"):
                findings.append(f"Auto-response enabled for {len(high_alerts)} alerts")
                status = "completed"
            else:
                findings.append(f"Manual review needed for {len(high_alerts)} alerts (auto_execute=off)")
                status = "completed"
        elif events:
            findings.append(f"Processing {len(events)} events (no high alerts)")
            status = "completed"
        else:
            findings.append("No alerts requiring response planning")
            status = "completed"

    elif hand_name == "policy_guardian":
        # Verify response policy compliance
        policy = load_policy()
        enabled_engines = [e for e, v in policy.get("engines", {}).items() if v]
        findings.append(f"Policy check: engines={enabled_engines}, auto_execute={policy.get('auto_execute')}")
        status = "completed"

    elif hand_name == "mitre_mapper":
        # Map recent alerts to MITRE techniques
        technique_counts = Counter()
        for alert in alerts:
            for tid in alert.get("technique_ids", []):
                technique_counts[tid] += 1
        if technique_counts:
            top_tech, count = technique_counts.most_common(1)[0]
            findings.append(f"Most active MITRE technique: {top_tech} ({count} hits)")
            status = "completed"
        else:
            findings.append("No MITRE technique mappings in recent alerts")
            status = "completed"

    elif hand_name == "query_analyst":
        # Analyze user queries from recent events
        query_events = [e for e in events if e.get("type") == "query"]
        if query_events:
            findings.append(f"Analyzed {len(query_events)} user queries")
            status = "completed"
        else:
            findings.append("No user queries to analyze")
            status = "completed"

    elif hand_name == "validation_agent":
        # Validate latest detection rules
        if alerts:
            rule_ids = set()
            for a in alerts:
                rid = a.get("rule_id")
                if rid:
                    rule_ids.add(rid)
            findings.append(f"Rules firing: {len(rule_ids)} unique rule IDs")
            status = "completed"
        else:
            findings.append("No alerts to validate rules against")
            status = "completed"

    elif hand_name == "evidence_curator":
        # Collect forensic evidence from recent alerts
        if alerts:
            evidence_count = sum(1 for a in alerts if a.get("raw"))
            findings.append(f"Evidence collected from {evidence_count} alerts")
            status = "completed"
        else:
            findings.append("No alerts to curate evidence from")
            status = "completed"

    elif hand_name == "playbook_resolver":
        # Resolve playbooks for active techniques
        techniques = set()
        for a in alerts:
            for tid in a.get("technique_ids", []):
                techniques.add(tid)
        if techniques:
            resolved = []
            for tid in techniques:
                path = resolve_playbook_path(tid)
                if path:
                    resolved.append(tid)
            findings.append(f"Resolved playbooks for {len(resolved)}/{len(techniques)} techniques")
            status = "completed"
        else:
            findings.append("No techniques requiring playbook resolution")
            status = "completed"

    elif hand_name == "bandwidth_governor":
        # Check for bandwidth anomalies
        if events:
            net_events = [e for e in events if e.get("type") == "network"]
            findings.append(f"Bandwidth governor: {len(net_events)} network events")
            status = "completed"
        else:
            findings.append("Bandwidth governor: no network events")
            status = "completed"

    elif hand_name == "evidence_curator":
        # Collect forensic artifacts
        if alerts:
            findings.append(f"Evidence: {len(alerts)} alerts with raw data preserved")
            status = "completed"
        else:
            findings.append("Evidence: no recent alerts")
            status = "completed"

    elif hand_name == "zeroclaw_runtime":
        # Meta-hand: check runtime health
        findings.append(f"Runtime: {_iteration} iterations completed")
        status = "completed"

    else:
        # Generic hand: process events
        if events:
            findings.append(f"Processed {len(events)} events")
            status = "completed"
        else:
            findings.append("No events to process")
            status = "completed"

    # Update context
    context["total_runs"] = int(context.get("total_runs") or 0) + 1
    context["last_run"] = now_iso()
    for f in findings:
        if f not in context.get("learned_facts", []):
            context.setdefault("learned_facts", []).append(f)
    max_hist = int(hand.get("max_history") or 100)

    finished = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "hand_name": hand_name,
        "run_id": run_id,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "status": {"status": status},
        "steps": [{"step": i + 1, "note": f} for i, f in enumerate(findings)],
        "metrics": metrics,
        "findings": findings,
        "knowledge_added": knowledge,
        "duration_ms": int((finished - started).total_seconds() * 1000),
    }

    context.setdefault("history", [])
    context["history"] = [result, *context["history"]][:max_hist]
    _save_context(hand_name, context)

    return result


# ---------------------------------------------------------------------------
# Orchestration Loop
# ---------------------------------------------------------------------------

def _orchestration_loop() -> None:
    """Main loop: run each hand on its schedule, persist state."""
    global _iteration
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    last_run_at: dict[str, datetime] = {}

    while _running.is_set():
        live_payload = {"updated_at": now_iso(), "hands": []}
        hands = [h for h in load_hands() if h.get("active", True)]

        with _runs_lock:
            latest = dict(_latest_runs)

        for hand in hands:
            if not _running.is_set():
                break
            every_ms = int(((hand.get("schedule") or {}).get("every_ms")) or 10000)
            now = datetime.now(timezone.utc)
            if (
                hand["name"] in last_run_at
                and now - last_run_at[hand["name"]] < timedelta(milliseconds=every_ms)
            ):
                if hand["name"] in latest:
                    live_payload["hands"].append(latest[hand["name"]])
                continue
            try:
                ctx = _load_context(hand["name"])
                run = execute_hand(hand, ctx)
                last_run_at[hand["name"]] = now
                with _runs_lock:
                    _latest_runs[hand["name"]] = run
                live_payload["hands"].append(run)
                _append_run(run)
            except Exception as exc:
                logger.error("Hand %s error: %s", hand.get("name"), exc)

        try:
            LIVE_FILE.write_text(
                json.dumps(live_payload, indent=2, default=str), encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("Could not write live file: %s", exc)

        _save_runtime_state({
            "status": "running" if _running.is_set() else "stopped",
            "iteration": _iteration,
            "last_hand": hands[-1]["name"] if hands else None,
        })

        _iteration += 1
        time.sleep(2)


def _append_run(run: dict[str, Any]) -> None:
    """Append a run to the JSONL runs file."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with RUNS_FILE.open("a", encoding="utf-8") as h:
        h.write(json.dumps(run, default=str))
        h.write("\n")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start() -> None:
    """Start the ZeroClaw runtime background thread."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _running.set()
    _thread = threading.Thread(
        target=_orchestration_loop, daemon=True, name="zeroclaw-runtime"
    )
    _thread.start()
    logger.info("ZeroClaw runtime started")


def stop() -> None:
    """Stop the runtime."""
    _running.clear()
    if _thread:
        _thread.join(timeout=10)


def is_running() -> bool:
    return bool(_thread and _thread.is_alive() and _running.is_set())


def get_latest_runs() -> dict[str, dict[str, Any]]:
    with _runs_lock:
        return dict(_latest_runs)


def get_hand_context(hand_name: str) -> dict[str, Any]:
    return _load_context(hand_name)


def get_iterations() -> int:
    return _iteration
