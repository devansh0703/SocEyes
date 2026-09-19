#!/usr/bin/env python3
"""
FDA Cyber Control — Main API Server (Native IDS)

Single-process FastAPI server with SQLite backend.
Serves frontend, API, attack simulation, and all agent endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent.parent  # fda/

from app_shared.unified_store import (
    get_analytics_summary, get_latest_alerts, init_db,
    prune_events, query_events, search_alerts, search_rules,
    store_alert, store_event, get_kv, set_kv,
    start_run, stop_run, current_run, save_run, run_history,
    find_rule, index_rule, es_available,
)
from app_shared.response_policy import (
    choose_action, action_detail, render_command_preview,
    load_policy, save_policy,
)
from app_shared.text_utils import now_utc, clean_text
from app_shared.retention import read_retention_hours
from app_shared.state_paths import read_json, read_jsonl, state_path
from backend.app.standalone import start_simulation, stop_simulation, _sim_running

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
# Event receiver is always on (no interval needed — it polls queue every 0.5s)
def _default_frontend_dist() -> Path:
    """Prefer the Next.js static export (frontend/out); fall back to frontend/"""
    out = _ROOT / "frontend" / "out"
    if (out / "index.html").exists():
        return out
    return _ROOT / "frontend"


FRONTEND_DIST = Path(os.environ.get("FRONTEND_DIST", _default_frontend_dist()))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("fda.api")

# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------
# Replaced by _event_receiver_running and _event_receiver_thread above
_prune_thread: threading.Thread | None = None
_prune_running = threading.Event()

# Orchestration engine state (the real ZeroClaw engine)
_orch_engine_running = False
_zeroclaw_thread: threading.Thread | None = None
_zeroclaw_running = threading.Event()

# Ensure log directory exists
_log_dir = _ROOT / "state" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Real Event Receiver (replaces attack simulator)
# ---------------------------------------------------------------------------
from typing import Any
_event_queue: list[dict[str, Any]] = []
_event_queue_lock = threading.Lock()
_event_receiver_thread: threading.Thread | None = None
_event_receiver_running = threading.Event()


def _event_receiver_loop():
    """Background thread: drain event queue and store + publish to ZeroClaw."""
    while _event_receiver_running.is_set():
        with _event_queue_lock:
            batch = list(_event_queue)
            _event_queue.clear()

        if batch:
            try:
                # Store events in SQLite
                from app_shared.unified_store import store_events_batch
                store_events_batch(batch)

                # Publish to ZeroClaw runtime event bus
                from backend.app.core.orchestrator import publish_event_all
                for ev in batch:
                    publish_event_all(ev)
            except Exception as exc:
                logger.warning("Event receiver error: %s", exc)

        time.sleep(0.5)


def start_event_receiver():
    global _event_receiver_thread
    if _event_receiver_thread and _event_receiver_thread.is_alive():
        return
    _event_receiver_running.set()
    _event_receiver_thread = threading.Thread(target=_event_receiver_loop, daemon=True, name="event-receiver")
    _event_receiver_thread.start()
    logger.info("Event receiver started (Go agent -> HTTP -> SQLite)")


def stop_event_receiver():
    _event_receiver_running.clear()
    if _event_receiver_thread:
        _event_receiver_thread.join(timeout=5)
    logger.info("Event receiver stopped")


def ingest_event(event: dict[str, Any]) -> dict[str, Any]:
    """Ingest a single event from the Go agent (called by HTTP endpoint)."""
    run_id = _current_run_id()
    event["run_id"] = run_id
    event["timestamp"] = event.get("timestamp") or now_utc()

    with _event_queue_lock:
        _event_queue.append(event)

    return {"status": "ok", "queued": True}


def _prune_loop():
    while _prune_running.is_set():
        try:
            hours = int(os.environ.get("RETENTION_HOURS", "24"))
            prune_events(hours)
        except Exception as exc:
            logger.warning("Prune error: %s", exc)
        time.sleep(3600)


def start_prune_loop():
    global _prune_thread
    _prune_running.set()
    _prune_thread = threading.Thread(target=_prune_loop, daemon=True)
    _prune_thread.start()
    logger.info("Retention prune loop started (hourly)")


def stop_prune_loop():
    _prune_running.clear()
    logger.info("Retention prune loop stopped")


# ---------------------------------------------------------------------------
# Real-time capture event detection (generates alerts from captured packets)
# ---------------------------------------------------------------------------

_CAPTURE_DETECT_RUNNING = threading.Event()
_capture_detect_thread: threading.Thread | None = None
_capture_detect_cursor: int = 0  # Last processed event ID


def _detect_from_capture_loop() -> None:
    """Scan capture-agent events for suspicious patterns and match against indexed rules."""
    from app_shared.unified_store import store_alert, store_event, query_events
    from app_shared.response_policy import choose_action, action_detail, render_command_preview

    logger.info("Capture detection loop started")

    while _CAPTURE_DETECT_RUNNING.is_set():
        try:
            # Phase 1: Detect port scans from capture-agent events
            events = query_events(
                sources=["capture-agent"],
                start=None,
                end=None,
                limit=500,
            )

            if events:
                # Group by source IP to detect port scan patterns
                ip_port_map: dict[str, set[int]] = {}
                ip_event_count: dict[str, int] = {}

                for ev in events:
                    src_ip = ev.get("source_ip", "")
                    if not src_ip or src_ip == "0.0.0.0":
                        continue
                    port = ev.get("destination_port") or 0
                    ip_port_map.setdefault(src_ip, set()).add(port)
                    ip_event_count[src_ip] = ip_event_count.get(src_ip, 0) + 1

                # Detect port scans: many distinct ports from one IP
                for src_ip, ports in ip_port_map.items():
                    if len(ports) >= 20:  # 20+ distinct ports = port scan
                        severity = "medium" if len(ports) < 50 else "high"
                        title = f"Port scan reconnaissance (T1046)"
                        technique_id = "T1046"
                        tech = [technique_id]
                        ts = datetime.now(timezone.utc).isoformat()

                        # Store as events (for ES indexing)
                        store_event(
                            "suricata", "fda-capture-detection",
                            engine="suricata",
                            title=title,
                            message=f"Detected {len(ports)} distinct ports scanned from {src_ip} across {ip_event_count[src_ip]} capture events. Real detection from Go agent packet capture.",
                            severity=severity,
                            rule_id=f"CAPTURE-{technique_id}",
                            source_ip=src_ip,
                            technique_ids=tech,
                            timestamp=ts,
                        )
                        store_event(
                            "elastic", ".alerts-security.alerts-fda",
                            engine="elastic",
                            title=title,
                            message=f"Detected {len(ports)} distinct ports scanned from {src_ip} across {ip_event_count[src_ip]} capture events. Real detection from Go agent packet capture.",
                            severity=severity,
                            rule_id=f"CAPTURE-{technique_id}",
                            source_ip=src_ip,
                            technique_ids=tech,
                            timestamp=ts,
                        )

                        # Store as correlated alert
                        action = choose_action(tech)
                        detail = action_detail(action)
                        preview = {
                            "title": detail["title"],
                            "summary": detail["summary"],
                            "preview_command": render_command_preview(
                                action, {"source_ip": src_ip, "rule_id": f"CAPTURE-{technique_id}", "technique_id": technique_id}
                            ),
                            "success_criteria": f"{src_ip} is present in the runtime blocklist.",
                        }
                        store_alert(
                            "correlated", severity, title,
                            message=f"{title} — Detected by real-time capture analysis from Go agent packets.",
                            rule_id=f"CAPTURE-{technique_id}",
                            source_ip=src_ip,
                            technique_ids=tech,
                            response_preview=preview,
                            timestamp=ts,
                        )
                        logger.info("Capture detection: port scan from %s (%d ports) -> alert CAPTURE-%s",
                                    src_ip, len(ports), technique_id)

            # Phase 2: Match ALL recent events (capture + IDS alerts) against indexed rules
            logger.debug("Starting rule matching cycle...")
            _match_events_to_rules()
            logger.debug("Rule matching cycle complete")

        except Exception as exc:
            logger.warning("Capture detection error: %s", exc)

        time.sleep(10)  # Scan every 10 seconds


def _match_events_to_rules() -> None:
    """Match recent IDS alerts against all indexed detection rules.

    Queries alerts from suricata/wazuh/elastic (which carry technique_ids) and
    matches them to detection rules via parent-technique resolution.
    Sub-techniques like T1059.001 resolve to parent T1059 for rule matching.

    This wires all 1764 indexed rules into live detection.
    """
    import sqlite3
    import json
    import os
    from app_shared.unified_store import store_alert, store_event
    from app_shared.response_policy import choose_action, action_detail, render_command_preview
    from app_shared.state_paths import state_path

    db_path = state_path("fda_events.sqlite")
    if not db_path or not os.path.exists(db_path):
        return

    matched_rules: set[str] = set()
    matched_alerts: set[str] = set()

    # Query recent IDS alerts (suricata/wazuh/elastic) — these carry technique_ids
    ids_alerts = query_events(
        sources=["suricata", "wazuh", "elastic"],
        start=None, end=None, limit=100, query="",
    )
    if not ids_alerts:
        return

    # Query capture-agent events for network context enrichment
    capture_events = query_events(
        sources=["capture-agent"],
        start=None, end=None, limit=100, query="",
    )
    ip_ports: dict[str, set[int]] = {}
    for ev in capture_events:
        src = ev.get("source_ip", "") or ""
        port = ev.get("destination_port") or 0
        if src and src != "0.0.0.0" and port:
            ip_ports.setdefault(src, set()).add(port)

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Pre-query: collect all matched rule rows per alert
        alert_to_rules: dict[str, list[sqlite3.Row]] = {}
        for alert in ids_alerts:
            alert_id = alert.get("id", "")
            if not alert_id or alert_id in matched_alerts:
                continue

            tech_raw = alert.get("technique_ids", "[]") or "[]"
            try:
                if isinstance(tech_raw, str):
                    tech_ids = json.loads(tech_raw) if tech_raw else []
                elif isinstance(tech_raw, list):
                    tech_ids = tech_raw
                else:
                    tech_ids = []
            except (json.JSONDecodeError, TypeError):
                tech_ids = []
            if not tech_ids:
                continue

            # DEBUG: log first alert's tech resolution
            if len(alert_to_rules) == 0:
                logger.warning("RULE_MATCH_DEBUG_ALERT: alert_id=%s, tech_raw=%s, parsed_techs=%s, type=%s",
                               alert_id[:20], tech_raw, tech_ids, type(tech_raw).__name__)

            # Resolve sub-techniques to parent techniques
            parent_techs = set()
            for t in tech_ids:
                parent = t.split(".")[0] if "." in t else t
                parent_techs.add(parent)

            # DEBUG: log parent techs and rule query results
            if len(alert_to_rules) == 0:
                logger.warning("RULE_MATCH_DEBUG_PARENTS: parents=%s", parent_techs)

            # Query rules for each parent technique
            rule_rows = []
            for parent in parent_techs:
                cursor.execute(
                    "SELECT rule_id, title, description, severity, technique_ids FROM rules WHERE technique_ids LIKE '%' || ? || '%' LIMIT 5",
                    [parent],
                )
                fetched = cursor.fetchall()
                rule_rows.extend(fetched)
                if len(alert_to_rules) == 0:
                    logger.warning("RULE_MATCH_DEBUG_QUERY: parent=%s, rows_returned=%d", parent, len(fetched))

            alert_to_rules[alert_id] = rule_rows

        conn.close()

        # DEBUG: log what we found
        logger.warning("RULE_MATCH_DEBUG: ids_alerts=%d, alert_to_rules=%d, capture_events=%d, sample_alert_id=%s, sample_tech=%s",
                       len(ids_alerts), len(alert_to_rules), len(capture_events),
                       (ids_alerts[0].get("id","")[:20] if ids_alerts else "none"),
                       (ids_alerts[0].get("technique_ids","") if ids_alerts else "none"))

        # DEBUG: trace first alert processing
        if ids_alerts:
            first = ids_alerts[0]
            fid = first.get("id", "")
            ftech = first.get("technique_ids", "[]")
            logger.warning("RULE_MATCH_DEBUG_FIRST: alert_id=%s, tech_raw=%s, in_matched=%s",
                           fid[:20], ftech, fid in matched_alerts)

        # Process each alert with its matched rules
        logger.warning("RULE_MATCH_DEBUG_PROCESSING_START: processing %d alerts, matched_alerts=%d, matched_rules=%d",
                       len(ids_alerts), len(matched_alerts), len(matched_rules))
        sample_id = ids_alerts[0].get("id", "") if ids_alerts else ""
        logger.warning("RULE_MATCH_DEBUG_ALERTTORULES: sample_id=%s, entries=%d, first_entry_len=%d",
                       sample_id[:20], len(alert_to_rules), len(alert_to_rules.get(sample_id, [])))
        for alert in ids_alerts:
            alert_id = alert.get("id", "")
            if not alert_id or alert_id in matched_alerts:
                continue
            if alert_id not in alert_to_rules:
                logger.warning("RULE_MATCH_SKIP: alert_id=%s not in alert_to_rules", alert_id[:20])
                continue
            if len(alert_to_rules[alert_id]) == 0:
                logger.warning("RULE_MATCH_SKIP: alert_id=%s has empty rule list", alert_id[:20])
                continue

            tech_raw = alert.get("technique_ids", "[]") or "[]"
            try:
                tech_ids = json.loads(tech_raw) if tech_raw else []
            except (json.JSONDecodeError, TypeError):
                tech_ids = []
            if not tech_ids:
                continue

            source_ip = alert.get("source_ip", "") or ""
            dest_ip = alert.get("destination_ip", "") or ""
            host_name = alert.get("host_name", "") or ""
            ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

            port_count = len(ip_ports.get(source_ip, set()))
            port_context = f" (scanning {port_count} ports)" if port_count > 5 else ""

            logger.warning("RULE_MATCH_DEBUG_PROCESSING: alert_id=%s, rules=%d, source_ip=%s",
                           alert_id[:20], len(alert_to_rules[alert_id]), source_ip)

            logger.warning("RULE_MATCH_DEBUG_RULE_LOOP: about to process %d rules for alert %s (type=%s)",
                           len(alert_to_rules[alert_id]) if alert_to_rules.get(alert_id) else 0,
                           alert_id[:20],
                           type(alert_to_rules.get(alert_id)).__name__)
            for rule in (alert_to_rules.get(alert_id, []) or []):
                logger.warning("RULE_MATCH_DEBUG_RULE: processing rule %s for alert %s",
                               rule["rule_id"][:20], alert_id[:20])
                rule_id_matched = rule["rule_id"]
                if not rule_id_matched or rule_id_matched in matched_rules:
                    continue
                matched_rules.add(rule_id_matched)

                tech_ids_rule = json.loads(rule["technique_ids"]) if rule["technique_ids"] else []
                severity = rule["severity"] or "medium"
                rule_title = rule["title"] or rule_id_matched
                rule_desc = rule["description"] or ""

                alert_title = f"{rule_title} (matched from IDS alert)"
                alert_message = (
                    f"Detection rule '{rule_id_matched}' matched IDS alert via technique {tech_ids[0]}. "
                    f"Rule: {rule_desc[:200]}. "
                    f"Source: {source_ip or 'unknown'}, Host: {host_name or 'unknown'}{port_context}. "
                    f"Cross-matched against {len(matched_rules)} indexed detection rules."
                )

                store_event(
                    "suricata", ".alerts-security.alerts-fda",
                    engine="suricata",
                    title=alert_title,
                    message=alert_message,
                    severity=severity,
                    rule_id=rule_id_matched,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    host_name=host_name,
                    technique_ids=tech_ids_rule,
                    timestamp=ts,
                )

                action = choose_action(tech_ids_rule)
                detail = action_detail(action)
                preview = {
                    "title": detail["title"],
                    "summary": detail["summary"],
                    "preview_command": render_command_preview(
                        action,
                        {"source_ip": source_ip, "destination_ip": dest_ip, "rule_id": rule_id_matched,
                         "technique_id": tech_ids_rule[0] if tech_ids_rule else "", "host_name": host_name},
                    ),
                    "success_criteria": f"{source_ip or dest_ip or 'target'} is present in the runtime blocklist.",
                }
                store_alert(
                    "correlated", severity, alert_title,
                    message=alert_message,
                    rule_id=rule_id_matched,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    technique_ids=tech_ids_rule,
                    response_preview=preview,
                    timestamp=ts,
                )
                matched_alerts.add(alert_id)
                logger.info("Rule match: %s -> IDS from %s (rule %s, tech %s)",
                            alert_title, source_ip or "unknown", rule_id_matched, tech_ids[0])

    except Exception as exc:
        logger.warning("Rule matching SQLite error: %s", exc)


def start_capture_detection() -> None:
    """Start the capture event detection loop."""
    global _capture_detect_thread
    if _capture_detect_thread and _capture_detect_thread.is_alive():
        return
    _CAPTURE_DETECT_RUNNING.set()
    _capture_detect_thread = threading.Thread(
        target=_detect_from_capture_loop, daemon=True, name="capture-detection"
    )
    _capture_detect_thread.start()
    logger.info("Capture detection loop started (scanning for port scans, brute force)")


def stop_capture_detection() -> None:
    """Stop the capture event detection loop."""
    _CAPTURE_DETECT_RUNNING.clear()
    logger.info("Capture detection loop stopped")


# ---------------------------------------------------------------------------
# Real Orchestration Engine (ZeroClaw-style)
# ---------------------------------------------------------------------------
def _zeroclaw_loop():
    """Native ZeroClaw agent runner — processes hands via the real orchestration engine."""
    global _orch_engine_running
    _orch_engine_running = True
    try:
        from agents.orchestration_engine import start as orch_start, stop as orch_stop, is_running
        orch_start()
        # Keep the thread alive; the engine runs its own loop
        while _orch_engine_running and is_running():
            time.sleep(1)
    except Exception as exc:
        logger.error("Orchestration engine error: %s", exc)
        time.sleep(5)
    finally:
        _orch_engine_running = False
        try:
            from agents.orchestration_engine import stop as orch_stop
            orch_stop()
        except Exception:
            pass


def start_zeroclaw():
    """Start the real orchestration engine as a background thread."""
    global _zeroclaw_thread
    if _zeroclaw_thread and _zeroclaw_thread.is_alive():
        return
    _zeroclaw_thread = threading.Thread(target=_zeroclaw_loop, daemon=True, name="orchestration-engine")
    _zeroclaw_thread.start()
    logger.info("Orchestration engine started (ZeroClaw-style 18-hand pipeline)")


def stop_zeroclaw():
    """Stop the orchestration engine."""
    global _orch_engine_running
    _orch_engine_running = False
    logger.info("Orchestration engine stopped")


# ---------------------------------------------------------------------------
# Seed rules
# ---------------------------------------------------------------------------
def _seed_rules():
    """Index available Sigma + Elastic detection rules."""
    try:
        import yaml
    except ImportError:
        return
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            tomllib = None

    sigma_dir = _ROOT / "sigma" / "rules"
    if sigma_dir.exists():
        for yml in sigma_dir.rglob("*.yml"):
            try:
                data = yaml.safe_load(yml.read_text())
                if isinstance(data, dict) and data.get("id"):
                    index_rule({
                        "rule_id": data["id"], "engine": "sigma",
                        "title": data.get("title", ""),
                        "description": data.get("description", ""),
                        "severity": data.get("level", "medium"),
                        "technique_ids": [], "mitre_ids": [],
                        "file_path": str(yml), "raw": data,
                    })
            except Exception:
                pass

    det_dir = _ROOT / "detection-rules" / "rules"
    if det_dir.exists() and tomllib:
        for toml_file in det_dir.rglob("*.toml"):
            try:
                with open(toml_file, "rb") as f:
                    data = tomllib.load(f)
                rule = data.get("rule", {})
                rule_id = rule.get("rule_id") or rule.get("id")
                if rule_id:
                    technique_ids = []
                    for threat in rule.get("threat", []):
                        for tech in threat.get("technique", []):
                            if tech.get("id"):
                                technique_ids.append(tech["id"])
                    index_rule({
                        "rule_id": rule_id, "engine": "elastic",
                        "title": rule.get("name", ""),
                        "description": rule.get("description", ""),
                        "severity": rule.get("severity", "medium"),
                        "technique_ids": technique_ids, "mitre_ids": [],
                        "file_path": str(toml_file), "raw": data,
                    })
            except Exception:
                pass


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
def _build_response_preview(alert: dict) -> dict:
    tech = alert.get("technique_ids", [])
    action = choose_action(tech)
    detail = action_detail(action)
    payload = {
        "source_ip": alert.get("source_ip", ""),
        "destination_ip": alert.get("destination_ip", ""),
        "host_name": alert.get("host_name", ""),
        "rule_id": alert.get("rule_id", ""),
        "technique_id": tech[0] if tech else "",
    }
    preview_cmd = render_command_preview(action, payload)
    llm_tech = ""
    if NVIDIA_API_KEY:
        try:
            resp = requests.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": NVIDIA_MODEL,
                    "messages": [
                        {"role": "system", "content": (
                            "You are a cybersecurity analyst. Provide a concise technical explanation "
                            "of the security incident and a non-technical summary for executives. "
                            "Keep both under 150 words each."
                        )},
                        {"role": "user", "content": (
                            f"Alert: {alert.get('title','')}\n"
                            f"Message: {alert.get('message','')}\n"
                            f"Technique IDs: {', '.join(tech)}\n"
                            f"Severity: {alert.get('severity','medium')}\n"
                            f"Source IP: {alert.get('source_ip','')}\n"
                            f"Destination IP: {alert.get('destination_ip','')}\n"
                            f"Host: {alert.get('host_name','')}\n"
                            f"Recommended action: {action}"
                        )},
                    ],
                    "max_tokens": 512,
                    "temperature": 0.3,
                },
                timeout=15,
            )
            if resp.ok:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                if content:
                    llm_tech = content
        except Exception as exc:
            logger.debug("NVIDIA API error: %s", exc)

    return {
        "title": detail["title"],
        "summary": detail["summary"],
        "preview_command": preview_cmd,
        "success_criteria": detail["success_criteria"],
        "technical_explanation": llm_tech or detail["summary"],
        "nontechnical_explanation": f"Security incident detected. Recommended action: {action.replace('_', ' ')}.",
        "playbook": {"sections": []},
    }


def _current_run_id() -> str | None:
    cr = current_run()
    return cr.get("run_id") if cr.get("active") else None


def _build_dashboard(start=None, end=None, run_id=None) -> dict:
    # Dashboard aggregates scan millions of SQLite rows (tens of seconds on a
    # cold cache). Serve a cached/stale payload immediately and refresh it in
    # the background so no request ever waits on a full rebuild.
    cache_key = f"{start or ''}|{end or ''}|{run_id or _current_run_id()}"
    now = time.time()
    with _dashboard_lock:
        cached = _dashboard_cache.get(cache_key)
    if cached and (now - cached[0]) < _DASHBOARD_TTL_SECONDS:
        return cached[1]
    if cache_key in _dashboard_rebuilding:
        # A rebuild is already running: wait briefly for it rather than stacking
        # another multi-second query load on the store.
        deadline = now + _DASHBOARD_REBUILD_WAIT_SECONDS
        while time.time() < deadline:
            time.sleep(0.5)
            with _dashboard_lock:
                cached = _dashboard_cache.get(cache_key)
            if cached and cached[0] > now:
                return cached[1]
    if cached:
        # stale-while-revalidate: hand back the stale payload now, refresh async
        with _dashboard_lock:
            _dashboard_rebuilding.add(cache_key)
        threading.Thread(target=_rebuild_dashboard, args=(start, end, run_id, cache_key),
                         daemon=True, name="dashboard-revalidate").start()
        return cached[1]
    # No cached payload at all (cold start): register the key so concurrent
    # first requests coalesce onto one rebuild instead of stacking queries.
    with _dashboard_lock:
        _dashboard_rebuilding.add(cache_key)
    return _rebuild_dashboard(start, end, run_id, cache_key)


def _rebuild_dashboard(start=None, end=None, run_id=None, cache_key: str = "") -> dict:
    try:
        summary = get_analytics_summary(start=start, end=end, run_id=run_id or _current_run_id())
        summary["rules_total"] = _rule_count()
        latest = get_latest_alerts(limit=12)
        summary["latest_alerts"] = [{
            "id": a.get("id", a.get("run_id")),
            "engine": a.get("engine", "correlated"),
            "title": a.get("title", ""),
            "severity": a.get("severity", "medium"),
            "timestamp": a.get("timestamp", ""),
            "message": a.get("message", ""),
            "technique_ids": a.get("technique_ids", []),
            "response_preview": a.get("response_preview", {}),
        } for a in latest]
        if latest:
            rp = latest[0].get("response_preview", {})
            summary["response_preview"] = rp if isinstance(rp, dict) else json.loads(rp) if isinstance(rp, str) else {}
        else:
            summary["response_preview"] = {}
        summary["zeroclaw"] = {
            "available": _orch_engine_running,
            "summary": "Orchestration engine active" if _orch_engine_running else "Orchestration engine not running",
        }
        from agents.orchestration_engine import get_latest_runs
        engine_runs = get_latest_runs()
        _hands = []
        for _toml in sorted((_ROOT / "zeroclaw" / "hands").glob("*.toml")):
            _name = _toml.stem
            _run = engine_runs.get(_name)
            _hands.append({
                "hand_name": _name,
                "status": {"status": (_run or {}).get("status", {}).get("status", "active" if _orch_engine_running else "idle")},
            })
        summary["agents"] = {"hands": _hands}
        summary["response_actions_total"] = get_kv("response_actions_total", 0)
        with _dashboard_lock:
            _dashboard_cache[cache_key] = (time.time(), summary)
        return summary
    finally:
        with _dashboard_lock:
            _dashboard_rebuilding.discard(cache_key)
        with _dashboard_lock:
            _dashboard_rebuilding.discard(cache_key)


# --- dashboard payload cache (key -> (built_at, payload)) -------------------
_DASHBOARD_TTL_SECONDS = float(os.environ.get("FDA_DASHBOARD_TTL_SECONDS", "30"))
_DASHBOARD_REBUILD_WAIT_SECONDS = float(os.environ.get("FDA_DASHBOARD_REBUILD_WAIT_SECONDS", "45"))
_dashboard_cache: dict[str, tuple[float, dict]] = {}
_dashboard_rebuilding: set[str] = set()
_dashboard_lock = threading.Lock()


def _rule_count() -> int:
    conn = init_db()
    row = conn.execute("SELECT COUNT(*) as c FROM rules").fetchone()
    return row["c"] if row else 0


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="FDA Cyber Control (Native IDS)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def normalize_api_trailing_slash(request, call_next):
    """Frontend fetches use trailing slashes (/api/x/?limit=1); route them."""
    path = request.scope.get("path", "")
    if path.startswith("/api/") and path.endswith("/") and len(path) > 5:
        request.scope["path"] = path.rstrip("/")
    return await call_next(request)


@app.on_event("startup")
async def startup():
    init_db()
    _seed_rules()
    start_event_receiver()
    start_prune_loop()
    start_simulation()
    start_capture_detection()
    start_zeroclaw()
    threading.Thread(target=_build_dashboard, daemon=True, name="dashboard-warmup").start()
    logger.info("FDA Cyber Control API started")
    logger.info("NVIDIA API: %s", "enabled" if NVIDIA_API_KEY else "disabled")


@app.on_event("shutdown")
async def shutdown():
    stop_event_receiver()
    stop_prune_loop()
    stop_capture_detection()
    stop_zeroclaw()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "native",
        "simulation": _sim_running.is_set(),
        "zeroclaw": _orch_engine_running,
        "elasticsearch": es_available(),
    }


@app.get("/api/dashboard")
def get_dashboard(start: str | None = None, end: str | None = None, run_id: str | None = None):
    return _build_dashboard(start, end, run_id)


@app.get("/api/overview")
def get_overview(start: str | None = None, end: str | None = None, run_id: str | None = None):
    return _build_dashboard(start, end, run_id)


@app.get("/api/rules/search")
def rules_search(q: str, limit: int = 10, engines: str = ""):
    engine_list = [e.strip() for e in engines.split(",") if e.strip()]
    return {"query": q, "matches": search_rules(q, limit=limit, engines=engine_list or None)}


@app.get("/api/rules/{rule_id}")
def rule_detail(rule_id: str):
    rule = find_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.get("/api/rules/{rule_id}/evidence")
def rule_evidence(rule_id: str, limit: int = 20, start: str | None = None, end: str | None = None, run_id: str | None = None):
    rule = find_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    logs = query_events(sources=None, start=start, end=end, run_id=run_id, limit=limit,
                        query=f"{rule.get('title','')} {rule.get('description','')}")
    return {"rule": rule, "logs": logs[:limit], "alerts": []}


@app.get("/api/logs/search")
def logs_search(q: str, limit: int = 50, start: str | None = None, end: str | None = None, run_id: str | None = None):
    return {"query": q, "matches": query_events(sources=None, start=start, end=end, run_id=run_id, limit=limit, query=q)}


@app.get("/api/logs/live")
def logs_live(limit: int = 50, start: str | None = None, end: str | None = None, run_id: str | None = None):
    return {"items": query_events(sources=None, start=start, end=end, run_id=run_id, limit=limit, query="")}


@app.get("/api/logs/grouped")
def logs_grouped(limit: int = 150, start: str | None = None, end: str | None = None, run_id: str | None = None):
    all_events = query_events(sources=None, start=start, end=end, run_id=run_id, limit=500, query="")
    groups: dict[str, list] = {}
    for ev in all_events:
        key = ev.get("source_ip") or ev.get("host_name") or ev.get("source", "unknown") or "unknown"
        groups.setdefault(key, []).append(ev)
    result = []
    for key, items in sorted(groups.items(), key=lambda kv: kv[1][-1].get("timestamp", ""), reverse=True)[:limit]:
        latest = items[-1]
        result.append({
            "group_id": str(uuid4())[:12],
            "count": len(items),
            "start_time": items[0].get("timestamp", ""),
            "end_time": latest.get("timestamp", ""),
            "latest": latest,
            "ids": [e.get("id") for e in items],
        })
    return {"items": result}


@app.get("/api/logs/{log_id}/rules")
def log_rules(log_id: str, limit: int = 5):
    events = query_events(sources=None, limit=2000, query="")
    target = next((e for e in events if e.get("id") == log_id), None)
    if not target:
        return {"log": None, "matches": []}
    matches = search_rules(f"{target.get('title','')} {target.get('message','')}", limit=limit)
    return {"log": target, "matches": matches}


@app.get("/api/logs/{log_id}/detail")
def log_item_detail(log_id: str, start: str | None = None, end: str | None = None, run_id: str | None = None):
    payload = _log_detail(log_id, start=start, end=end, run_id=run_id)
    if not payload.get("log"):
        raise HTTPException(status_code=404, detail="Log not found")
    return payload


def _log_detail(log_id: str, start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict:
    events = query_events(sources=None, start=start, end=end, run_id=run_id, limit=2000, query="")
    target = next((e for e in events if e.get("id") == log_id), None)
    if not target:
        return {"log": None, "matches": [], "timeline": {"events": []}, "ip_context": {}}
    timeline = {
        "entity_type": "log",
        "entity_id": str(log_id),
        "count": len(events),
        "start_time": events[0].get("timestamp", "") if events else "",
        "stop_time": events[-1].get("timestamp", "") if events else "",
        "events": [{"kind": "log", "timestamp": e.get("timestamp", ""), "id": e.get("id"),
                     "title": e.get("title", ""), "source_ip": e.get("source_ip", ""),
                     "destination_ip": e.get("destination_ip", "")} for e in events[:300]],
    }
    matches = search_rules(f"{target.get('title','')} {target.get('message','')}", limit=8)
    ip_context = {}
    for field in ["source_ip", "destination_ip"]:
        ip_val = target.get(field, "")
        if ip_val:
            ip_events = query_events(sources=None, limit=100, query="")
            ip_rel = [e for e in ip_events if e.get(field, "") == ip_val]
            ip_context[field] = {"ip": ip_val, "timeline": {
                "entity_type": "ip", "entity_id": ip_val, "count": len(ip_rel),
                "start_time": ip_rel[0].get("timestamp", "") if ip_rel else "",
                "stop_time": ip_rel[-1].get("timestamp", "") if ip_rel else "",
                "events": [{"kind": "log", "timestamp": e.get("timestamp", ""), "id": e.get("id"),
                             "title": e.get("title", ""), "source_ip": e.get("source_ip", ""),
                             "destination_ip": e.get("destination_ip", "")} for e in ip_rel[:100]],
            }}
    return {"log": target, "matches": matches, "timeline": timeline, "ip_context": ip_context}


@app.get("/api/logs/analytics")
def get_logs_analytics(start: str | None = None, end: str | None = None, run_id: str | None = None):
    return get_analytics_summary(start=start, end=end, run_id=run_id or _current_run_id()).get("analytics", {})


@app.get("/api/alerts/live")
def live_alerts(limit: int = 50, start: str | None = None, end: str | None = None, run_id: str | None = None):
    return {"items": search_alerts(start=start, end=end, run_id=run_id, limit=limit)}


@app.post("/api/query/resolve")
async def resolve_query(request: Request):
    body = await request.json()
    q = body.get("query", "")
    limit = body.get("limit", 10)
    engines = body.get("engines", [])
    start = body.get("start")
    end = body.get("end")
    rules = search_rules(q, limit=limit, engines=engines or None)
    enriched = []
    for rule in rules[: min(len(rules), 6)]:
        ev = query_events(sources=None, start=start, end=end, limit=10,
                          query=f"{rule.get('title','')} {rule.get('description','')}")
        enriched.append({**rule, "positive_alert_count": 0, "positive_log_count": len(ev),
                          "evidence": {"logs": ev[:10], "alerts": []}})
    enriched.sort(key=lambda x: (x["positive_alert_count"] > 0, x["positive_alert_count"], x.get("score", 0)), reverse=True)
    return {"query": q, "matches": enriched}


@app.post("/api/chat")
async def soc_chat(payload: dict, request: Request):
    """SOC investigation chat — Triage + explain an incident. Returns a structured
    answer plus next-actions and evidence references the drawer can render."""
    body = await request.json()
    message = body.get("message", "")
    include_llm = bool(NVIDIA_API_KEY)
    if not message.strip():
        return {"answer": "", "next_actions": [], "llm_generated": False, "references": {}}
    try:
        # Pull live context the drawer can attribute to rule/log hits.
        dash = _build_dashboard()
        latest = dash.get("latest_alerts", []) or []
        references = {
            "rule_hits": [
                {"rule_id": a.get("rule_id",""), "engine": a.get("engine",""), "id": a.get("id","")}
                for a in latest[:6]
            ],
            "log_hits": [],
        }
        ctx = (
            f"Latest alerts ({len(latest)}):\n"
            + "\n".join(
                f"- [{a.get('severity','?')}] {a.get('title','')}: {a.get('message','')[:200]}"
                for a in latest[:5]
            )
        )
        system = (
            "You are FDA Cyber Control's SOC investigation assistant. "
            "Return STRICT JSON with these exact keys: answer (string, concise triage + what to do next), "
            "next_actions (list of 2-5 strings, concrete operator actions), "
            "llm_generated (true). No markdown, no backticks, no '```json' wrapper — only the JSON object."
        )
        user_msg = f"Dashboard context:\n{ctx}\n\nQuestion: {message}"
        answer_text = message
        next_actions: list[str] = []
        resp_ok = False
        if include_llm:
            resp = requests.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": NVIDIA_MODEL,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                    "max_tokens": 1024,
                    "temperature": 0.2,
                },
                timeout=120,
            )
            resp_ok = resp.ok
            if resp_ok:
                text = resp.json()["choices"][0]["message"]["content"].strip()
                # Try to parse the JSON the model emitted.
                try:
                    parsed = json.loads(text)
                    answer_text = parsed.get("answer", text)
                    next_actions = parsed.get("next_actions", [])
                    if not isinstance(next_actions, list):
                        next_actions = []
                except (json.JSONDecodeError, KeyError, IndexError):
                    answer_text = text
            else:
                answer_text = f"API error {resp.status_code}"
        return {
            "answer": answer_text,
            "next_actions": next_actions,
            "llm_generated": include_llm and resp_ok,
            "references": references,
        }
    except Exception as exc:
        return {
            "answer": f"Error: {exc}",
            "next_actions": [],
            "llm_generated": False,
            "references": {"rule_hits": [], "log_hits": []},
        }


@app.get("/api/playbooks/{technique_id}")
def playbook_detail(technique_id: str):
    from app_shared.mitre_playbooks import resolve_playbook_path
    playbook_root = Path(os.environ.get("SOAR_PLAYBOOK_ROOT", str(_ROOT / "vendor" / "MITRE-ATT_CK-Playbooks" / "Playbooks")))
    path = resolve_playbook_path(technique_id, playbook_root)
    content = ""
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            pass
    sections = []
    if content:
        for section in content.split("\n## "):
            if section.strip():
                heading, _, body = section.partition("\n\n")
                sections.append({"title": heading.strip().replace("#", "").strip(), "paragraphs": [body.strip()]})
    return {"technique_id": technique_id, "path": str(path) if path else "", "available": bool(path), "sections": sections}


@app.get("/api/agents/live")
def agents_live():
    """ZeroClaw hands with their latest real run records (frontend HandRun contract)."""
    from agents.orchestration_engine import get_latest_runs

    engine_runs = get_latest_runs()
    hands: list[dict] = []
    hands_dir = _ROOT / "zeroclaw" / "hands"
    for toml_file in sorted(hands_dir.glob("*.toml")):
        name = toml_file.stem
        run = engine_runs.get(name)
        if run:
            hands.append(run)
        else:
            hands.append({
                "hand_name": name,
                "run_id": f"{name}-pending",
                "status": {"status": "active" if _orch_engine_running else "idle"},
                "findings": [],
                "steps": [],
                "metrics": {},
            })
    return {"hands": hands, "last_update": now_utc(), "count": len(hands)}


@app.get("/api/agents/{hand_name}/history")
def agent_history(hand_name: str, limit: int = 30):
    from agents.orchestration_engine import get_hand_context
    ctx = get_hand_context(hand_name)
    items = ctx.get("history", [])[:limit]
    return {"items": items, "total_runs": ctx.get("total_runs", 0)}


@app.get("/api/agents/{hand_name}/run")
def agent_latest_run(hand_name: str):
    """Return the latest run result for a specific hand."""
    from agents.orchestration_engine import get_hand_run
    run = get_hand_run(hand_name)
    if not run:
        raise HTTPException(status_code=404, detail=f"No run found for hand '{hand_name}'")
    return run


@app.get("/api/agents/runs")
def agent_all_runs():
    """Return latest run results for all hands."""
    from agents.orchestration_engine import get_latest_runs
    return {"hands": get_latest_runs()}


@app.get("/api/zeroclaw/status")
def zeroclaw_status():
    from agents.orchestration_engine import get_iterations
    return {
        "available": _orch_engine_running,
        "summary": "Orchestration engine active" if _orch_engine_running else "Orchestration engine stopped",
        "hands_dir": str(_ROOT / "zeroclaw" / "hands"),
        "iterations": get_iterations(),
    }


@app.get("/api/zeroclaw/health")
def zeroclaw_health():
    from agents.orchestration_engine import get_iterations
    return {"available": _orch_engine_running, "iterations": get_iterations() if _orch_engine_running else 0}


@app.get("/api/runs/current")
def current_run_endpoint():
    return current_run()


@app.get("/api/runs/history")
def run_history_endpoint(limit: int = 20):
    return {"items": run_history(limit=limit)}


@app.get("/api/runs/{run_id}")
def run_by_id(run_id: str):
    conn = init_db()
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Run not found")
    return dict(row)


@app.post("/api/runs/start")
async def start_run_endpoint(request: Request):
    body = await request.json()
    return start_run(name=body.get("name", ""), note=body.get("note", ""))


@app.post("/api/runs/stop")
def stop_run_endpoint():
    return stop_run()


@app.post("/api/runs/save")
async def save_run_endpoint(request: Request):
    body = await request.json()
    return save_run(name=body.get("name", ""), note=body.get("note", ""))


@app.get("/api/retention/status")
def get_retention_status():
    conn = init_db()
    total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
    hours = read_retention_hours()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    return {"retention_hours": hours, "cutoff": cutoff, "total_events": total, "mode": "elasticsearch+sqlite" if es_available() else "sqlite"}


@app.post("/api/retention/prune")
def trigger_prune():
    hours = read_retention_hours()
    return prune_events(hours)


@app.put("/api/retention/config")
def update_retention(hours: int = 24):
    os.environ["RETENTION_HOURS"] = str(hours)
    return {"retention_hours": hours, "updated": True}


@app.get("/api/response/policy")
def get_policy():
    return load_policy()


@app.put("/api/response/policy")
async def put_policy(request: Request):
    body = await request.json()
    return save_policy(body)


@app.get("/api/response/runtime")
def get_runtime():
    return {}


@app.get("/api/honeypot/sessions")
def honeypot_sessions(limit: int = 12):
    return {"items": []}


@app.get("/api/honeypot/sessions/{session_id}")
def honeypot_session(session_id: str):
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/api/cloud/exposure")
async def cloud_exposure():
    """Run cloud asset exposure checks (AWS/Azure/GCP metadata)."""
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "check_cloud_exposure.py")],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return {"status": "ok", "findings": json.loads(result.stdout)}
        return {"status": "error", "error": result.stderr}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@app.get("/api/packs")
async def list_packs():
    """List available detection packs (directories under detection-rules/rules/)."""
    from pathlib import Path
    rules_dir = _ROOT / "detection-rules" / "rules"
    packs = []
    if rules_dir.exists():
        for d in sorted(rules_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("_"):
                rule_count = len(list(d.rglob("*.toml")))
                packs.append({
                    "id": d.name,
                    "name": d.name.replace("_", " ").title(),
                    "description": f"Detection rules for {d.name}",
                    "rules_count": rule_count,
                    "category": d.name,
                    "tags": [d.name],
                    "author": "fda",
                    "version": "1.0",
                    "updated_at": "",
                })
    return {"packs": packs}


@app.get("/api/packs/{pack_id}/rules")
async def pack_rules(pack_id: str):
    """List rules in a detection pack."""
    from pathlib import Path
    import tomllib
    rules_dir = _ROOT / "detection-rules" / "rules" / pack_id
    rules = []
    if rules_dir.exists():
        for toml_file in sorted(rules_dir.rglob("*.toml")):
            try:
                with open(toml_file, "rb") as f:
                    data = tomllib.load(f)
                rule = data.get("rule", {})
                rule_id = rule.get("rule_id") or rule.get("id") or toml_file.stem
                tech_ids = [t["id"] for t in rule.get("threat", []) for t in t.get("technique", []) if t.get("id")]
                rules.append({
                    "id": rule_id,
                    "title": rule.get("name", ""),
                    "severity": rule.get("severity", "medium"),
                    "engine": "elastic",
                    "technique_ids": tech_ids,
                    "description": rule.get("description", ""),
                    "enabled": True,
                })
            except Exception:
                pass
    return {"rules": rules}


@app.get("/api/marketplace/packs")
async def marketplace_packs():
    """List marketplace packs (currently same as local packs)."""
    from pathlib import Path
    rules_dir = _ROOT / "detection-rules" / "rules"
    packs = []
    if rules_dir.exists():
        for d in sorted(rules_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("_"):
                rule_count = len(list(d.rglob("*.toml")))
                packs.append({
                    "id": d.name,
                    "name": d.name.replace("_", " ").title(),
                    "description": f"Detection rules for {d.name}",
                    "rules_count": rule_count,
                    "category": d.name,
                    "tags": [d.name],
                    "author": "fda",
                    "version": "1.0",
                    "downloads": 0,
                    "rating": 0,
                })
    return {"packs": packs}


@app.get("/api/responses/audit")
async def response_audit_log(limit: int = 200):
    """Audit log of all enforcement actions + AI decisions (frontend AuditEntry contract)."""
    log_path = state_path("response", "control_actions.jsonl")
    entries = []
    if log_path.exists():
        for raw in read_jsonl(log_path, limit=limit):
            if not isinstance(raw, dict):
                continue
            action = str(raw.get("action") or "unknown")
            status = str(raw.get("status") or ("executed" if raw.get("updated") else "recorded"))
            entries.append({
                "timestamp": raw.get("@timestamp") or raw.get("timestamp") or raw.get("updated_at") or "",
                "type": "observation" if action == "observe_only" else "enforcement",
                "rule_id": raw.get("rule_id") or "",
                "source_ip": raw.get("source_ip") or "",
                "action": action,
                "verdict": status,
                "severity": raw.get("severity"),
                "summary": raw.get("message") or "",
                "technique_id": raw.get("technique_id"),
                "username": raw.get("username") or "",
            })

    # ZeroClaw runtime decisions context
    zeroclaw_state = state_path("zeroclaw", "runtime.json")
    zeroclaw_info = {}
    if zeroclaw_state.exists():
        zeroclaw_info = read_json(zeroclaw_state)

    return {
        "items": entries,
        "zeroclaw": zeroclaw_info,
        "total": len(entries),
    }


@app.post("/api/response/preview")
async def response_preview(request: Request):
    body = await request.json()
    alert_id = body.get("alert_id", "")
    alerts = search_alerts(limit=500)
    alert = next((a for a in alerts if a.get("id") == alert_id), None)
    if not alert:
        latest = get_latest_alerts(limit=1)
        if latest:
            alert = latest[0]
    if alert:
        return _build_response_preview(alert)
    return {"error": "No alerts available"}


@app.post("/api/response/execute")
async def execute_response(request: Request) -> dict:
    body = await request.json()
    # Accept both flat format (from incidents component) and nested format
    # Flat: {"action": "...", "source_ip": "...", "rule_id": "..."}
    # Nested: {"actions": ["..."], "payload": {"source_ip": "...", ...}}
    flat_action = body.get("action", "")
    actions = body.get("actions", [])
    payload = body.get("payload", {})

    # If flat format detected, convert to nested
    if flat_action and not actions:
        actions = [flat_action]
        payload = {k: v for k, v in body.items() if k != "action"}

    if not actions:
        return {
            "executed": [],
            "count": 0,
            "success": False,
            "dry_run": DRY_RUN,
            "results": [{"error": "No actions provided. Expected 'actions' array or 'action' string."}],
        }

    # Import the real response engine
    from agents.response_engine import execute_response_action, DRY_RUN

    results = []
    for action in actions:
        result = execute_response_action(
            action=action,
            source_ip=payload.get("source_ip", ""),
            destination_ip=payload.get("destination_ip", ""),
            username=payload.get("username", ""),
            target_path=payload.get("target_path", "/api/login"),
            requests_per_minute=payload.get("requests_per_minute", 30),
            rule_id=payload.get("rule_id", ""),
            technique_id=payload.get("technique_id", ""),
            engine=payload.get("engine", ""),
            message=payload.get("message", ""),
        )
        results.append(result)

    set_kv("response_actions_total", get_kv("response_actions_total", 0) + len(actions))
    return {
        "executed": actions,
        "count": len(actions),
        "success": True,
        "dry_run": DRY_RUN,
        "results": results,
    }


@app.get("/api/timeline")
def get_timeline(entity_type: str, entity_id: str, start: str | None = None, end: str | None = None,
                 run_id: str | None = None, limit: int = 200):
    events = query_events(sources=None, start=start, end=end, run_id=run_id, limit=limit, query="")
    if entity_type == "ip":
        filtered = [e for e in events if e.get("source_ip") == entity_id or e.get("destination_ip") == entity_id]
    elif entity_type == "log":
        filtered = [e for e in events if e.get("id") == entity_id]
    elif entity_type == "rule":
        filtered = [e for e in events if e.get("rule_id") == entity_id]
    elif entity_type == "run":
        filtered = [e for e in events if e.get("run_id") == entity_id]
    else:
        filtered = events[:limit]
    return {
        "entity_type": entity_type, "entity_id": entity_id, "count": len(filtered),
        "start_time": filtered[0].get("timestamp", "") if filtered else "",
        "stop_time": filtered[-1].get("timestamp", "") if filtered else "",
        "events": [{"kind": "log", "timestamp": e.get("timestamp", ""), "id": e.get("id"),
                     "title": e.get("title", ""), "source_ip": e.get("source_ip", ""),
                     "destination_ip": e.get("destination_ip", "")} for e in filtered],
    }


@app.get("/api/stream/overview")
async def stream_overview(request: Request, start: str | None = None, end: str | None = None):
    async def event_stream():
        while not await request.is_disconnected():
            try:
                payload = _build_dashboard(start, end, None)
                yield f"data: {json.dumps(payload)}\n\n"
            except Exception as exc:
                yield f"event: error\ndata: {json.dumps({'detail': str(exc)})}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Real event ingestion endpoint (Go agent -> HTTP -> SQLite)
# ---------------------------------------------------------------------------
@app.post("/api/events/ingest")
async def ingest_event_endpoint(request: Request):
    """Ingest captured network events from the Go agent."""
    try:
        body = await request.json()
        # Accept single event or batch
        if isinstance(body, list):
            results = []
            for event in body:
                result = ingest_event(event)
                results.append(result)
            return {"status": "ok", "ingested": len(results)}
        else:
            result = ingest_event(body)
            return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/events/status")
async def event_status():
    """Show event receiver status."""
    with _event_queue_lock:
        queue_size = len(_event_queue)
    return {
        "status": "ok",
        "event_queue_size": queue_size,
        "event_receiver_running": _event_receiver_running.is_set(),
    }


# ---------------------------------------------------------------------------
# Frontend SPA catch-all (MUST be registered LAST)
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    if FRONTEND_DIST.exists():
        index_file = FRONTEND_DIST / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
    return HTMLResponse("<h1>FDA Cyber Control</h1><p>Frontend not built.</p>")


@app.get("/_next/static/{path:path}")
def serve_next_static(path: str):
    if not FRONTEND_DIST.exists():
        raise HTTPException(status_code=404)
    file_path = FRONTEND_DIST / "_next" / "static" / path
    if file_path.is_file():
        return FileResponse(file_path)
    raise HTTPException(status_code=404)


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve pre-rendered page HTML for app routes; fall back to the SPA shell."""
    if full_path.startswith("api/") or full_path.startswith("_next/"):
        raise HTTPException(status_code=404)
    if FRONTEND_DIST.exists():
        candidate = (FRONTEND_DIST / full_path).resolve()
        dist_root = FRONTEND_DIST.resolve()
        if candidate.is_file() and dist_root in candidate.parents:
            return FileResponse(candidate)
        for rel in ((full_path.rstrip("/"), "index.html"), ("index.html",)):
            page_file = FRONTEND_DIST.joinpath(*[p for p in rel if p]).resolve()
            if page_file.is_file() and dist_root in page_file.parents:
                return FileResponse(page_file)
        index_file = FRONTEND_DIST / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
    return HTMLResponse("<h1>Frontend not available</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.agents_api:app", host="0.0.0.0", port=8000, reload=False)
