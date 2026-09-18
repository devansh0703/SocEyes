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

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
# Event receiver is always on (no interval needed — it polls queue every 0.5s)
FRONTEND_DIST = Path(os.environ.get("FRONTEND_DIST", _ROOT / "frontend"))

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
    summary["response_actions_total"] = get_kv("response_actions_total", 0)
    return summary


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


@app.on_event("startup")
async def startup():
    init_db()
    _seed_rules()
    start_event_receiver()
    start_prune_loop()
    start_zeroclaw()
    logger.info("FDA Cyber Control API started")
    logger.info("NVIDIA API: %s", "enabled" if NVIDIA_API_KEY else "disabled")


@app.on_event("shutdown")
async def shutdown():
    stop_event_receiver()
    stop_prune_loop()
    stop_zeroclaw()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "native",
        "simulation": _event_receiver_running.is_set(),
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
async def chat(request: Request):
    body = await request.json()
    message = body.get("message", "")
    if not NVIDIA_API_KEY:
        return {"response": "NVIDIA API key not configured. Set NVIDIA_API_KEY environment variable.", "model": None}
    try:
        dash = _build_dashboard()
        dash_context = {k: v for k, v in dash.items() if k != "latest_alerts"}
        ctx_json = json.dumps(dash_context, default=str)[:2000]
        resp = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
            json={"model": NVIDIA_MODEL, "messages": [
                {"role": "system", "content": "You are FDA Cyber Control's AI assistant."},
                {"role": "user", "content": f"Dashboard: {ctx_json}\n\nQuestion: {message}"},
            ], "max_tokens": 1000, "temperature": 0.3},
            timeout=15,
        )
        if resp.ok:
            return {"response": resp.json()["choices"][0]["message"]["content"].strip(), "model": NVIDIA_MODEL}
        return {"response": f"Error: {resp.status_code}", "model": NVIDIA_MODEL}
    except Exception as exc:
        return {"response": f"Error: {exc}", "model": NVIDIA_MODEL}


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
    hands_dir = _ROOT / "zeroclaw" / "hands"
    hands = []
    if hands_dir.exists():
        for toml_file in sorted(hands_dir.glob("*.toml")):
            hands.append({"hand": toml_file.stem, "status": "active" if _orch_engine_running else "idle"})
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


@app.get("/api/responses/audit")
async def response_audit_log(limit: int = 200):
    """Return audit log of all enforcement actions + AI decisions."""
    log_path = state_path("response", "control_actions.jsonl")
    entries = []
    if log_path.exists():
        entries = read_jsonl(log_path, limit=limit)

    # Also include enforcement log from core/enforce.py
    enforce_log = state_path("response", "enforce.log")
    enforce_entries = []
    if enforce_log.exists():
        with open(enforce_log) as f:
            for line in f:
                line = line.strip()
                if line:
                    enforce_entries.append({"raw": line})
        enforce_entries = enforce_entries[-limit:]

    # Also include ZeroClaw runtime decisions
    zeroclaw_state = state_path("zeroclaw", "runtime.json")
    zeroclaw_info = {}
    if zeroclaw_state.exists():
        zeroclaw_info = read_json(zeroclaw_state)

    return {
        "items": entries + enforce_entries,
        "zeroclaw": zeroclaw_info,
        "total": len(entries) + len(enforce_entries),
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
    actions = body.get("actions", [])
    payload = body.get("payload", {})

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
    """Serve index.html for SPA routes."""
    if full_path.startswith("api/") or full_path.startswith("_next/"):
        raise HTTPException(status_code=404)
    if FRONTEND_DIST.exists():
        index_file = FRONTEND_DIST / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
    return HTMLResponse("<h1>Frontend not available</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.agents_api:app", host="0.0.0.0", port=8000, reload=False)
