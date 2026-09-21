#!/usr/bin/env python3
"""
SocEyes — Main API Server (Native IDS)

Single-process FastAPI server with SQLite backend.
Serves frontend, API, attack simulation, and all agent endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
from backend.app.paths import _ROOT

from app_shared.unified_store import (
    get_analytics_summary, get_latest_alerts, init_db,
    prune_events, query_events, search_alerts, search_rules,
    get_kv, set_kv, update_alert_preview,
    start_run, stop_run, current_run, save_run, run_history,
    find_rule, index_rule, es_available,
)
from app_shared.response_policy import (
    choose_action, action_detail, render_command_preview,
    load_policy, save_policy,
)
from app_shared.response_state import append_action_log, now_iso as _now_iso
from app_shared.nvidia_ai import ai_triage, chat_completion
from app_shared.text_utils import now_utc
from app_shared.retention import read_retention_hours
from app_shared.state_paths import read_json, read_jsonl, state_path
from backend.app.runtime_controls import (
    check_and_count_rate_limit,
    client_ip_from_request,
    enforcement_response,
    is_blocked_ip,
)
from backend.app.services.dashboard import DashboardService
from backend.app.services.event_receiver import (
    event_queue_size,
    ingest_event,
    start_event_receiver,
    start_prune_loop,
    stop_event_receiver,
    stop_prune_loop,
)
from backend.app.services.capture_detection import start_capture_detection, stop_capture_detection
from backend.app.services.seed_rules import seed_rules
from agents.response_engine import execute_response_action
from agents.response_engine import dry_run as response_dry_run
from agents.response_engine import start_engine_thread, stop_engine_thread

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
# Event receiver is always on (no interval needed — it polls queue every 0.5s)
def _default_frontend_dist() -> Path:
    """Prefer the Next.js static export (frontend/out); fall back to frontend/"""
    out = _ROOT / "frontend" / "out"
    if (out / "index.html").exists():
        return out
    return _ROOT / "frontend"


FRONTEND_DIST = Path(os.environ.get("FRONTEND_DIST", _default_frontend_dist()))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("soceyes.api")

# ---------------------------------------------------------------------------
# Orchestration engine state (the real ZeroClaw engine). Event receiver,
# retention and capture-detection threads live in backend/app/services/.
# ---------------------------------------------------------------------------
_orch_engine_running = False
_zeroclaw_thread: threading.Thread | None = None

# Ensure log directory exists
_log_dir = _ROOT / "state" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)


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
# API helpers
# ---------------------------------------------------------------------------
def _build_response_preview(alert: dict) -> dict:
    """Build the operator-facing response preview, enriched with AI triage."""
    tech = alert.get("technique_ids", []) or []
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

    # AI triage owns the explanations: packet context + correlated timeline +
    # MITRE mapping, with a deterministic fallback when no API key is set.
    triage = ai_triage({
        "title": alert.get("title", ""),
        "message": alert.get("message", ""),
        "severity": alert.get("severity", "medium"),
        "source_ip": alert.get("source_ip", ""),
        "destination_ip": alert.get("destination_ip", ""),
        "host_name": alert.get("host_name", ""),
        "rule_id": alert.get("rule_id", ""),
        "engine": alert.get("engine", ""),
        "technique_ids": tech,
    })
    return {
        "title": detail["title"],
        "summary": detail["summary"],
        "preview_command": preview_cmd,
        "success_criteria": detail["success_criteria"],
        "technical_explanation": triage.get("technical_details") or triage.get("summary") or detail["summary"],
        "nontechnical_explanation": triage.get("summary") or f"Security incident detected. Recommended action: {action.replace('_', ' ')}.",
        "ai_triage": triage,
        "playbook": {"sections": []},
    }


def _current_run_id() -> str | None:
    cr = current_run()
    return cr.get("run_id") if cr.get("active") else None


def _rule_count() -> int:
    conn = init_db()
    row = conn.execute("SELECT COUNT(*) as c FROM rules").fetchone()
    return row["c"] if row else 0


def _orch_engine_running_fn() -> bool:
    return _orch_engine_running


# Dashboard service: cached aggregates with stale-while-revalidate
# (backend/app/services/dashboard.py owns the cache mechanics).
_dashboard = DashboardService(
    orchestration_running=lambda: _orch_engine_running,
    rule_count=_rule_count,
    run_id_provider=_current_run_id,
)


def _build_dashboard(start=None, end=None, run_id=None) -> dict:
    return _dashboard.build(start=start, end=end, run_id=run_id)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="SocEyes (Native IDS)")
_allowed_origins = [
    origin.strip() for origin in
    os.environ.get("SOC_ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
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


@app.middleware("http")
async def enforce_runtime_controls(request, call_next):
    """Apply the live response control plane to API traffic.

    Blocklisted source IPs are refused outright, and per-path/per-IP rate
    limits from state/response/runtime/rate_limits.json are enforced. The
    control files are written by the response engine (scripts/apply_response_control.py),
    so an operator can throttle or ban an actor without restarting the API.
    """
    path = request.scope.get("path", "")
    if path.startswith("/api/"):
        client_ip = client_ip_from_request(request)
        if client_ip and is_blocked_ip(client_ip):
            return enforcement_response(f"Source IP {client_ip} is blocklisted", 403)
        if client_ip:
            allowed, remaining, rule = check_and_count_rate_limit(path, client_ip)
            if not allowed:
                return enforcement_response(
                    f"Rate limit exceeded for {path} ({rule.get('requests_per_minute')} req/min)", 429,
                )
    return await call_next(request)


@app.on_event("startup")
async def startup():
    init_db()
    seed_rules(_ROOT)
    start_event_receiver()
    start_prune_loop()
    start_capture_detection()
    start_zeroclaw()
    start_engine_thread()
    threading.Thread(target=_build_dashboard, daemon=True, name="dashboard-warmup").start()
    logger.info("SocEyes API started")
    logger.info("NVIDIA API: %s", "enabled" if NVIDIA_API_KEY else "disabled")
    logger.info("Response enforcement: %s", "dry-run" if response_dry_run() else "LIVE")


@app.on_event("shutdown")
async def shutdown():
    stop_engine_thread()
    stop_event_receiver()
    stop_prune_loop()
    stop_capture_detection()
    stop_zeroclaw()
    from app_shared.db_maintenance import stop_wal_maintenance
    stop_wal_maintenance()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "native",
        # The attack simulator was removed from the server (test-only now);
        # the flag is kept in the contract so dashboards can assert it stays false.
        "simulation": False,
        "zeroclaw": _orch_engine_running,
        "elasticsearch": es_available(),
    }


@app.get("/api/threat-intel")
def threat_intel_status():
    """Indicator-store stats: how many IOCs are loaded from which feeds."""
    from app_shared import threat_intel as ti

    return ti.ti_stats()


@app.post("/api/threat-intel/refresh")
def threat_intel_refresh():
    """Force a feed sync now (bypasses the SOC_TI_SYNC_SEC throttle)."""
    from app_shared import threat_intel as ti

    return ti.sync_feeds(force=True)


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
async def soc_chat(request: Request):
    """SOC investigation chat — Triage + explain an incident. Returns a structured
    answer plus next-actions and evidence references the drawer can render."""
    body = await request.json()
    message = str(body.get("message", ""))
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
            "You are SocEyes's SOC investigation assistant. "
            "Return STRICT JSON with these exact keys: answer (string, concise triage + what to do next), "
            "next_actions (list of 2-5 strings, concrete operator actions), "
            "llm_generated (true). No markdown, no backticks, no '```json' wrapper — only the JSON object."
        )
        user_msg = f"Dashboard context:\n{ctx}\n\nQuestion: {message}"
        answer_text = message
        next_actions: list[str] = []
        llm_generated = False
        content = chat_completion(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=1024,
            temperature=0.2,
            timeout=120,
        )
        if content:
            llm_generated = True
            # The model is asked for strict JSON; fall back to raw text.
            try:
                parsed = json.loads(content)
                answer_text = parsed.get("answer", content)
                next_actions = parsed.get("next_actions", [])
                if not isinstance(next_actions, list):
                    next_actions = []
            except (json.JSONDecodeError, KeyError, IndexError):
                answer_text = content
        return {
            "answer": answer_text,
            "next_actions": next_actions,
            "llm_generated": llm_generated,
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
    """Live response control-plane state (blocklists, rate limits, disabled
    accounts) — read from state/response/runtime control files."""
    from backend.app.runtime_controls import load_controls
    return load_controls()


@app.get("/api/honeypot/sessions")
def honeypot_sessions(limit: int = 12):
    """Real honeypot sessions from state/honeypot/sessions.jsonl (written by the
    response engine when containment containers are created)."""
    sessions_file = state_path("honeypot", "sessions.jsonl")
    items = []
    if sessions_file.exists():
        for raw in read_jsonl(sessions_file, limit=limit):
            if not isinstance(raw, dict):
                continue
            items.append({
                "session_id": raw.get("container_name") or raw.get("container_id", ""),
                "container_id": raw.get("container_id", ""),
                "container_name": raw.get("container_name", ""),
                "created_at": raw.get("created_at", ""),
                "severity": raw.get("severity", "medium"),
                "source_ip": raw.get("source_ip", ""),
                "events_captured": int(raw.get("events_captured", 0) or 0),
                "log_path": raw.get("log_path", ""),
                "message": raw.get("message", ""),
            })
    return {"items": items, "total": len(items)}


@app.get("/api/honeypot/sessions/{session_id}")
def honeypot_session(session_id: str):
    sessions_file = state_path("honeypot", "sessions")
    session_file = sessions_file / session_id / "session.json"
    if not session_file.exists():
        raise HTTPException(status_code=404, detail="Honeypot session not found")
    return read_json(session_file)


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
                    "author": "soceyes",
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
    """List marketplace packs — real data only, no fabricated download counts or ratings."""
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
                    "author": "soceyes",
                    "version": "1.0",
                })
    return {"packs": packs}


@app.get("/api/marketplace/packs/{pack_id}/download")
async def download_pack(pack_id: str):
    """Download a detection pack as a zip of its rule files (real assets, built on demand)."""
    import io
    import zipfile
    rules_dir = _ROOT / "detection-rules" / "rules" / pack_id
    if not rules_dir.is_dir() or pack_id.startswith("_"):
        raise HTTPException(status_code=404, detail=f"Pack '{pack_id}' not found")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for toml_file in sorted(rules_dir.rglob("*.toml")):
            zf.write(toml_file, arcname=str(toml_file.relative_to(rules_dir)))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{pack_id}.zip"'},
    )


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
            "dry_run": response_dry_run(),
            "results": [{"error": "No actions provided. Expected 'actions' array or 'action' string."}],
        }

    # Operator policy gate: manual execution can be disabled entirely.
    policy = load_policy()
    if not policy.get("allow_manual_execute", True):
        return {
            "executed": [],
            "count": 0,
            "success": False,
            "dry_run": response_dry_run(),
            "results": [{"error": "Manual response execution is disabled by the response policy."}],
        }

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

    # Stamp the originating alert (if any) and audit-log the manual action.
    alert_id = payload.get("alert_id", "")
    failed = any(r.get("error") for r in results)
    executed_any = bool(results) and not failed
    manual_status = (
        "failed" if not executed_any
        else "executed" if not response_dry_run()
        else "simulated"
    )
    if alert_id:
        update_alert_preview(alert_id, {
            "status": manual_status,
            "recommended_action": actions[0],
            "manual": True,
            "updated_at": _now_iso(),
        })
    append_action_log({
        "@timestamp": _now_iso(),
        "action": actions[0],
        "source_ip": payload.get("source_ip", ""),
        "destination_ip": payload.get("destination_ip", ""),
        "rule_id": payload.get("rule_id", ""),
        "technique_id": payload.get("technique_id", ""),
        "engine": payload.get("engine", ""),
        "alert_id": alert_id,
        "status": manual_status,
        "message": f"Manual response ({'dry-run' if response_dry_run() else 'LIVE'}): {', '.join(actions)}",
        "dry_run": response_dry_run(),
        "execution": results[0] if len(results) == 1 else results,
    })

    return {
        "executed": actions,
        "count": len(actions),
        "success": True,
        "dry_run": response_dry_run(),
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
            run_id = _current_run_id()
            results = []
            for event in body:
                results.append(ingest_event(event, run_id))
            return {"status": "ok", "ingested": len(results)}
        else:
            return ingest_event(body, _current_run_id())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/events/status")
async def event_status():
    """Show event receiver status."""
    from backend.app.services.event_receiver import event_receiver_running
    return {
        "status": "ok",
        "event_queue_size": event_queue_size(),
        "event_receiver_running": event_receiver_running(),
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
    return HTMLResponse("<h1>SocEyes</h1><p>Frontend not built.</p>")


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
    import os

    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("SOC_PORT", "8000")),
        reload=False,
    )
