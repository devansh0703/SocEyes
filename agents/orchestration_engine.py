#!/usr/bin/env python3
"""
FDA Cyber Control — Orchestration Engine (Native, ZeroClaw-style)

Implements the 18-hand detection pipeline from scripts/run_orchestration_engine.py,
adapted to run as a background thread with the unified store (ES → SQLite fallback).

Hands:
  - alert_correlator: Correlates alerts across engines
  - bandwidth_governor: Throttles suspicious traffic
  - elastic_sensor: Polls for new events (ES/SQLite)
  - evidence_curator: Collects forensic artifacts
  - mitre_mapper: Maps alerts to MITRE ATT&CK
  - orchestrator_main: Main orchestrator
  - playbook_resolver: Resolves playbook references
  - policy_guardian: Enforces response policies
  - query_analyst: Analyzes user queries
  - response_planner: Plans response actions
  - rule_mapper: Maps logs to rules
  - run_supervisor: Manages run lifecycle
  - suricata_sensor: Processes Suricata events
  - telemetry_curator: Curates telemetry data
  - threat_summarizer: Generates threat summaries
  - validation_agent: Validates detection rules
  - wazuh_sensor: Processes Wazuh alerts
  - zeroclaw_runtime: ZeroClaw integration

Each hand uses the unified store (ES when available, SQLite fallback) to query
events, correlate, map to MITRE, etc. The engine runs as a background thread
and exposes its state via module-level globals for the /api/agents/* endpoints.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
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

ROOT = Path(__file__).resolve().parent.parent
sys_path_inserted = False
if str(ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT))
    sys_path_inserted = True

# Ensure log directory exists
os.makedirs(ROOT / "state" / "logs", exist_ok=True)

from app_shared.unified_store import es_count, es_search
from app_shared.mitre_playbooks import resolve_playbook_path
from app_shared.response_policy import choose_action, load_policy
from app_shared.state_paths import state_path
from app_shared.text_utils import now_utc as now_iso

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [orchestration] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "state" / "logs" / "orchestration.log", mode="a"),
    ],
)
logger = logging.getLogger("fda.orchestration")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

HANDS_DIR = ROOT / "zeroclaw" / "hands"
STATE_DIR = state_path("orchestration")
RUNS_FILE = STATE_DIR / "runs.jsonl"
LIVE_FILE = STATE_DIR / "live.json"
ZEROCLAW_BIN = Path(os.environ.get("ZEROCLAW_BIN", "/opt/zeroclaw/target/release/zeroclaw"))

# Thread control
_running = threading.Event()
_thread: threading.Thread | None = None

# Latest run results per hand (for API endpoints)
_latest_runs: dict[str, dict[str, Any]] = {}
_runs_lock = threading.Lock()

# Iteration counter for observability
_iteration = 0


# ---------------------------------------------------------------------------
# Load hands from TOML files
# ---------------------------------------------------------------------------

def load_hands() -> list[dict[str, Any]]:
    """Load hand definitions from zeroclaw/hands/*.toml."""
    hands: list[dict[str, Any]] = []
    if not HANDS_DIR.exists():
        return hands
    for path in sorted(HANDS_DIR.glob("*.toml")):
        with path.open("rb") as handle:
            document = tomllib.load(handle)
        document["path"] = str(path)
        hands.append(document)
    return hands


# ---------------------------------------------------------------------------
# HandContext — mutable state shared across hand handlers
# ---------------------------------------------------------------------------

@dataclass
class HandContext:
    metrics: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    knowledge: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    latest_runs: dict[str, dict[str, Any]] = field(default_factory=dict)

    def step(self, title: str, detail: str, status: str = "completed") -> None:
        self.steps.append({
            "title": title,
            "detail": detail,
            "status": status,
            "timestamp": now_iso(),
        })


# ---------------------------------------------------------------------------
# Hand handlers
# ---------------------------------------------------------------------------

def _hand_orchestrator_main(ctx: HandContext) -> None:
    bandwidth = _summarize_bandwidth()
    ctx.metrics.update({"active_hands": len(ctx.latest_runs), **bandwidth})
    ctx.step("Assess bandwidth",
             f"Operating mode is {bandwidth['mode']} with {bandwidth['logs']} logs in the last 15 minutes.")
    ctx.step("Review alerts",
             f"{es_count('.alerts-security.alerts-*,wazuh-alerts-*')} combined Elastic and Wazuh alerts are currently indexed.")
    ctx.step("Check live run", f"Current validation run is {'active' if _is_run_active() else 'idle'}.")
    ctx.findings.append(f"Pipeline pacing is {bandwidth['mode']}.")
    ctx.knowledge.append("The orchestration loop adapts to current ingest volume.")


def _hand_elastic_sensor(ctx: HandContext) -> None:
    rules = es_count("rule-catalog")
    alerts = es_count(".alerts-security.alerts-*")
    logs = es_count("log-catalog")
    ctx.metrics.update({"rules": rules, "alerts": alerts, "logs": logs})
    ctx.step("Count Elastic rules", f"{rules} Elastic rules are searchable.")
    ctx.step("Count Elastic alerts", f"{alerts} Elastic alerts are currently indexed.")
    ctx.findings.append(f"Elastic has {alerts} alerts against {rules} cataloged rules.")


def _hand_wazuh_sensor(ctx: HandContext) -> None:
    alerts = es_count("wazuh-alerts-*")
    archives = es_count("wazuh-archives-*")
    ctx.metrics.update({"alerts": alerts, "archives": archives})
    ctx.step("Count Wazuh alerts", f"{alerts} Wazuh alerts are available for triage.")
    ctx.step("Count Wazuh archives", f"{archives} Wazuh archive events are retained.")
    ctx.findings.append(f"Wazuh currently holds {alerts} alerts.")


def _hand_suricata_sensor(ctx: HandContext) -> None:
    total = es_count("fda-suricata.eve-*")
    flows = es_count("fda-suricata.eve-*", {"term": {"event_type": "flow"}})
    alerts = es_count("fda-suricata.eve-*", {"term": {"event_type": "alert"}})
    ctx.metrics.update({"events": total, "flows": flows, "alerts": alerts})
    ctx.step("Inspect Suricata volume",
             f"{total} Suricata EVE events are available, including {flows} flows and {alerts} alerts.")
    ctx.findings.append(f"Suricata has processed {flows} flow records.")


def _hand_rule_mapper(ctx: HandContext) -> None:
    recent = es_search("log-catalog", {
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["message", "rule_description", "source_index"],
        "query": {"match_all": {}},
    })
    mapped = len(recent)
    ctx.metrics.update({"mapped_samples": mapped})
    ctx.step("Sample latest logs", f"Mapped {mapped} recent log samples back to searchable catalog entries.")
    ctx.findings.append("Recent telemetry can be pivoted back into mapped rule content.")


def _hand_query_analyst(ctx: HandContext) -> None:
    rules = es_count("rule-catalog")
    top_titles = es_search("rule-catalog", {
        "size": 3,
        "_source": ["title", "engine"],
        "sort": [{"_score": {"order": "desc"}}],
        "query": {"multi_match": {"query": "ssh brute force network sweep suricata sudoers",
                                    "fields": ["search_text^3", "title^2"]}},
    })
    titles = [hit.get("_source", {}).get("title", "") for hit in top_titles]
    ctx.metrics.update({"rules": rules})
    ctx.step("Review search coverage", f"{rules} rules are available to the query layer.")
    if titles:
        ctx.step("Highlight high-signal rule families", ", ".join(titles))
    ctx.findings.append("Natural-language search is anchored to BM25 over the live rule catalog.")


def _hand_mitre_mapper(ctx: HandContext) -> None:
    alerts = _recent_alerts(limit=3)
    technique_count = 0
    for alert in alerts:
        threat = alert.get("threat") or {}
        technique = threat.get("technique") or {}
        ids = technique.get("id") or []
        if isinstance(ids, list):
            technique_count += len(ids)
        elif ids:
            technique_count += 1
    ctx.metrics.update({"recent_alerts": len(alerts), "recent_techniques": technique_count})
    ctx.step("Inspect recent ATT&CK coverage",
             f"The latest {len(alerts)} alerts expose {technique_count} ATT&CK technique references.")
    ctx.findings.append("MITRE coverage is available for recent alert activity.")


def _hand_playbook_resolver(ctx: HandContext) -> None:
    preview = _response_preview()
    ctx.metrics.update({"resolved": int(bool(preview["playbook_path"]))})
    ctx.step("Resolve playbook", preview["playbook_path"] or "No playbook currently resolved from the latest alert.")
    ctx.findings.append("SOAR playbook previews are prepared for operator review.")


def _hand_response_planner(ctx: HandContext) -> None:
    preview = _response_preview()
    policy = preview["policy"]
    action = preview["action"]
    ctx.metrics.update({"auto_execute": int(bool(policy.get("auto_execute")))})
    ctx.step("Choose response", f"Next recommended action is {action}.")
    ctx.step("Review policy gate",
             f"Auto execute is {'enabled' if policy.get('auto_execute') else 'disabled'} for the active policy.")
    ctx.findings.append(f"Prepared response action {action} for the latest alert.")

    # Auto-execute the response if policy allows
    if policy.get("auto_execute") and action != "observe_only":
        _execute_auto_response(preview)


def _hand_bandwidth_governor(ctx: HandContext) -> None:
    bandwidth = _summarize_bandwidth()
    ctx.metrics.update(bandwidth)
    ctx.step("Measure telemetry rate",
             f"{bandwidth['logs']} logs, {bandwidth['alerts']} alerts, and {bandwidth['responses']} responses were seen in the last 15 minutes.")
    ctx.step("Set orchestration mode", f"Recommended execution mode is {bandwidth['mode']}.")
    ctx.findings.append(f"Bandwidth governor recommends {bandwidth['mode']} mode.")


def _hand_validation_agent(ctx: HandContext) -> None:
    completed = [name for name, run in ctx.latest_runs.items()
                 if run.get("status", {}).get("status") == "completed"]
    missing = sorted(set(ctx.latest_runs) - set(completed))
    ctx.metrics.update({"completed_agents": len(completed), "missing_agents": len(missing)})
    ctx.step("Validate prior runs", f"{len(completed)} hands completed successfully in the latest cycle.")
    if missing:
        ctx.step("Flag missing agents", ", ".join(missing), status="warning")
        ctx.findings.append("Some hands did not complete successfully.")
    else:
        ctx.findings.append("All monitored hands completed successfully in the latest cycle.")


def _hand_alert_correlator(ctx: HandContext) -> None:
    alerts = _recent_alerts(limit=8)
    grouped = Counter()
    for alert in alerts:
        ds = (alert.get("event") or {}).get("dataset")
        rid = (alert.get("rule") or {}).get("id")
        msg = (alert.get("message") or "")[:40]
        grouped[ds or rid or msg] += 1
    ctx.metrics.update({"recent_alerts": len(alerts), "clusters": len(grouped)})
    ctx.step("Gather recent alerts", f"Loaded {len(alerts)} recent alerts for cross-engine review.")
    if grouped:
        lead = max(grouped.items(), key=lambda item: item[1])
        ctx.step("Highlight dominant cluster", f"Top cluster {lead[0]} appeared {lead[1]} times in the latest window.")
    ctx.findings.append("Recent alert flow is correlated into operator-friendly clusters.")


def _hand_evidence_curator(ctx: HandContext) -> None:
    logs = es_search("log-catalog", {
        "size": 5,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["message", "source_index", "process_command_line", "source_ip", "destination_ip"],
        "query": {"match_all": {}},
    })
    ctx.metrics.update({"latest_logs": len(logs)})
    ctx.step("Collect evidence samples", f"Curated {len(logs)} fresh logs for drill-down views.")
    if logs:
        sample = logs[0].get("_source", {})
        ctx.step("Promote latest evidence",
                 sample.get("message") or sample.get("process_command_line") or "Recent log sample available.")
    ctx.findings.append("Readable evidence cards are ready for live investigation.")


def _hand_telemetry_curator(ctx: HandContext) -> None:
    network = es_count("fda-suricata.eve-*", {"range": {"@timestamp": {"gte": "now-30m"}}})
    process_events = es_count("log-catalog", {
        "bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-30m"}}},
            {"exists": {"field": "process_command_line"}},
        ]}
    })
    ctx.metrics.update({"network_events": network, "process_events": process_events})
    ctx.step("Measure telemetry mix",
             f"Captured {network} network events and {process_events} process-oriented events in the last 30 minutes.")
    ctx.findings.append("Telemetry mix remains broad enough for cross-source rule validation.")


def _hand_run_supervisor(ctx: HandContext) -> None:
    run_state = _load_current_run()
    ctx.metrics.update({"active": int(bool(run_state.get("active")))})
    if run_state.get("active"):
        ctx.step("Track active run",
                 f"Run {run_state.get('run_id')} started at {run_state.get('started_at')}.")
        ctx.findings.append(f"Manual run {run_state.get('name') or run_state.get('run_id')} is active.")
    else:
        ctx.step("Track active run", "No live validation run is active right now.")
        ctx.findings.append("Run supervisor is waiting for the next manual validation session.")


def _hand_policy_guardian(ctx: HandContext) -> None:
    policy = load_policy()
    ctx.metrics.update({
        "auto_execute": int(bool(policy.get("auto_execute"))),
        "elastic_enabled": int(bool((policy.get("engines") or {}).get("elastic"))),
        "wazuh_enabled": int(bool((policy.get("engines") or {}).get("wazuh"))),
    })
    ctx.step("Inspect response policy",
             f"Auto execute is {'enabled' if policy.get('auto_execute') else 'disabled'} for the current policy.")
    ctx.step("Inspect engine gates",
             f"Elastic={'on' if (policy.get('engines') or {}).get('elastic') else 'off'}, "
             f"Wazuh={'on' if (policy.get('engines') or {}).get('wazuh') else 'off'}.")
    ctx.findings.append("Policy guardian confirmed the live response gates.")


def _hand_threat_summarizer(ctx: HandContext) -> None:
    preview = _response_preview()
    ctx.metrics.update({"playbook_resolved": int(bool(preview.get("playbook_path")))})
    ctx.step("Summarize latest threat",
             f"Latest action recommendation is {preview['action']} for technique {preview['technique_id'] or 'unknown'}.")
    if preview.get("playbook_path"):
        ctx.step("Resolve response narrative", preview["playbook_path"])
    ctx.findings.append("Threat summary is ready for the operator dashboard.")


def _hand_zeroclaw_runtime(ctx: HandContext) -> None:
    lines = _zeroclaw_status_lines()
    ctx.metrics.update({"status_lines": len(lines), "binary_present": int(ZEROCLAW_BIN.exists())})
    ctx.step("Inspect ZeroClaw runtime", lines[0] if lines else "ZeroClaw status unavailable.")
    for line in lines[1:4]:
        ctx.step("ZeroClaw detail", line)
    ctx.findings.append("Real ZeroClaw CLI status has been collected for runtime visibility.")


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_HAND_DISPATCH: dict[str, Callable[[HandContext], None]] = {
    "orchestrator_main": _hand_orchestrator_main,
    "elastic_sensor": _hand_elastic_sensor,
    "wazuh_sensor": _hand_wazuh_sensor,
    "suricata_sensor": _hand_suricata_sensor,
    "rule_mapper": _hand_rule_mapper,
    "query_analyst": _hand_query_analyst,
    "mitre_mapper": _hand_mitre_mapper,
    "playbook_resolver": _hand_playbook_resolver,
    "response_planner": _hand_response_planner,
    "bandwidth_governor": _hand_bandwidth_governor,
    "validation_agent": _hand_validation_agent,
    "alert_correlator": _hand_alert_correlator,
    "evidence_curator": _hand_evidence_curator,
    "telemetry_curator": _hand_telemetry_curator,
    "run_supervisor": _hand_run_supervisor,
    "policy_guardian": _hand_policy_guardian,
    "threat_summarizer": _hand_threat_summarizer,
    "zeroclaw_runtime": _hand_zeroclaw_runtime,
}


# ---------------------------------------------------------------------------
# Helpers used by multiple hands
# ---------------------------------------------------------------------------

def _summarize_bandwidth() -> dict[str, Any]:
    """Measure ingest volume over the last 15 minutes."""
    half_hour = {"range": {"@timestamp": {"gte": "now-15m"}}}
    logs = es_count("log-catalog", half_hour)
    alerts = es_count(".alerts-security.alerts-*,wazuh-alerts-*", half_hour)
    responses = es_count("security-response-*", half_hour)
    total = logs + alerts + responses
    if total > 5000:
        mode = "throttled"
    elif total > 1000:
        mode = "normal"
    else:
        mode = "fast"
    return {"logs": logs, "alerts": alerts, "responses": responses, "mode": mode}


def _response_preview() -> dict[str, Any]:
    """Build response preview from the latest alert."""
    latest = _recent_alerts(limit=1)
    alert = latest[0] if latest else {}
    technique_ids: list[str] = []
    # Check nested threat.technique.id (ES format)
    threat = alert.get("threat") or {}
    technique = threat.get("technique") or {}
    ids = technique.get("id") or []
    if isinstance(ids, list):
        technique_ids = [str(i) for i in ids]
    elif ids:
        technique_ids = [str(ids)]
    # Fallback: check top-level technique_ids (simulation/SQLite format)
    if not technique_ids:
        top_ids = alert.get("technique_ids", [])
        if isinstance(top_ids, list):
            technique_ids = [str(t) for t in top_ids]
        elif top_ids:
            technique_ids = [str(top_ids)]
    action = choose_action(technique_ids)
    technique_id = technique_ids[0] if technique_ids else ""
    playbook_path = resolve_playbook_path(technique_id)
    return {
        "technique_id": technique_id,
        "action": action,
        "playbook_path": playbook_path,
        "policy": load_policy(),
    }


def _recent_alerts(limit: int = 5) -> list[dict[str, Any]]:
    """Fetch recent alerts from ES or SQLite."""
    try:
        hits = es_search(
            ".alerts-security.alerts-*,wazuh-alerts-*,security-response-*",
            {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": True,
                "query": {"match_all": {}},
            },
        )
        results = [hit.get("_source") or {} for hit in hits]
        if results:
            return results
    except Exception:
        pass

    # Fallback: read from SQLite via unified store
    try:
        from app_shared.unified_store import get_latest_alerts
        return get_latest_alerts(limit=limit)
    except Exception:
        return []


def _execute_auto_response(preview: dict[str, Any]) -> None:
    """Execute the recommended response action via the backend API."""
    import requests

    alert = _recent_alerts(limit=1)[0] if _recent_alerts(limit=1) else {}
    source_ip = alert.get("source_ip", "")
    destination_ip = alert.get("destination_ip", "")
    rule_id = alert.get("rule_id", "")
    technique_ids = []
    tech = alert.get("technique") or {}
    ids = tech.get("id") or []
    if isinstance(ids, list):
        technique_ids = [str(i) for i in ids]
    elif ids:
        technique_ids = [str(ids)]
    technique_id = technique_ids[0] if technique_ids else ""

    if not source_ip:
        return

    api_url = os.environ.get("API_URL", "http://127.0.0.1:8123")
    try:
        resp = requests.post(
            f"{api_url}/api/response/execute",
            json={
                "action": preview["action"],
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "rule_id": rule_id,
                "technique_id": technique_id,
            },
            timeout=30,
        )
        if resp.ok:
            result = resp.json()
            if result.get("success"):
                logger.info("Auto-response executed: %s for %s (success=%s)",
                            preview["action"], source_ip, result.get("success"))
            else:
                logger.warning("Auto-response failed: %s for %s (success=%s)",
                               preview["action"], source_ip, result.get("success"))
        else:
            logger.warning("Auto-response API error: %s for %s (status=%s)",
                           preview["action"], source_ip, resp.status_code)
    except Exception as exc:
        logger.error("Auto-response exception: %s", exc)


def _load_current_run() -> dict[str, Any]:
    """Load the current demo run state."""
    current_run_file = state_path("demo_runs", "current.json")
    if not current_run_file.exists():
        return {"active": False}
    try:
        payload = json.loads(current_run_file.read_text(encoding="utf-8"))
        return {"active": True, **payload}
    except json.JSONDecodeError:
        return {"active": False}


def _is_run_active() -> bool:
    return _load_current_run().get("active", False)


def _zeroclaw_status_lines() -> list[str]:
    from app_shared.text_utils import ANSI_ESCAPE_RE
    if not ZEROCLAW_BIN.exists():
        return ["ZeroClaw binary is not mounted into the orchestration runtime."]
    try:
        result = subprocess.run(
            [str(ZEROCLAW_BIN), "status"],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except Exception as exc:
        return [f"ZeroClaw status failed: {exc}"]
    lines = [ANSI_ESCAPE_RE.sub("", line).strip() for line in result.stdout.splitlines() if line.strip()]
    lines = [line for line in lines if "Config loaded" not in line]
    if not lines:
        lines = [result.stderr.strip() or "ZeroClaw status returned no output."]
    return lines[:12]


# ---------------------------------------------------------------------------
# Execute a single hand
# ---------------------------------------------------------------------------

def execute_hand(hand: dict[str, Any], latest_runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Execute a single orchestration hand and return the structured run record."""
    started = datetime.now(timezone.utc)
    run_id = f"{hand['name']}-{uuid.uuid4()}"
    ctx = HandContext(latest_runs=latest_runs)

    try:
        handler = _HAND_DISPATCH.get(hand["name"])
        if handler is not None:
            handler(ctx)
        else:
            ctx.step("Idle", "No specialized routine is defined for this hand yet.")
            ctx.findings.append("Hand is active and ready.")
    except Exception as exc:
        finished = datetime.now(timezone.utc)
        return _finalize_run(hand, run_id, started, finished, "failed",
                             steps=ctx.steps, metrics=ctx.metrics,
                             findings=ctx.findings, knowledge=ctx.knowledge,
                             error=str(exc))

    finished = datetime.now(timezone.utc)
    return _finalize_run(hand, run_id, started, finished, "completed",
                         steps=ctx.steps, metrics=ctx.metrics,
                         findings=ctx.findings, knowledge=ctx.knowledge)


def _finalize_run(
    hand: dict[str, Any],
    run_id: str,
    started: datetime,
    finished: datetime,
    status: str,
    steps: list[dict[str, Any]],
    metrics: dict[str, Any],
    findings: list[str],
    knowledge: list[str],
    error: str | None = None,
) -> dict[str, Any]:
    """Build the standard run-result dict."""
    result: dict[str, Any] = {
        "hand_name": hand["name"],
        "run_id": run_id,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "status": {"status": status},
        "steps": steps,
        "metrics": metrics,
        "findings": findings,
        "knowledge_added": knowledge,
        "duration_ms": int((finished - started).total_seconds() * 1000),
    }
    if error is not None:
        result["status"]["error"] = error
    return result


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _orchestration_loop() -> None:
    """Background thread that runs each hand on its configured schedule."""
    global _iteration
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    last_run_at: dict[str, datetime] = {}

    while _running.is_set():
        live_payload = {"updated_at": now_iso(), "hands": []}
        hands = [hand for hand in load_hands() if hand.get("active", True)]

        with _runs_lock:
            latest_runs = dict(_latest_runs)

        for hand in hands:
            if not _running.is_set():
                break
            every_ms = int(((hand.get("schedule") or {}).get("every_ms")) or 10000)
            now = datetime.now(timezone.utc)
            if hand["name"] in last_run_at and now - last_run_at[hand["name"]] < timedelta(milliseconds=every_ms):
                if hand["name"] in latest_runs:
                    live_payload["hands"].append(latest_runs[hand["name"]])
                continue
            try:
                run = execute_hand(hand, latest_runs)
                last_run_at[hand["name"]] = now
                with _runs_lock:
                    _latest_runs[hand["name"]] = run
                live_payload["hands"].append(run)
                _append_run(run)
                _save_context(hand, run)
            except Exception as exc:
                logger.error("Hand %s error: %s", hand.get("name"), exc)

        try:
            LIVE_FILE.write_text(json.dumps(live_payload, indent=2, default=str), encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not write live file: %s", exc)

        _iteration += 1
        time.sleep(2)

    logger.info("Orchestration engine stopped")


def _append_run(run: dict[str, Any]) -> None:
    """Append a run to the JSONL runs file."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with RUNS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(run, default=str))
        handle.write("\n")


def _save_context(hand: dict[str, Any], run: dict[str, Any]) -> None:
    """Persist hand context (history + learned facts)."""
    context = _load_context(hand["name"])
    if run["status"]["status"] == "completed":
        context["total_runs"] = int(context.get("total_runs") or 0) + 1
        context["last_run"] = run["finished_at"]
    for fact in run.get("knowledge_added", []):
        if fact not in context["learned_facts"]:
            context["learned_facts"].append(fact)
    max_hist = int(hand.get("max_history") or 100)
    context["history"] = [run, *context.get("history", [])][:max_hist]
    hand_dir = HANDS_DIR / hand["name"]
    hand_dir.mkdir(parents=True, exist_ok=True)
    (hand_dir / "context.json").write_text(json.dumps(context, indent=2, default=str), encoding="utf-8")


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


# ---------------------------------------------------------------------------
# Public API for the main FastAPI process
# ---------------------------------------------------------------------------

def start() -> None:
    """Start the orchestration engine background thread."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _running.set()
    _thread = threading.Thread(target=_orchestration_loop, daemon=True, name="orchestration-engine")
    _thread.start()
    logger.info("Orchestration engine started (background thread)")


def stop() -> None:
    """Stop the orchestration engine."""
    _running.clear()
    if _thread:
        _thread.join(timeout=10)
    logger.info("Orchestration engine stopped")


def is_running() -> bool:
    """Return True if the orchestration engine thread is alive."""
    return bool(_thread and _thread.is_alive() and _running.is_set())


def get_latest_runs() -> dict[str, dict[str, Any]]:
    """Return the latest run result for each hand (thread-safe copy)."""
    with _runs_lock:
        return dict(_latest_runs)


def get_hand_run(hand_name: str) -> dict[str, Any] | None:
    """Return the latest run for a specific hand."""
    with _runs_lock:
        return _latest_runs.get(hand_name)


def get_iterations() -> int:
    """Return the current iteration count."""
    return _iteration


def get_hand_context(hand_name: str) -> dict[str, Any]:
    """Return persisted context for a hand."""
    return _load_context(hand_name)


def get_live_payload() -> dict[str, Any]:
    """Read the live.json file (or build from memory)."""
    if LIVE_FILE.exists():
        try:
            return json.loads(LIVE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"updated_at": now_iso(), "hands": list(_latest_runs.values())}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """Run the orchestration engine in standalone mode (blocking)."""
    from app_shared.sqlite_store import init_db
    init_db()
    logger.info("Orchestration engine started (standalone)")
    try:
        _orchestration_loop()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
