from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests

from app_shared.mitre_playbooks import resolve_playbook_path
from app_shared.es_client import get_es_client
from app_shared.response_policy import action_detail, choose_action, load_policy, render_command_preview
from app_shared.state_paths import (
    append_jsonl,
    readable_candidates,
    read_json,
    read_jsonl,
    state_path,
    writable_path,
    write_json,
)
from app_shared.text_utils import (  # noqa: F401 — re-used text helpers
    ANSI_ESCAPE_RE,
    _write_json,
    clean_text,
    deep_get,
    extract_mitre_from_tags,
    extract_rule_mitre,
    humanize_possible_structured_text,
    normalize_severity,
    now_utc,
    parse_markdown_sections,
    slugify,
)
from backend.app.config import settings


RULE_INDEX = "rule-catalog"
LOG_INDEX = "log-catalog"
LIVE_LOG_INDEX = "logs-linux.auditd-*,fda-syslog-*,fda-suricata.eve-*,wazuh-archives-*,wazuh-alerts-*,security-response-*"
ELASTIC_ALERT_INDEX = ".alerts-security.alerts-*"
WAZUH_ALERT_INDEX = "wazuh-alerts-*"
RESPONSE_INDEX = "security-response-*"
SURICATA_INDEX = "fda-suricata.eve-*"
ORCHESTRATION_LIVE_FILE = state_path("orchestration", "live.json")
ORCHESTRATION_RUNS_FILE = state_path("orchestration", "runs.jsonl")
ZEROCLAW_GATEWAY_LOG = state_path("orchestration", "zeroclaw_gateway.log")
DEMO_RUNS_DIR = state_path("demo_runs")
CURRENT_RUN_FILE = DEMO_RUNS_DIR / "current.json"
RUN_HISTORY_FILE = DEMO_RUNS_DIR / "history.jsonl"
HONEYPOT_STATE_DIR = state_path("honeypot")
HONEYPOT_SESSIONS_FILE = HONEYPOT_STATE_DIR / "sessions.jsonl"
ZEROCLAW_BIN = Path(os.environ.get("ZEROCLAW_BIN", "/opt/zeroclaw/target/release/zeroclaw"))
ZEROCLAW_GATEWAY_URL = os.environ.get("ZEROCLAW_GATEWAY_URL", "").rstrip("/")
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
# Response/honeypot helpers are child processes of the API; they must never be
# able to hang a request forever.
HELPER_COMMAND_TIMEOUT = int(os.environ.get("FDA_HELPER_TIMEOUT_SECONDS", "240"))
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def session() -> requests.Session:
    """Shared Elasticsearch session — delegates to ``app_shared.es_client``."""
    return get_es_client()


def es_request(method: str, path: str, payload: dict[str, Any] | None = None, timeout: int | None = None) -> dict[str, Any]:
    response = session().request(
        method,
        f"{settings.elasticsearch_url}{path}",
        json=payload,
        timeout=timeout or settings.es_timeout_seconds,
    )
    response.raise_for_status()
    return response.json()


def build_range(start: str | None = None, end: str | None = None, default: str = "now-24h") -> dict[str, Any]:
    params: dict[str, Any] = {}
    if start:
        params["gte"] = start
    elif not end:
        params["gte"] = default
    if end:
        params["lte"] = end
    return {"range": {"@timestamp": params}}
def playbook_detail(technique_id: str) -> dict[str, Any]:
    path = resolve_playbook_path(technique_id, settings.playbook_root)
    content = ""
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            content = ""
    return {
        "technique_id": technique_id,
        "path": path,
        "available": bool(path),
        "sections": parse_markdown_sections(content) if content else [],
    }
@lru_cache(maxsize=256)
def _nvidia_response_explanations(cache_key: str) -> dict[str, str]:
    if not NVIDIA_API_KEY:
        return {"technical": "", "nontechnical": ""}
    try:
        context = json.loads(cache_key)
    except json.JSONDecodeError:
        return {"technical": "", "nontechnical": ""}
    body = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a SOC response assistant. Return strict JSON with keys technical and nontechnical. "
                    "technical must describe detection evidence, attack mapping, and concrete response command considerations. "
                    "nontechnical must explain risk and business impact in plain language. Keep both concise."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(context, sort_keys=True),
            },
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    try:
        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=25,
        )
        response.raise_for_status()
        raw = str(response.json()["choices"][0]["message"]["content"]).strip()
        parsed = json.loads(raw)
    except Exception:
        return {"technical": "", "nontechnical": ""}
    return {
        "technical": clean_text(parsed.get("technical")),
        "nontechnical": clean_text(parsed.get("nontechnical")),
    }


@lru_cache(maxsize=256)
def _nvidia_recommended_action(cache_key: str) -> str:
    if not NVIDIA_API_KEY:
        return ""
    try:
        context = json.loads(cache_key)
    except json.JSONDecodeError:
        return ""
    body = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Pick exactly one action from: block_source_ip, throttle_service, disable_account, isolate_host, quarantine_endpoint, block_egress, observe_only. "
                    "Return JSON with key action only."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(context, sort_keys=True),
            },
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    try:
        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=20,
        )
        response.raise_for_status()
        raw = str(response.json()["choices"][0]["message"]["content"]).strip()
        parsed = json.loads(raw)
    except Exception:
        return ""
    action = clean_text(parsed.get("action"))
    allowed = {
        "block_source_ip",
        "throttle_service",
        "disable_account",
        "isolate_host",
        "quarantine_endpoint",
        "block_egress",
        "observe_only",
    }
    return action if action in allowed else ""


def response_preview(payload: dict[str, Any], include_llm: bool | None = None) -> dict[str, Any]:
    if include_llm is None:
        include_llm = bool(NVIDIA_API_KEY)
    technique_ids = [item for item in payload.get("mitre_ids", []) if item]
    technique_id = payload.get("technique_id") or (technique_ids[0] if technique_ids else "")
    severity = normalize_severity(payload.get("severity"))
    action = choose_action([technique_id] if technique_id else [])
    if severity["level"] == "low":
        action = "observe_only"
    elif severity["level"] == "critical" and action == "observe_only":
        action = "quarantine_endpoint"
    if include_llm:
        llm_action = _nvidia_recommended_action(
            json.dumps(
                {
                    "technique_id": technique_id,
                    "mitre_ids": technique_ids,
                    "rule_id": payload.get("rule_id", ""),
                    "engine": payload.get("engine", ""),
                    "source_ip": payload.get("source_ip", ""),
                    "destination_ip": payload.get("destination_ip", ""),
                    "username": payload.get("username", ""),
                    "message": payload.get("message", ""),
                },
                sort_keys=True,
            )
        )
        if llm_action:
            action = llm_action
    detail = action_detail(action)
    rendered_command = render_command_preview(
        action,
        {
            "source_ip": payload.get("source_ip", ""),
            "destination_ip": payload.get("destination_ip", ""),
            "username": payload.get("username", ""),
            "rule_id": payload.get("rule_id", ""),
            "technique_id": technique_id,
        },
    )
    playbook = playbook_detail(technique_id) if technique_id else {"technique_id": "", "path": "", "available": False, "sections": []}
    technical = ""
    nontechnical = ""
    if include_llm:
        llm_context = {
            "technique_id": technique_id,
            "mitre_ids": technique_ids,
            "action": action,
            "action_title": detail["title"],
            "rule_id": payload.get("rule_id", ""),
            "engine": payload.get("engine", ""),
            "source_ip": payload.get("source_ip", ""),
            "destination_ip": payload.get("destination_ip", ""),
            "username": payload.get("username", ""),
            "message": payload.get("message", ""),
            "playbook_excerpt": " ".join((playbook.get("sections") or [{}])[0].get("paragraphs", [])[:2]),
            "command": rendered_command,
        }
        explanations = _nvidia_response_explanations(json.dumps(llm_context, sort_keys=True))
        technical = explanations.get("technical", "")
        nontechnical = explanations.get("nontechnical", "")
    if not technical:
        technical = (
            f"Severity level {severity['level']} ({severity['score']}/100). "
            f"{detail['summary']} Command preview: {rendered_command}"
        )
    if not nontechnical:
        nontechnical = (
            f"Risk level is {severity['level']}. This response is chosen to reduce impact while preserving evidence."
        )
    technical = humanize_possible_structured_text(technical)
    nontechnical = humanize_possible_structured_text(nontechnical)
    summary = humanize_possible_structured_text(detail["summary"])
    should_honeypot = bool(severity["level"] == "critical" and (payload.get("source_ip") or payload.get("destination_ip")))
    return {
        "technique_id": technique_id,
        "action": action,
        "severity": severity,
        "warning_level": severity["level"],
        "should_honeypot": should_honeypot,
        "title": detail["title"],
        "summary": summary,
        "preview_command": rendered_command,
        "success_criteria": detail["success_criteria"],
        "technical_explanation": technical,
        "nontechnical_explanation": nontechnical,
        "llm_generated": bool(include_llm and NVIDIA_API_KEY),
        "policy": load_policy(),
        "playbook": playbook,
    }


def humanize_sigma_rule(raw: dict[str, Any]) -> list[dict[str, Any]]:
    detection = raw.get("detection") or {}
    logic = []
    for name, value in detection.items():
        if name == "condition":
            continue
        logic.append(f"{name}: {clean_text(json.dumps(value, sort_keys=True))}")
    sections = []
    if logic:
        sections.append({"title": "Detection Logic", "slug": "detection-logic", "paragraphs": [], "bullets": logic[:8]})
    if detection.get("condition"):
        sections.append({"title": "Match Condition", "slug": "match-condition", "paragraphs": [clean_text(detection.get("condition"))], "bullets": []})
    return sections


def humanize_elastic_rule(raw: dict[str, Any]) -> list[dict[str, Any]]:
    sections = []
    if raw.get("query"):
        sections.append(
            {
                "title": "Detection Query",
                "slug": "detection-query",
                "paragraphs": [clean_text(raw.get("query"))],
                "bullets": [],
            }
        )
    note = clean_text(raw.get("note"))
    if note:
        sections.extend(parse_markdown_sections(raw.get("note") or ""))
    return sections[:8]


def humanize_panther_rule(raw: dict[str, Any]) -> list[dict[str, Any]]:
    sections = []
    summary = clean_text(raw.get("Description") or raw.get("Summary"))
    if summary:
        sections.append({"title": "Summary", "slug": "summary", "paragraphs": [summary], "bullets": []})
    log_types = [str(item) for item in raw.get("LogTypes", [])]
    if log_types:
        sections.append({"title": "Covered Log Types", "slug": "covered-log-types", "paragraphs": [], "bullets": log_types[:10]})
    return sections


def humanize_wazuh_rule(raw: dict[str, Any]) -> list[dict[str, Any]]:
    fields = raw.get("fields") or []
    return [{"title": "Field Matching", "slug": "field-matching", "paragraphs": [], "bullets": [clean_text(item) for item in fields[:10]]}] if fields else []


def rule_sections(source: dict[str, Any]) -> list[dict[str, Any]]:
    raw = source.get("raw") or {}
    common = [
        f"Engine: {source.get('engine', '').upper()}",
        f"Severity: {clean_text(source.get('level') or 'unknown')}",
        f"Path: {source.get('path', '')}",
    ]
    if source.get("indices"):
        common.append("Indices: " + ", ".join(source["indices"][:5]))
    sections = [{"title": "Coverage", "slug": "coverage", "paragraphs": [], "bullets": common}]
    engine = source.get("engine")
    if engine == "sigma":
        sections.extend(humanize_sigma_rule(raw))
    elif engine == "elastic":
        sections.extend(humanize_elastic_rule(raw))
    elif engine == "panther":
        sections.extend(humanize_panther_rule(raw))
    elif engine == "wazuh":
        sections.extend(humanize_wazuh_rule(raw))
    if source.get("references"):
        sections.append(
            {
                "title": "References",
                "slug": "references",
                "paragraphs": [],
                "bullets": [clean_text(item) for item in source["references"][:8]],
            }
        )
    return sections[:10]


def enrich_rule_hit(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    mitre_ids = extract_rule_mitre(source)
    preview = response_preview({"mitre_ids": mitre_ids, "rule_id": source.get("rule_id", "")})
    return {
        "score": float(hit.get("_score") or 0),
        **source,
        "mitre_ids": mitre_ids,
        "playbooks": [playbook_detail(technique_id) for technique_id in mitre_ids],
        "sections": rule_sections({**source, "mitre_ids": mitre_ids}),
        "response_preview": preview,
    }


def search_rules(query: str, limit: int = 10, engines: list[str] | None = None) -> list[dict[str, Any]]:
    filters = []
    if engines:
        filters.append({"terms": {"engine": engines}})
    payload = {
        "size": limit,
        "query": {
            "bool": {
                "must": {
                    "multi_match": {
                        "query": query,
                        "type": "best_fields",
                        "fields": [
                            "title^5",
                            "description^4",
                            "query^3",
                            "search_text^6",
                            "tags^2",
                            "product^2",
                            "service^2",
                            "category^2",
                            "path^2",
                        ],
                    }
                },
                "filter": filters,
            }
        },
    }
    data = es_request("GET", f"/{RULE_INDEX}/_search", payload)
    return [enrich_rule_hit(hit) for hit in data.get("hits", {}).get("hits", [])]


def find_rule(rule_id: str) -> dict[str, Any] | None:
    candidate_ids = [rule_id]
    if rule_id.startswith("sigma-"):
        candidate_ids.append(rule_id.removeprefix("sigma-"))
    for candidate in candidate_ids:
        payload = {"size": 1, "query": {"term": {"rule_id": candidate}}}
        data = es_request("GET", f"/{RULE_INDEX}/_search", payload)
        hits = data.get("hits", {}).get("hits", [])
        if hits:
            return enrich_rule_hit(hits[0])
    return None


def format_log_hit(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    return {
        "id": hit.get("_id", source.get("source_id", "")),
        "timestamp": source.get("@timestamp") or source.get("timestamp"),
        "message": clean_text(source.get("message") or source.get("event_original") or source.get("full_log") or deep_get(source, ["event", "original"]) or "Event"),
        "source_index": source.get("source_index", hit.get("_index", "")),
        "decoder": source.get("decoder_name", ""),
        "rule_description": clean_text(source.get("rule_description") or deep_get(source, ["rule", "description"])),
        "process_name": source.get("process_name", deep_get(source, ["process", "name"])),
        "process_command_line": source.get("process_command_line", deep_get(source, ["process", "command_line"])),
        "host_name": source.get("host_name", deep_get(source, ["host", "name"])),
        "user_name": source.get("user_name", deep_get(source, ["user", "name"])),
        "source_ip": source.get("source_ip", deep_get(source, ["source", "ip"])),
        "destination_ip": source.get("destination_ip", deep_get(source, ["destination", "ip"])),
        "destination_port": source.get("destination_port", deep_get(source, ["destination", "port"], 0)),
        "network_transport": source.get("network_transport", deep_get(source, ["network", "transport"])),
        "suricata_event_type": source.get("suricata_event_type", source.get("event_type", "")),
        "tags": source.get("tags", []),
        "run_id": clean_text((source.get("labels") or {}).get("run_id") or source.get("run_id") or ""),
    }


def search_logs(query: str, limit: int = 50, start: str | None = None, end: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    must: list[dict[str, Any]] = [build_range(start, end)]
    if run_id:
        must.append(
            {
                "bool": {
                    "should": [
                        {"term": {"labels.run_id.keyword": run_id}},
                        {"term": {"labels.run_id": run_id}},
                        {"term": {"run_id.keyword": run_id}},
                        {"term": {"run_id": run_id}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    if query.strip():
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "type": "best_fields",
                    "fields": [
                        "message^5",
                        "full_log^5",
                        "event_original^3",
                        "event.original^3",
                        "process.command_line^4",
                        "process.name^4",
                        "process_name^4",
                        "process_command_line^4",
                        "rule_description^2",
                        "search_text^6",
                    ],
                }
            }
        )
    payload = {
        "size": limit,
        "_source": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
    }
    data = es_request("GET", f"/{LIVE_LOG_INDEX}/_search", payload)
    return [format_log_hit(hit) for hit in data.get("hits", {}).get("hits", [])]


def grouped_live_logs(limit: int = 120, start: str | None = None, end: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    items = search_logs("", limit=limit, start=start, end=end, run_id=run_id)
    grouped: dict[str, dict[str, Any]] = {}
    for log in items:
        signature = "|".join(
            [
                clean_text(log.get("message", "")).lower(),
                clean_text(log.get("source_index", "")).lower(),
                clean_text(log.get("source_ip", "")),
                clean_text(log.get("destination_ip", "")),
            ]
        )
        existing = grouped.get(signature)
        if existing:
            existing["count"] += 1
            existing["ids"].append(log.get("id"))
            if (log.get("timestamp") or "") < (existing.get("start_time") or ""):
                existing["start_time"] = log.get("timestamp")
            if (log.get("timestamp") or "") > (existing.get("end_time") or ""):
                existing["end_time"] = log.get("timestamp")
                existing["latest"] = log
            continue
        grouped[signature] = {
            "signature": signature,
            "group_id": f"group-{len(grouped) + 1}",
            "count": 1,
            "start_time": log.get("timestamp"),
            "end_time": log.get("timestamp"),
            "latest": log,
            "ids": [log.get("id")],
        }
    groups = list(grouped.values())
    groups.sort(key=lambda item: item.get("end_time") or "", reverse=True)
    for group in groups:
        group.pop("signature", None)
    return groups


def find_log(log_id: str) -> dict[str, Any] | None:
    payload = {"size": 1, "query": {"bool": {"should": [{"term": {"source_id": log_id}}, {"ids": {"values": [log_id]}}], "minimum_should_match": 1}}}
    try:
        data = es_request("GET", f"/{LIVE_LOG_INDEX}/_search", payload)
    except requests.HTTPError:
        return None
    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return None
    return format_log_hit(hits[0])


def map_log_to_rules(log_id: str, limit: int = 5) -> dict[str, Any]:
    log = find_log(log_id)
    if not log:
        return {"log": None, "matches": []}
    query = "\n".join(
        item
        for item in [
            log.get("message", ""),
            log.get("process_name", ""),
            log.get("process_command_line", ""),
            log.get("source_index", ""),
            log.get("suricata_event_type", ""),
        ]
        if item
    )
    matches = search_rules(query or log.get("message", ""), limit=limit)
    return {"log": log, "matches": matches}


def query_rule_evidence(rule: dict[str, Any], limit: int = 20, start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    should = [
        {"term": {"kibana.alert.rule.rule_id": rule["rule_id"]}},
        {"term": {"signal.rule.rule_id": rule["rule_id"]}},
        {"term": {"rule.id": rule["rule_id"]}},
    ]
    alerts = []
    query = {"bool": {"must": [build_range(start, end)], "should": should, "minimum_should_match": 1}}
    for index in [ELASTIC_ALERT_INDEX, WAZUH_ALERT_INDEX]:
        try:
            data = es_request(
                "GET",
                f"/{index}/_search",
                {
                    "size": limit,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": query,
                },
            )
            alerts.extend([hit.get("_source") or {} for hit in data.get("hits", {}).get("hits", [])])
        except requests.HTTPError:
            continue
    log_query = "\n".join(value for value in [rule.get("title", ""), rule.get("description", ""), rule.get("query", "")] if value)
    logs = search_logs(log_query, limit=limit, start=start, end=end, run_id=run_id)
    return {"alerts": alerts[:limit], "logs": logs[:limit]}
def current_demo_run() -> dict[str, Any]:
    for candidate in readable_candidates(CURRENT_RUN_FILE):
        payload = read_json(candidate, default=None)
        if isinstance(payload, dict) and payload:
            return {"active": True, **payload}
    return {"active": False}


def start_demo_run(name: str = "", note: str = "") -> dict[str, Any]:
    run_id = f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    payload = {
        "run_id": run_id,
        "name": clean_text(name) or "Manual live validation",
        "note": clean_text(note),
        "started_at": now_utc(),
    }
    _write_json(CURRENT_RUN_FILE, payload)
    return {"active": True, **payload, "attack_seed": seed_demo_attacks(run_id=run_id)}


def _run_helper(
    command: list[str],
    label: str,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a child helper script with a hard timeout.

    Response actions and honeypot deploys are child processes triggered by an
    HTTP request, so without a timeout a stuck child would pin an API worker
    indefinitely.
    """
    limit = timeout or HELPER_COMMAND_TIMEOUT
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=limit,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} timed out after {limit}s") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"{label} failed")
    return result


def _run_seed_command(command: list[str], label: str, timeout: int = 60) -> dict[str, Any]:
    try:
        run = _run_helper(command, label, timeout=timeout)
    except RuntimeError as exc:
        return {"scenario": label, "ok": False, "output": clean_text(str(exc))}
    return {
        "scenario": label,
        "ok": True,
        "output": clean_text(run.stdout) or clean_text(run.stderr),
    }


def seed_demo_attacks(run_id: str) -> list[dict[str, Any]]:
    scenarios = [
        "sigma_system_info",
        "sigma_password_policy",
        "sigma_file_event_sudoers",
        "elastic_network_sweep",
        "elastic_external_ssh_bruteforce",
        "wazuh_failed_ssh",
        "suricata_network_sweep",
    ]
    results: list[dict[str, Any]] = []
    for scenario in scenarios:
        results.append(
            _run_seed_command(
                [sys.executable, "scripts/manual_rules/emit_existing_rule_signals.py", scenario],
                label=scenario,
                timeout=60,
            )
        )

    response_seeds = [
        {
            "label": "response_low_seed",
            "severity": "low",
            "technique": "T1082",
            "rule_id": "demo-low-discovery",
            "source_ip": "10.0.10.11",
            "destination_ip": "10.0.20.11",
            "message": "Demo low-priority discovery behavior",
        },
        {
            "label": "response_medium_seed",
            "severity": "medium",
            "technique": "T1110",
            "rule_id": "demo-medium-bruteforce",
            "source_ip": "8.8.8.8",
            "destination_ip": "10.0.20.22",
            "message": "Demo medium-priority credential abuse behavior",
        },
        {
            "label": "response_high_seed",
            "severity": "high",
            "technique": "T1046",
            "rule_id": "demo-high-recon",
            "source_ip": "10.10.10.50",
            "destination_ip": "10.10.20.50",
            "message": "Demo high-priority network reconnaissance behavior",
        },
        {
            "label": "response_critical_seed",
            "severity": "critical",
            "technique": "T1190",
            "rule_id": "demo-critical-exploit",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.30.9",
            "message": "Demo critical-priority exploitation behavior",
        },
    ]
    for seed in response_seeds:
        results.append(
            _run_seed_command(
                [
                    sys.executable,
                    "scripts/run_response_action.py",
                    "--run-id",
                    run_id,
                    "--engine",
                    "response",
                    "--rule-id",
                    seed["rule_id"],
                    "--technique-id",
                    seed["technique"],
                    "--source-ip",
                    seed["source_ip"],
                    "--destination-ip",
                    seed["destination_ip"],
                    "--message",
                    seed["message"],
                    "--severity",
                    seed["severity"],
                ],
                label=seed["label"],
                timeout=90,
            )
        )
    return results


def stop_demo_run() -> dict[str, Any]:
    current = current_demo_run()
    if not current.get("active"):
        return {"active": False}
    stopped_at = now_utc()
    record = {
        **current,
        "stopped_at": stopped_at,
        "duration_seconds": round(
            (
                datetime.fromisoformat(stopped_at.replace("Z", "+00:00"))
                - datetime.fromisoformat(str(current["started_at"]).replace("Z", "+00:00"))
            ).total_seconds(),
            3,
        ),
    }
    history_file = writable_path(RUN_HISTORY_FILE)
    append_jsonl(history_file, record)
    writable_path(CURRENT_RUN_FILE).unlink(missing_ok=True)
    try:
        CURRENT_RUN_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    return {**record, "active": False}


def save_demo_run(name: str = "", note: str = "") -> dict[str, Any]:
    current = current_demo_run()
    if not current.get("active"):
        return {"active": False, "saved": False}
    snapshot = {
        **current,
        "saved": True,
        "saved_at": now_utc(),
        "name": clean_text(name) or current.get("name") or "Manual live validation",
        "note": clean_text(note) or current.get("note", ""),
    }
    history_file = writable_path(RUN_HISTORY_FILE)
    append_jsonl(history_file, snapshot)
    return {"active": True, **snapshot}


def demo_run_history(limit: int = 20) -> list[dict[str, Any]]:
    items = []
    seen_raw: set[str] = set()
    for history_file in readable_candidates(RUN_HISTORY_FILE):
        for row in read_jsonl(history_file):
            raw = json.dumps(row, sort_keys=True)
            if raw in seen_raw:
                continue
            seen_raw.add(raw)
            items.append(row)
    items.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return items[:limit]


def demo_run_by_id(run_id: str) -> dict[str, Any] | None:
    current = current_demo_run()
    if current.get("active") and clean_text(current.get("run_id")) == clean_text(run_id):
        return current
    for item in demo_run_history(limit=1000):
        if clean_text(item.get("run_id")) == clean_text(run_id):
            return item
    return None


def extract_alert_techniques(alert: dict[str, Any]) -> list[str]:
    values: list[str] = []

    def collect_threat(threat_payload: Any) -> None:
        threats = threat_payload if isinstance(threat_payload, list) else [threat_payload]
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            techniques = threat.get("technique") or []
            if isinstance(techniques, dict):
                techniques = [techniques]
            for technique in techniques:
                if not isinstance(technique, dict):
                    continue
                technique_id = technique.get("id")
                if technique_id:
                    values.append(str(technique_id))
                subtechniques = technique.get("subtechnique") or []
                if isinstance(subtechniques, dict):
                    subtechniques = [subtechniques]
                for subtechnique in subtechniques:
                    if isinstance(subtechnique, dict) and subtechnique.get("id"):
                        values.append(str(subtechnique["id"]))

    collect_threat(alert.get("threat"))
    collect_threat(alert.get("kibana.alert.rule.threat"))
    collect_threat((alert.get("kibana.alert.rule.parameters") or {}).get("threat"))

    rule = alert.get("rule") or {}
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") or []
    if isinstance(ids, list):
        values.extend(str(item) for item in ids if item)
    for item in (alert.get("kibana.alert.rule.tags") or []) + (alert.get("kibana.alert.rule.parameters", {}).get("tags") or []):
        if isinstance(item, str) and item.lower().startswith("attack.t"):
            values.append(f"T{item.split('.', 1)[1][1:].upper()}")
    normalized = []
    for value in values:
        if not value:
            continue
        normalized.append(re.sub(r"[^A-Za-z0-9.]", "", value).upper())
    return sorted(set(normalized))


def alert_title(source: dict[str, Any]) -> str:
    return clean_text(
        source.get("kibana.alert.rule.name")
        or ((source.get("rule") or {}).get("description"))
        or ((source.get("response") or {}).get("action_title"))
        or source.get("message")
        or "Alert"
    )


def live_alerts(limit: int = 50, start: str | None = None, end: str | None = None, run_id: str | None = None) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    query = {"bool": {"must": [build_range(start, end)]}}
    for index, engine in [(ELASTIC_ALERT_INDEX, "elastic"), (WAZUH_ALERT_INDEX, "wazuh"), (RESPONSE_INDEX, "response")]:
        try:
            data = es_request(
                "GET",
                f"/{index}/_search",
                {
                    "size": limit,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": query,
                },
            )
        except requests.HTTPError:
            continue
        for hit in data.get("hits", {}).get("hits", []):
            source = hit.get("_source") or {}
            technique_ids = extract_alert_techniques(source)
            severity_raw = clean_text(source.get("kibana.alert.severity") or ((source.get("rule") or {}).get("level")) or source.get("event", {}).get("outcome", ""))
            severity = normalize_severity(severity_raw)
            preview = response_preview(
                {
                    "mitre_ids": technique_ids,
                    "rule_id": source.get("kibana.alert.rule.rule_id") or ((source.get("rule") or {}).get("id")) or "",
                    "source_ip": ((source.get("source") or {}).get("ip") or ""),
                    "destination_ip": ((source.get("destination") or {}).get("ip") or ""),
                    "username": ((source.get("user") or {}).get("name") or ""),
                    "severity": severity_raw,
                }
            )
            item = {
                    "engine": engine,
                    "index": hit.get("_index"),
                    "id": hit.get("_id"),
                    "timestamp": source.get("@timestamp") or source.get("timestamp"),
                    "title": alert_title(source),
                    "severity": severity["label"],
                    "severity_level": severity["level"],
                    "severity_score": severity["score"],
                    "warning_level": severity["level"],
                    "rule_id": source.get("kibana.alert.rule.rule_id") or ((source.get("rule") or {}).get("id")) or "",
                    "message": clean_text(source.get("message") or source.get("full_log") or (source.get("response") or {}).get("summary") or ""),
                    "technique_ids": technique_ids,
                    "source_ip": ((source.get("source") or {}).get("ip") or ""),
                    "destination_ip": ((source.get("destination") or {}).get("ip") or ""),
                    "username": ((source.get("user") or {}).get("name") or ""),
                    "run_id": clean_text((source.get("labels") or {}).get("run_id") or ""),
                    "response_preview": preview,
                }
            if run_id and clean_text(item.get("run_id")) != clean_text(run_id):
                continue
            alerts.append(item)
    alerts.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return alerts[:limit]


def entity_timeline(entity_type: str, entity_id: str, start: str | None = None, end: str | None = None, limit: int = 300, run_id: str | None = None) -> dict[str, Any]:
    logs = search_logs("", limit=max(limit, 200), start=start, end=end, run_id=run_id)
    alerts = live_alerts(limit=max(limit, 200), start=start, end=end, run_id=run_id)
    target = clean_text(entity_id)

    events: list[dict[str, Any]] = []
    for item in logs:
        match = False
        if entity_type == "ip":
            match = target in {clean_text(item.get("source_ip")), clean_text(item.get("destination_ip"))}
        elif entity_type == "log":
            match = clean_text(item.get("id")) == target
        elif entity_type == "source":
            match = clean_text(item.get("source_index")) == target
        if match:
            events.append(
                {
                    "kind": "log",
                    "timestamp": item.get("timestamp"),
                    "id": item.get("id"),
                    "title": item.get("message"),
                    "source": item.get("source_index"),
                    "source_ip": item.get("source_ip"),
                    "destination_ip": item.get("destination_ip"),
                }
            )

    for item in alerts:
        match = False
        if entity_type == "ip":
            match = target in {clean_text(item.get("source_ip")), clean_text(item.get("destination_ip"))}
        elif entity_type == "rule":
            match = clean_text(item.get("rule_id")) == target
        elif entity_type == "playbook":
            match = target in [clean_text(technique) for technique in item.get("technique_ids", [])]
        elif entity_type == "run":
            match = clean_text(item.get("run_id")) == target
        if match:
            events.append(
                {
                    "kind": "alert",
                    "timestamp": item.get("timestamp"),
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "engine": item.get("engine"),
                    "rule_id": item.get("rule_id"),
                    "technique_ids": item.get("technique_ids", []),
                    "source_ip": item.get("source_ip"),
                    "destination_ip": item.get("destination_ip"),
                }
            )

    events.sort(key=lambda entry: entry.get("timestamp") or "", reverse=True)
    trimmed = events[:limit]
    timestamps = [entry.get("timestamp") for entry in trimmed if entry.get("timestamp")]
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "count": len(trimmed),
        "start_time": min(timestamps) if timestamps else "",
        "stop_time": max(timestamps) if timestamps else "",
        "events": trimmed,
    }


def log_detail(log_id: str, start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    mapped = map_log_to_rules(log_id, limit=8)
    log = mapped.get("log")
    if not log:
        return {"log": None, "matches": [], "timeline": {"events": []}, "ip_context": {}}
    timeline = entity_timeline("log", str(log.get("id") or log_id), start=start, end=end, limit=120, run_id=run_id)
    ip_context = {}
    source_ip = clean_text(log.get("source_ip"))
    if source_ip:
        ip_context["source_ip"] = {
            "ip": source_ip,
            "timeline": entity_timeline("ip", source_ip, start=start, end=end, limit=120, run_id=run_id),
        }
    destination_ip = clean_text(log.get("destination_ip"))
    if destination_ip:
        ip_context["destination_ip"] = {
            "ip": destination_ip,
            "timeline": entity_timeline("ip", destination_ip, start=start, end=end, limit=120, run_id=run_id),
        }
    return {
        "log": log,
        "matches": mapped.get("matches", []),
        "timeline": timeline,
        "ip_context": ip_context,
    }


def count(index: str, query: dict[str, Any] | None = None) -> int:
    try:
        return int(es_request("GET", f"/{index}/_count", {"query": query or {"match_all": {}}}).get("count") or 0)
    except requests.HTTPError:
        return 0


def aggregation(index: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return es_request("GET", f"/{index}/_search", payload)
    except requests.HTTPError:
        return {}


def load_orchestration_live() -> dict[str, Any]:
    if not ORCHESTRATION_LIVE_FILE.exists():
        payload = {"updated_at": now_utc(), "hands": []}
    else:
        try:
            payload = json.loads(ORCHESTRATION_LIVE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {"updated_at": now_utc(), "hands": []}
    if ZEROCLAW_GATEWAY_LOG.exists():
        lines = [line.strip() for line in ZEROCLAW_GATEWAY_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
        payload["hands"].append(
            {
                "hand_name": "zeroclaw_gateway",
                "run_id": "zeroclaw-gateway-live",
                "status": {"status": "completed"},
                "findings": [lines[-1] if lines else "ZeroClaw gateway log is available."],
                "steps": [{"title": "Gateway runtime", "detail": line, "status": "completed"} for line in lines[-6:]],
                "metrics": {"log_lines": len(lines)},
            }
        )
    status = zeroclaw_status()
    if status.get("available"):
        payload["zeroclaw"] = status
    return payload
def zeroclaw_daemon_health() -> dict[str, Any]:
    if not ZEROCLAW_GATEWAY_URL:
        return {"reachable": False, "url": "", "status": "not_configured"}
    try:
        response = requests.get(f"{ZEROCLAW_GATEWAY_URL}/health", timeout=5)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return {
            "reachable": False,
            "url": ZEROCLAW_GATEWAY_URL,
            "status": "unreachable",
            "error": clean_text(exc),
        }
    runtime = payload.get("runtime") or {}
    components = runtime.get("components") or {}
    scheduler = components.get("scheduler") or {}
    gateway = components.get("gateway") or {}
    return {
        "reachable": True,
        "url": ZEROCLAW_GATEWAY_URL,
        "status": clean_text(payload.get("status") or "ok"),
        "paired": bool(payload.get("paired")),
        "pairing_required": bool(payload.get("require_pairing")),
        "uptime_seconds": int(runtime.get("uptime_seconds") or 0),
        "scheduler_status": clean_text(scheduler.get("status") or ""),
        "gateway_status": clean_text(gateway.get("status") or ""),
        "pid": runtime.get("pid"),
    }


def orchestration_history(hand_name: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if hand_name == "zeroclaw_gateway":
        if not ZEROCLAW_GATEWAY_LOG.exists():
            return []
        lines = [line.strip() for line in ZEROCLAW_GATEWAY_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [
            {
                "hand_name": "zeroclaw_gateway",
                "run_id": f"zeroclaw-line-{index}",
                "status": {"status": "completed"},
                "findings": [line],
                "steps": [{"title": "Gateway output", "detail": line, "status": "completed"}],
                "metrics": {},
            }
            for index, line in enumerate(reversed(lines[-limit:]), start=1)
        ]
    if not ORCHESTRATION_RUNS_FILE.exists():
        return []
    runs = []
    for line in ORCHESTRATION_RUNS_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            run = json.loads(line)
        except json.JSONDecodeError:
            continue
        if hand_name and run.get("hand_name") != hand_name:
            continue
        runs.append(run)
    runs.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return runs[:limit]


def zeroclaw_status() -> dict[str, Any]:
    daemon = zeroclaw_daemon_health()
    if not ZEROCLAW_BIN.exists():
        return {
            "available": False,
            "status": "missing",
            "summary": "ZeroClaw binary is not mounted into the runtime.",
            "daemon": daemon,
        }
    try:
        result = subprocess.run(
            [str(ZEROCLAW_BIN), "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except OSError as exc:
        return {"available": False, "status": "error", "summary": str(exc)}
    raw_lines = [clean_text(line) for line in (result.stdout or "").splitlines() if clean_text(line)]
    lines = [
        line for line in raw_lines
        if "Config loaded" not in line
    ]
    if daemon.get("reachable"):
        daemon_lines = [
            f"Gateway daemon: running at {daemon['url']}",
            f"Gateway status: {daemon.get('gateway_status') or daemon.get('status')}",
            f"Scheduler status: {daemon.get('scheduler_status') or 'unknown'}",
            f"Pairing required: {'yes' if daemon.get('pairing_required') else 'no'}",
            f"Paired: {'yes' if daemon.get('paired') else 'no'}",
            f"Daemon uptime: {daemon.get('uptime_seconds', 0)}s",
        ]
        insert_at = 1 if lines else 0
        for offset, line in enumerate(daemon_lines):
            lines.insert(insert_at + offset, line)
    elif daemon.get("status") == "unreachable":
        lines.insert(1 if lines else 0, f"Gateway daemon: unavailable at {daemon.get('url')}")
    return {
        "available": True,
        "status": "ok" if result.returncode == 0 else "error",
        "summary": lines[0] if lines else clean_text(result.stderr.strip() or "ZeroClaw status produced no output."),
        "lines": lines[:20],
        "binary": str(ZEROCLAW_BIN),
        "daemon": daemon,
    }


def logs_analytics(start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    range_filter = build_range(start, end)
    timeline = aggregation(
        LIVE_LOG_INDEX,
        {
            "size": 0,
            "query": range_filter,
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m",
                        "min_doc_count": 0,
                    }
                }
            },
        },
    )
    suricata = aggregation(
        SURICATA_INDEX,
        {
            "size": 0,
            "query": range_filter,
            "aggs": {
                "protocols": {"terms": {"field": "network.transport", "size": 6}},
                "event_types": {"terms": {"field": "event_type", "size": 6}},
                "sources": {"terms": {"field": "source.ip", "size": 6}},
                "destinations": {"terms": {"field": "destination.ip", "size": 6}},
                "ports": {"terms": {"field": "destination.port", "size": 8}},
            },
        },
    )
    source_indices = aggregation(
        LIVE_LOG_INDEX,
        {
            "size": 0,
            "query": range_filter,
            "aggs": {
                "indices": {"terms": {"field": "source_index.keyword", "size": 8}},
                "decoders": {"terms": {"field": "decoder_name.keyword", "size": 8}},
            },
        },
    )
    alert_cards = live_alerts(limit=100, start=start, end=end, run_id=run_id)
    severity_counts = Counter(item.get("severity") or "unknown" for item in alert_cards)
    engine_counts = Counter(item.get("engine") or "unknown" for item in alert_cards)
    hand_history = orchestration_history(limit=120)
    hand_durations = Counter(run.get("hand_name") or "unknown" for run in hand_history)
    return {
        "timeline": [
            {"time": bucket.get("key_as_string"), "count": bucket.get("doc_count", 0)}
            for bucket in (((timeline.get("aggregations") or {}).get("timeline") or {}).get("buckets") or [])
        ],
        "severity_distribution": [{"label": label, "value": value} for label, value in severity_counts.items()],
        "engine_distribution": [{"label": label, "value": value} for label, value in engine_counts.items()],
        "suricata_protocols": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((suricata.get("aggregations") or {}).get("protocols") or {}).get("buckets") or [])
        ],
        "suricata_event_types": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((suricata.get("aggregations") or {}).get("event_types") or {}).get("buckets") or [])
        ],
        "top_sources": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((suricata.get("aggregations") or {}).get("sources") or {}).get("buckets") or [])
        ],
        "top_destinations": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((suricata.get("aggregations") or {}).get("destinations") or {}).get("buckets") or [])
        ],
        "top_ports": [
            {"label": str(bucket.get("key") or "unknown"), "value": bucket.get("doc_count", 0)}
            for bucket in (((suricata.get("aggregations") or {}).get("ports") or {}).get("buckets") or [])
        ],
        "source_indices": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((source_indices.get("aggregations") or {}).get("indices") or {}).get("buckets") or [])
        ],
        "decoder_distribution": [
            {"label": bucket.get("key") or "unknown", "value": bucket.get("doc_count", 0)}
            for bucket in (((source_indices.get("aggregations") or {}).get("decoders") or {}).get("buckets") or [])
        ],
        "agent_run_mix": [{"label": label, "value": value} for label, value in hand_durations.items()],
    }


def dashboard(start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    latest_alerts = live_alerts(limit=12, start=start, end=end, run_id=run_id)
    analytics = logs_analytics(start=start, end=end, run_id=run_id)
    agents = load_orchestration_live()
    return {
        "rules_total": count(RULE_INDEX),
        "logs_total": count(LIVE_LOG_INDEX, build_range(start, end)),
        "elastic_alerts_total": count(ELASTIC_ALERT_INDEX, build_range(start, end)),
        "wazuh_alerts_total": count(WAZUH_ALERT_INDEX, build_range(start, end)),
        "suricata_events_total": count(SURICATA_INDEX, build_range(start, end)),
        "response_actions_total": count(RESPONSE_INDEX, build_range(start, end)),
        "response_policy": load_policy(),
        "latest_alerts": latest_alerts,
        "analytics": analytics,
        "agents": agents,
        "zeroclaw": zeroclaw_status(),
        "run_state": current_demo_run(),
        "response_preview": latest_alerts[0]["response_preview"] if latest_alerts else response_preview({}),
    }


def verify_response_effect(payload: dict[str, Any]) -> dict[str, Any]:
    rule_id = clean_text(payload.get("rule_id"))
    source_ip = clean_text(payload.get("source_ip"))
    destination_ip = clean_text(payload.get("destination_ip"))
    recent = live_alerts(limit=150, start="now-30m")
    remaining = []
    for item in recent:
        if item.get("engine") == "response":
            continue
        if rule_id and clean_text(item.get("rule_id")) == rule_id:
            remaining.append(item)
            continue
        if source_ip and source_ip in {clean_text(item.get("source_ip")), clean_text(item.get("destination_ip"))}:
            remaining.append(item)
            continue
        if destination_ip and destination_ip in {clean_text(item.get("source_ip")), clean_text(item.get("destination_ip"))}:
            remaining.append(item)
            continue
    return {
        "window": "now-30m",
        "status": "mitigated" if not remaining else "still_active",
        "remaining_alerts": len(remaining),
        "sample": remaining[:5],
    }


def docker_availability() -> tuple[bool, str]:
    """Whether this runtime can start honeypot containers at all."""
    if not shutil.which("docker"):
        return False, "the docker CLI is not installed in this runtime"
    socket_path = Path(os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock"))
    if not socket_path.exists():
        return False, f"the docker socket ({socket_path}) is not mounted into this runtime"
    return True, ""


def deploy_honeypot(payload: dict[str, Any], severity_level: str) -> dict[str, Any]:
    available, reason = docker_availability()
    if not available:
        # Containment already happened; the lure is best-effort and must not turn
        # a successful response into an HTTP 500.
        return {
            "status": "skipped",
            "reason": reason,
            "hint": (
                "Run `python scripts/deploy_honeypot.py` on the docker host, or give this "
                "container the docker socket and CLI, to enable the honeypot stage."
            ),
        }
    command = [
        sys.executable,
        "scripts/deploy_honeypot.py",
        "--source-ip",
        clean_text(payload.get("source_ip")),
        "--rule-id",
        clean_text(payload.get("rule_id")),
        "--technique-id",
        clean_text(payload.get("technique_id")),
        "--engine",
        clean_text(payload.get("engine")),
        "--severity",
        severity_level,
        "--message",
        clean_text(payload.get("message")),
    ]
    result = _run_helper(command, "honeypot deployment")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("honeypot deployment returned invalid output")


def _tail_lines(path: Path, limit: int = 80) -> list[str]:
    if not path.exists():
        return []
    try:
        lines = [clean_text(line) for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
    except OSError:
        return []
    return [line for line in lines if line][-limit:]


def _docker_logs(container_name: str, limit: int = 80) -> list[str]:
    """Container logs through the docker CLI.

    Disabled unless `FDA_ENABLE_DOCKER_LOGS=1`: the API container has no docker
    client and no socket mounted, so the previous unconditional call shelled out
    (on every honeypot session lookup), failed, and burned its 20s timeout.
    """
    if not container_name or os.environ.get("FDA_ENABLE_DOCKER_LOGS") != "1":
        return []
    if not shutil.which("docker"):
        return []
    try:
        run = subprocess.run(
            ["docker", "logs", "--tail", str(limit), container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if run.returncode != 0:
        return []
    return [clean_text(line) for line in (run.stdout or "").splitlines() if clean_text(line)]


def honeypot_sessions(limit: int = 12) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in read_jsonl(HONEYPOT_SESSIONS_FILE):
        log_path = Path(str(row.get("log_path") or ""))
        # The deployer writes the container log to disk, so read that first; the
        # docker CLI is only consulted when explicitly opted into.
        session_logs = _tail_lines(log_path, limit=100) or _docker_logs(clean_text(row.get("container_name")))
        items.append(
            {
                "session_id": clean_text(row.get("session_id")),
                "created_at": clean_text(row.get("created_at")),
                "container_name": clean_text(row.get("container_name")),
                "container_id": clean_text(row.get("container_id")),
                "host_port": clean_text(row.get("host_port")),
                "severity": clean_text(row.get("severity")),
                "source_ip": clean_text(row.get("source_ip")),
                "rule_id": clean_text(row.get("rule_id")),
                "technique_id": clean_text(row.get("technique_id")),
                "nvidia_analysis": humanize_possible_structured_text(row.get("nvidia_analysis")),
                "logs": session_logs,
                "log_path": str(log_path),
            }
        )
    items.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return items[:limit]


def honeypot_session_detail(session_id: str) -> dict[str, Any] | None:
    for item in honeypot_sessions(limit=200):
        if clean_text(item.get("session_id")) == clean_text(session_id):
            return item
    return None


def chat_response(
    message: str,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
    detailed: bool = True,
) -> dict[str, Any]:
    normalized_message = clean_text(message)
    try:
        rules = search_rules(normalized_message, limit=5)
    except Exception:
        rules = []
    try:
        logs = search_logs(normalized_message, limit=8, start=start, end=end, run_id=run_id)
    except Exception:
        logs = []
    try:
        alerts = live_alerts(limit=8, start=start, end=end, run_id=run_id)
    except Exception:
        alerts = []
    top_alerts = [item for item in alerts if normalized_message.lower() in clean_text(item.get("title")).lower() or normalized_message.lower() in clean_text(item.get("message")).lower()]
    context = {
        "query": normalized_message,
        "run_id": run_id or "",
        "rule_hits": [
            {
                "rule_id": item.get("rule_id"),
                "engine": item.get("engine"),
                "title": item.get("title"),
                "mitre_ids": item.get("mitre_ids", [])[:4],
            }
            for item in rules[:5]
        ],
        "log_hits": [
            {
                "id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "source_index": item.get("source_index"),
                "message": item.get("message"),
                "source_ip": item.get("source_ip"),
                "destination_ip": item.get("destination_ip"),
            }
            for item in logs[:6]
        ],
        "alert_hits": [
            {
                "id": item.get("id"),
                "engine": item.get("engine"),
                "title": item.get("title"),
                "severity_level": item.get("severity_level"),
                "rule_id": item.get("rule_id"),
                "technique_ids": item.get("technique_ids", [])[:4],
            }
            for item in top_alerts[:6]
        ],
    }
    if NVIDIA_API_KEY:
        system_prompt = (
            "You are a SOC copilot assistant. Use only provided context. "
            "Return strict JSON with keys answer and next_actions (array of short strings)."
        )
        if detailed:
            system_prompt = (
                "You are a SOC copilot assistant. Use only provided context. "
                "Return strict JSON with keys answer and next_actions. "
                "answer must be detailed and include: what is happening, strongest evidence, likely attack hypothesis, "
                "confidence level, and immediate containment guidance."
            )
        body = {
            "model": NVIDIA_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {"role": "user", "content": json.dumps(context, sort_keys=True)},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        try:
            response = requests.post(
                "https://integrate.api.nvidia.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
                json=body,
                timeout=30,
            )
            response.raise_for_status()
            parsed = json.loads(str(response.json()["choices"][0]["message"]["content"]).strip())
            return {
                "message": normalized_message,
                "answer": clean_text(parsed.get("answer")),
                "next_actions": [clean_text(item) for item in (parsed.get("next_actions") or []) if clean_text(item)],
                "references": context,
                "llm_generated": True,
            }
        except Exception:
            pass
    dynamic_summary = (
        f"Found {len(rules)} matching rules, {len(logs)} matching logs, and {len(top_alerts)} matching alerts "
        f"for '{normalized_message}'."
    )
    if detailed:
        dynamic_summary = (
            f"{dynamic_summary} Top rule: {clean_text((rules[0] or {}).get('rule_id') if rules else 'none')}. "
            f"Top log source: {clean_text((logs[0] or {}).get('source_index') if logs else 'none')}. "
            f"Highest matching alert severity: {clean_text((top_alerts[0] or {}).get('severity_level') if top_alerts else 'none')}."
        )
    next_actions = []
    if rules:
        next_actions.append(f"Inspect rule {clean_text(rules[0].get('rule_id'))} in Rule Studio.")
    if logs:
        next_actions.append(f"Pivot to log {clean_text(logs[0].get('id'))} in Logs + Runs.")
    if top_alerts:
        next_actions.append(f"Review alert {clean_text(top_alerts[0].get('title'))} severity {clean_text(top_alerts[0].get('severity_level'))}.")
    return {
        "message": normalized_message,
        "answer": dynamic_summary,
        "next_actions": next_actions,
        "references": context,
        "llm_generated": False,
    }


def execute_manual_response(payload: dict[str, Any]) -> dict[str, Any]:
    technique_id = payload.get("technique_id", "") or ((payload.get("mitre_ids") or [""])[0])
    command = [
        sys.executable,
        "scripts/run_response_action.py",
        "--engine",
        payload["engine"],
        "--rule-id",
        payload.get("rule_id", ""),
        "--technique-id",
        technique_id,
        "--source-ip",
        payload.get("source_ip", ""),
        "--destination-ip",
        payload.get("destination_ip", ""),
        "--username",
        payload.get("username", ""),
        "--message",
        payload.get("message", ""),
        "--severity",
        payload.get("severity", ""),
    ]
    if payload.get("alert_index"):
        command.extend(["--alert-index", payload["alert_index"]])
    if payload.get("alert_id"):
        command.extend(["--alert-id", payload["alert_id"]])
    preview = response_preview({**payload, "technique_id": technique_id}, include_llm=True)
    result = _run_helper(command, "response action")
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError:
        body = {"raw_output": result.stdout}
    body["preview"] = preview
    severity_level = clean_text(((preview.get("severity") or {}).get("level")))
    if severity_level == "critical":
        try:
            body["honeypot"] = deploy_honeypot({**payload, "technique_id": technique_id}, severity_level=severity_level)
        except RuntimeError as exc:
            body["honeypot_error"] = str(exc)
    body["verification"] = verify_response_effect(payload)
    return body
