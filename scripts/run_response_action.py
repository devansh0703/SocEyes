from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.mitre_playbooks import load_playbook_excerpt, resolve_playbook_path
from app_shared.response_policy import (
    RESPONSE_INDEX_PREFIX,
    VALID_ACTIONS,
    action_detail,
    choose_action,
    render_command_preview,
)
from app_shared.state_paths import append_jsonl, state_path
from common import ELASTICSEARCH_URL, elastic_session


RESPONSE_ACTIONS_FILE = state_path("response", "actions.jsonl")
# Child processes started from an alert-driven handler must be bounded.
CONTROL_TIMEOUT_SECONDS = int(os.environ.get("FDA_CONTROL_TIMEOUT_SECONDS", "120"))
HONEYPOT_TIMEOUT_SECONDS = int(os.environ.get("FDA_HONEYPOT_TIMEOUT_SECONDS", "240"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute a deterministic response action")
    parser.add_argument("--scenario-id", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--alert-index", default="")
    parser.add_argument("--alert-id", default="")
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--detected-at", default="")
    parser.add_argument("--technique-id", default="")
    parser.add_argument("--source-ip", default="")
    parser.add_argument("--destination-ip", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--message", default="")
    parser.add_argument("--severity", default="")
    return parser.parse_args()


def nvidia_summary(incident: dict[str, Any], playbook_excerpt: str) -> str:
    """Terse SOC note for the executed response (shared LLM client)."""
    prompt = {
        "engine": incident["response"]["engine"],
        "rule_id": incident["rule"]["id"],
        "technique_id": incident["threat"]["technique"]["id"],
        "response_action": incident["response"]["action"],
        "source_ip": incident.get("source", {}).get("ip", ""),
        "destination_ip": incident.get("destination", {}).get("ip", ""),
        "message": incident.get("message", ""),
    }
    return chat_completion(
        messages=[
            {
                "role": "system",
                "content": "Write a terse SOC note. Use 2 sentences max. Do not invent steps outside the provided playbook excerpt.",
            },
            {
                "role": "user",
                "content": json.dumps(prompt, sort_keys=True) + "\n\nPlaybook excerpt:\n" + playbook_excerpt,
            },
        ],
        max_tokens=200,
        temperature=0.1,
        timeout=30,
    ) or ""


def nvidia_plan(payload: dict[str, Any], fallback_action: str, playbook_excerpt: str) -> dict[str, Any]:
    """LLM-chosen response action with deterministic validation + fallback."""
    content = chat_completion(
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a SOC response planner. Pick one action from "
                    "block_source_ip, throttle_service, disable_account, isolate_host, quarantine_endpoint, block_egress, observe_only. "
                    "Return JSON only with keys action, reason, target_path, requests_per_minute. "
                    "Do not invent fields. Prefer throttle_service for high-volume HTTP abuse, block_source_ip for scans, "
                    "disable_account for credential abuse, quarantine_endpoint for exploitation, block_egress for C2."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "fallback_action": fallback_action,
                        "payload": payload,
                        "playbook_excerpt": playbook_excerpt[:1500],
                    },
                    sort_keys=True,
                ),
            },
        ],
        max_tokens=300,
        temperature=0.1,
        timeout=30,
    )
    if not content:
        return {"action": fallback_action}
    try:
        planned = extract_json_object(content)
    except (ValueError, json.JSONDecodeError):
        return {"action": fallback_action}
    action = str(planned.get("action") or fallback_action)
    if action not in VALID_ACTIONS:
        action = fallback_action
    return {
        "action": action,
        "reason": str(planned.get("reason") or ""),
        "target_path": str(planned.get("target_path") or "/api/login"),
        "requests_per_minute": int(planned.get("requests_per_minute") or 30),
    }


def index_response(doc: dict[str, Any]) -> None:
    session = elastic_session()
    index_name = f"{RESPONSE_INDEX_PREFIX}-{datetime.now(timezone.utc):%Y.%m.%d}"
    response = session.post(f"{ELASTICSEARCH_URL}/{index_name}/_doc", json=doc, timeout=30)
    response.raise_for_status()


def pick_action(args: argparse.Namespace, technique_id: str) -> str:
    return choose_action([technique_id] if technique_id else [])


def main() -> int:
    args = parse_args()
    technique_id = args.technique_id

    fallback_action = pick_action(args, technique_id)
    playbook_path = resolve_playbook_path(technique_id)
    playbook_excerpt = load_playbook_excerpt(playbook_path)
    payload = {
        "alert_id": args.alert_id,
        "alert_index": args.alert_index,
        "detected_at": args.detected_at,
        "destination_ip": args.destination_ip,
        "engine": args.engine,
        "message": args.message,
        "rule_id": args.rule_id,
        "scenario_id": args.scenario_id,
        "source_ip": args.source_ip,
        "severity": args.severity,
        "technique_id": technique_id,
        "username": args.username,
    }
    plan = nvidia_plan(payload, fallback_action, playbook_excerpt)
    action = str(plan.get("action") or fallback_action)
    response_payload = {
        **payload,
        "target_path": str(plan.get("target_path") or "/api/login"),
        "requests_per_minute": int(plan.get("requests_per_minute") or 30),
    }
    preview = action_detail(action)
    preview_command = render_command_preview(action, response_payload)
    command = [
        sys.executable,
        "scripts/apply_response_control.py",
        action,
        "--source-ip",
        args.source_ip,
        "--destination-ip",
        args.destination_ip,
        "--username",
        args.username,
        "--target-path",
        response_payload["target_path"],
        "--requests-per-minute",
        str(response_payload["requests_per_minute"]),
        "--rule-id",
        args.rule_id,
        "--technique-id",
        technique_id,
        "--engine",
        args.engine,
        "--message",
        args.message,
    ]
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=CONTROL_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        print(f"response action timed out after {CONTROL_TIMEOUT_SECONDS}s", file=sys.stderr)
        return 1
    if process.returncode != 0:
        print(process.stderr.strip() or process.stdout.strip() or "response action failed", file=sys.stderr)
        return process.returncode
    executed_command = " ".join(command)
    control_result = {}
    try:
        control_result = json.loads(process.stdout)
    except json.JSONDecodeError:
        control_result = {"raw_output": process.stdout.strip()}

    incident = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "message": args.message or f"Response action {action} executed",
        "event": {
            "action": action,
            "category": ["response"],
            "dataset": "security.response",
            "kind": "event",
            "outcome": "success",
            "type": ["change"],
        },
        "labels": {
            "run_id": args.run_id,
            "scenario_id": args.scenario_id,
            "alert_index": args.alert_index,
        },
        "rule": {
            "id": args.rule_id,
            "level": args.severity or "",
        },
        "kibana": {"alert": {"severity": args.severity or ""}},
        "source": {
            "ip": args.source_ip,
        },
        "destination": {
            "ip": args.destination_ip,
        },
        "user": {
            "name": args.username,
        },
        "threat": {
            "technique": {
                "id": [technique_id] if technique_id else [],
            }
        },
        "response": {
            "action": action,
            "action_title": preview["title"],
            "summary": preview["summary"],
            "preview_command": preview_command,
            "command": executed_command,
            "playbook_path": playbook_path,
            "status": "executed",
            "engine": args.engine,
            "detected_at": args.detected_at,
            "alert_id": args.alert_id,
            "llm_plan": plan,
            "control_result": control_result,
            "severity": args.severity,
        },
    }
    if str(args.severity).strip().lower() == "critical":
        honeypot_command = [
            sys.executable,
            "scripts/deploy_honeypot.py",
            "--source-ip",
            args.source_ip,
            "--rule-id",
            args.rule_id,
            "--technique-id",
            technique_id,
            "--engine",
            args.engine,
            "--severity",
            args.severity,
            "--message",
            args.message,
        ]
        try:
            honeypot = subprocess.run(
                honeypot_command,
                capture_output=True,
                text=True,
                check=False,
                timeout=HONEYPOT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            incident["response"]["honeypot_error"] = (
                f"honeypot deployment timed out after {HONEYPOT_TIMEOUT_SECONDS}s"
            )
        else:
            if honeypot.returncode == 0:
                try:
                    incident["response"]["honeypot"] = json.loads(honeypot.stdout)
                except json.JSONDecodeError:
                    incident["response"]["honeypot_raw"] = honeypot.stdout.strip()
            else:
                incident["response"]["honeypot_error"] = honeypot.stderr.strip() or honeypot.stdout.strip()
    llm_summary = nvidia_summary(incident, playbook_excerpt)
    if llm_summary:
        incident["response"]["llm_summary"] = llm_summary

    append_jsonl(RESPONSE_ACTIONS_FILE, incident)

    index_response(incident)
    print(json.dumps(incident, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
