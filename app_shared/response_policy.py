from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app_shared.state_paths import append_jsonl, read_json, state_path, write_json


POLICY_STATE_FILE = state_path("response", "policy.json")
ACTION_LOG_DIR = state_path("response")
ACTION_MAP_FILE = Path("config/response/actions.yml")
RESPONSE_INDEX_PREFIX = "security-response"

DEFAULT_POLICY: dict[str, Any] = {
    "auto_execute": False,
    "engines": {
        "elastic": False,
        "wazuh": False,
    },
    "allow_manual_execute": True,
}

ACTION_DETAILS: dict[str, dict[str, str]] = {
    "block_source_ip": {
        "title": "Block source address",
        "summary": "Block the abusive source address in the live API control plane so new requests from it are rejected immediately.",
        "command_template": "python scripts/apply_response_control.py block_source_ip --source-ip '{{source_ip}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The source address is present in the runtime blocklist and subsequent requests from it return an access-denied response.",
    },
    "throttle_service": {
        "title": "Throttle service exposure",
        "summary": "Apply a live per-minute request limit for the affected API path or client source.",
        "command_template": "python scripts/apply_response_control.py throttle_service --source-ip '{{source_ip}}' --target-path '{{target_path}}' --requests-per-minute '{{requests_per_minute}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The rate-limit rule is active and excess requests are answered with a throttled response.",
    },
    "disable_account": {
        "title": "Disable account",
        "summary": "Disable the observed account in the live API control plane so requests tied to that user are rejected.",
        "command_template": "python scripts/apply_response_control.py disable_account --username '{{username}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The username is present in the disabled-account list and future requests for that user are denied.",
    },
    "isolate_host": {
        "title": "Isolate host",
        "summary": "Mark the impacted host as isolated so operators can see the endpoint is under containment.",
        "command_template": "python scripts/apply_response_control.py isolate_host --destination-ip '{{destination_ip}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The endpoint is present in the live isolated-host inventory with the associated incident metadata.",
    },
    "quarantine_endpoint": {
        "title": "Quarantine endpoint",
        "summary": "Quarantine the affected endpoint in the runtime containment registry so the frontend reflects the state immediately.",
        "command_template": "python scripts/apply_response_control.py quarantine_endpoint --destination-ip '{{destination_ip}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The destination endpoint is present in the quarantine registry with a successful execution record.",
    },
    "block_egress": {
        "title": "Block egress path",
        "summary": "Block the suspicious source from continuing outbound activity inside the runtime network control registry.",
        "command_template": "python scripts/apply_response_control.py block_egress --source-ip '{{source_ip}}' --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "The source address is present in the egress-block registry and the action is recorded as successful.",
    },
    "observe_only": {
        "title": "Observe only",
        "summary": "Record analyst observation without applying containment so the incident stays visible but the runtime remains unchanged.",
        "command_template": "python scripts/apply_response_control.py observe_only --rule-id '{{rule_id}}' --technique-id '{{technique_id}}'",
        "success_criteria": "An observation is written to the response journal without adding any enforcement control.",
    },
}


def default_action_map() -> dict[str, Any]:
    return {
        "default_action": "observe_only",
        "technique_actions": {
            "T1003": "disable_account",
            "T1003.001": "disable_account",
            "T1003.002": "disable_account",
            "T1003.004": "disable_account",
            "T1021": "isolate_host",
            "T1021.001": "isolate_host",
            "T1021.002": "isolate_host",
            "T1021.004": "isolate_host",
            "T1027": "observe_only",
            "T1036": "observe_only",
            "T1041": "block_egress",
            "T1046": "block_source_ip",
            "T1047": "isolate_host",
            "T1053": "disable_account",
            "T1053.003": "disable_account",
            "T1053.005": "disable_account",
            "T1055": "isolate_host",
            "T1059": "isolate_host",
            "T1059.001": "isolate_host",
            "T1059.004": "isolate_host",
            "T1068": "isolate_host",
            "T1070": "isolate_host",
            "T1071": "block_egress",
            "T1071.002": "block_egress",
            "T1078": "disable_account",
            "T1082": "observe_only",
            "T1083": "observe_only",
            "T1087": "disable_account",
            "T1098": "disable_account",
            "T1105": "block_egress",
            "T1112": "isolate_host",
            "T1110": "disable_account",
            "T1110.001": "disable_account",
            "T1114": "disable_account",
            "T1136": "disable_account",
            "T1136.001": "disable_account",
            "T1136.002": "disable_account",
            "T1189": "quarantine_endpoint",
            "T1190": "quarantine_endpoint",
            "T1195": "quarantine_endpoint",
            "T1204": "isolate_host",
            "T1210": "isolate_host",
            "T1486": "quarantine_endpoint",
            "T1489": "throttle_service",
            "T1491": "throttle_service",
            "T1498": "throttle_service",
            "T1498.001": "throttle_service",
            "T1499": "throttle_service",
            "T1499.003": "throttle_service",
            "T1562": "isolate_host",
            "T1566": "quarantine_endpoint",
            "T1566.001": "quarantine_endpoint",
            "T1566.002": "quarantine_endpoint",
            "T1571": "block_egress",
            "T1573": "block_egress",
            "T1574": "isolate_host",
            "T1589": "observe_only",
            "T1595": "block_source_ip",
            "T1595.001": "block_source_ip",
        },
        "prefix_actions": {
            "T1003": "disable_account",
            "T1021": "isolate_host",
            "T1041": "block_egress",
            "T104": "block_source_ip",
            "T105": "isolate_host",
            "T1071": "block_egress",
            "T1078": "disable_account",
            "T1110": "disable_account",
            "T1136": "disable_account",
            "T1189": "quarantine_endpoint",
            "T1190": "quarantine_endpoint",
            "T148": "quarantine_endpoint",
            "T1498": "throttle_service",
            "T1499": "throttle_service",
            "T156": "isolate_host",
            "T157": "block_egress",
            "T1595": "block_source_ip",
        },
    }


def ensure_action_map_file() -> None:
    if ACTION_MAP_FILE.exists():
        return
    ACTION_MAP_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACTION_MAP_FILE.write_text(yaml.safe_dump(default_action_map(), sort_keys=False), encoding="utf-8")


def load_action_map() -> dict[str, Any]:
    ensure_action_map_file()
    data = yaml.safe_load(ACTION_MAP_FILE.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else default_action_map()


def load_policy() -> dict[str, Any]:
    data = read_json(POLICY_STATE_FILE, default=None)
    if not isinstance(data, dict):
        return DEFAULT_POLICY.copy()
    merged = DEFAULT_POLICY.copy()
    merged.update(data)
    merged["engines"] = {**DEFAULT_POLICY["engines"], **(data.get("engines") or {})}
    return merged


def save_policy(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "auto_execute": bool(policy.get("auto_execute", False)),
        "engines": {
            "elastic": bool((policy.get("engines") or {}).get("elastic", False)),
            "wazuh": bool((policy.get("engines") or {}).get("wazuh", False)),
        },
        "allow_manual_execute": bool(policy.get("allow_manual_execute", True)),
    }
    write_json(POLICY_STATE_FILE, normalized)
    return normalized


def is_auto_execution_enabled(engine: str) -> bool:
    policy = load_policy()
    return bool(policy.get("auto_execute")) and bool((policy.get("engines") or {}).get(engine, False))


def response_file_name(action: str) -> str:
    mapping = {
        "block_source_ip": "blocklist.jsonl",
        "throttle_service": "service_throttle.jsonl",
        "disable_account": "disabled_accounts.jsonl",
        "isolate_host": "isolated_hosts.jsonl",
        "quarantine_endpoint": "quarantined_endpoints.jsonl",
        "block_egress": "egress_blocks.jsonl",
        "observe_only": "observations.jsonl",
    }
    return mapping.get(action, "actions.jsonl")


def choose_action(technique_ids: list[str]) -> str:
    action_map = load_action_map()
    exact = action_map.get("technique_actions") or {}
    prefix = action_map.get("prefix_actions") or {}
    for technique_id in technique_ids:
        if exact.get(technique_id):
            return str(exact[technique_id])
    for technique_id in technique_ids:
        for key, value in prefix.items():
            if technique_id.startswith(key):
                return str(value)
    return str(action_map.get("default_action") or "observe_only")


def action_detail(action: str) -> dict[str, str]:
    detail = ACTION_DETAILS.get(action) or ACTION_DETAILS["observe_only"]
    return {"action": action, **detail}


def render_command_preview(action: str, payload: dict[str, Any]) -> str:
    template = action_detail(action)["command_template"]
    rendered = template
    defaults = {
        "target_path": "/api/login",
        "requests_per_minute": "30",
    }
    for key in ["source_ip", "destination_ip", "username", "rule_id", "technique_id", "target_path", "requests_per_minute"]:
        value = payload.get(key)
        if value in {"", None} and key in defaults:
            value = defaults[key]
        rendered = rendered.replace(f"{{{{{key}}}}}", str(value or ""))
    return rendered


def run_logged_command(action: str, payload: dict[str, Any]) -> str:
    """Record a response action in the matching JSONL log and return the path.

    This used to shell out to `bash -lc "mkdir ... && printf ... >> file"`, which
    spawned a process (and a quoting hazard) for a single append. It now appends
    the line directly under an advisory lock.
    """
    target = ACTION_LOG_DIR / response_file_name(action)
    append_jsonl(target, payload)
    return str(target)
