from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.response_policy import is_auto_execution_enabled
from app_shared.state_paths import state_path
from common import ELASTICSEARCH_URL, elastic_session


WATCHER_STATE_FILE = state_path("response", "watcher_state.json")
WATCHED_INDICES = [
    (".alerts-security.alerts-*", "elastic"),
    ("wazuh-alerts-*", "wazuh"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Watch alerts and trigger response actions")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def load_seen() -> set[str]:
    if not WATCHER_STATE_FILE.exists():
        return set()
    try:
        payload = json.loads(WATCHER_STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return set(payload.get("seen", []))


def save_seen(seen: set[str]) -> None:
    WATCHER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    trimmed = list(sorted(seen))[-10000:]
    WATCHER_STATE_FILE.write_text(json.dumps({"seen": trimmed}, indent=2), encoding="utf-8")


def query_hits(index_pattern: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    session = elastic_session()
    response = session.get(f"{ELASTICSEARCH_URL}/{index_pattern}/_search", json=payload, timeout=60)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def extract_techniques(source: dict[str, Any]) -> list[str]:
    values: list[str] = []
    threat = source.get("threat") or {}
    technique = threat.get("technique") or {}
    ids = technique.get("id") or []
    if isinstance(ids, list):
        values.extend(str(item) for item in ids if item)
    rule = source.get("rule") or {}
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") or []
    if isinstance(ids, list):
        values.extend(str(item) for item in ids if item)
    for tag in (source.get("kibana.alert.rule.tags") or []) + ((source.get("kibana.alert.rule.parameters") or {}).get("tags") or []):
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            values.append(f"T{tag.split('.', 1)[1][1:].upper()}")
    return sorted(set(values))


def extract_field(source: dict[str, Any], path: list[str], default: str = "") -> str:
    current: Any = source
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return str(current or default)


def build_command(engine: str, index_name: str, hit: dict[str, Any]) -> list[str]:
    source = hit.get("_source") or {}
    techniques = extract_techniques(source)
    detected_at = extract_field(source, ["@timestamp"]) or extract_field(source, ["timestamp"])
    rule_id = extract_field(source, ["kibana.alert.rule.rule_id"]) or extract_field(source, ["rule", "id"])
    source_ip = extract_field(source, ["source", "ip"])
    destination_ip = extract_field(source, ["destination", "ip"])
    username = extract_field(source, ["user", "name"]) or extract_field(source, ["auth", "username"])
    message = extract_field(source, ["message"]) or extract_field(source, ["full_log"])
    severity = (
        extract_field(source, ["kibana.alert.severity"])
        or extract_field(source, ["rule", "level"])
        or extract_field(source, ["event", "outcome"])
    )
    command = [
        sys.executable,
        "scripts/run_response_action.py",
        "--alert-index",
        index_name,
        "--alert-id",
        hit["_id"],
        "--engine",
        engine,
        "--rule-id",
        rule_id,
        "--detected-at",
        detected_at,
        "--technique-id",
        techniques[0] if techniques else "",
        "--source-ip",
        source_ip,
        "--destination-ip",
        destination_ip,
        "--username",
        username,
        "--message",
        message,
        "--severity",
        severity,
    ]
    return command


def should_skip(engine: str, source: dict[str, Any]) -> bool:
    if not is_auto_execution_enabled(engine):
        return True
    event_dataset = extract_field(source, ["event", "dataset"])
    return event_dataset == "security.response"


def main() -> int:
    args = parse_args()
    seen = load_seen()

    while True:
        changed = False
        for index_pattern, engine in WATCHED_INDICES:
            hits = query_hits(
                index_pattern,
                {
                    "size": 200,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {"match_all": {}},
                },
            )
            for hit in hits:
                hit_id = f"{hit['_index']}:{hit['_id']}"
                if hit_id in seen:
                    continue
                source = hit.get("_source") or {}
                if should_skip(engine, source):
                    seen.add(hit_id)
                    changed = True
                    continue
                subprocess.run(build_command(engine, hit["_index"], hit), check=False)
                seen.add(hit_id)
                changed = True
        if changed:
            save_seen(seen)
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
