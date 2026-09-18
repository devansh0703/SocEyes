from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.state_paths import append_jsonl, read_json, state_path, write_json


STATE_DIR = state_path("response", "runtime")
ACTION_LOG = state_path("response", "control_actions.jsonl")

FILES = {
    "block_source_ip": STATE_DIR / "blocked_ips.json",
    "throttle_service": STATE_DIR / "rate_limits.json",
    "disable_account": STATE_DIR / "disabled_accounts.json",
    "isolate_host": STATE_DIR / "isolated_hosts.json",
    "quarantine_endpoint": STATE_DIR / "quarantined_endpoints.json",
    "block_egress": STATE_DIR / "egress_blocks.json",
}


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def load_list(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path, default=[])
    return payload if isinstance(payload, list) else []


def save_list(path: Path, payload: list[dict[str, Any]]) -> None:
    write_json(path, payload)


def append_action(entry: dict[str, Any]) -> None:
    append_jsonl(ACTION_LOG, entry)


def upsert(path: Path, key_name: str, key_value: str, entry: dict[str, Any]) -> dict[str, Any]:
    current = load_list(path)
    updated = False
    for index, item in enumerate(current):
        if str(item.get(key_name) or "") == key_value:
            current[index] = {**item, **entry}
            updated = True
            break
    if not updated:
        current.append(entry)
    save_list(path, current)
    return {"updated": updated, "count": len(current)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply a live response control to the runtime state")
    parser.add_argument(
        "action",
        choices=[
            "block_source_ip",
            "throttle_service",
            "disable_account",
            "isolate_host",
            "quarantine_endpoint",
            "block_egress",
            "observe_only",
        ],
    )
    parser.add_argument("--source-ip", default="")
    parser.add_argument("--destination-ip", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--target-path", default="/api/login")
    parser.add_argument("--requests-per-minute", type=int, default=30)
    parser.add_argument("--rule-id", default="")
    parser.add_argument("--technique-id", default="")
    parser.add_argument("--engine", default="")
    parser.add_argument("--message", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timestamp = now_iso()
    detail = {
        "action": args.action,
        "source_ip": args.source_ip,
        "destination_ip": args.destination_ip,
        "username": args.username,
        "target_path": args.target_path,
        "requests_per_minute": args.requests_per_minute,
        "rule_id": args.rule_id,
        "technique_id": args.technique_id,
        "engine": args.engine,
        "message": args.message,
        "updated_at": timestamp,
    }

    if args.action == "observe_only":
        result = {"status": "recorded", "count": 0, "updated": False}
    elif args.action == "block_source_ip":
        if not args.source_ip:
            raise SystemExit("block_source_ip requires --source-ip")
        result = upsert(
            FILES[args.action],
            "ip",
            args.source_ip,
            {"ip": args.source_ip, "reason": args.rule_id or args.technique_id or "manual", **detail},
        )
    elif args.action == "throttle_service":
        key = f"{args.source_ip}:{args.target_path}"
        result = upsert(
            FILES[args.action],
            "key",
            key,
            {
                "key": key,
                "source_ip": args.source_ip,
                "path": args.target_path,
                "requests_per_minute": args.requests_per_minute,
                **detail,
            },
        )
    elif args.action == "disable_account":
        if not args.username:
            raise SystemExit("disable_account requires --username")
        result = upsert(
            FILES[args.action],
            "username",
            args.username,
            {"username": args.username, "reason": args.rule_id or args.technique_id or "manual", **detail},
        )
    elif args.action in {"isolate_host", "quarantine_endpoint"}:
        if not args.destination_ip:
            raise SystemExit(f"{args.action} requires --destination-ip")
        result = upsert(
            FILES[args.action],
            "ip",
            args.destination_ip,
            {"ip": args.destination_ip, "reason": args.rule_id or args.technique_id or "manual", **detail},
        )
    elif args.action == "block_egress":
        if not args.source_ip:
            raise SystemExit("block_egress requires --source-ip")
        result = upsert(
            FILES[args.action],
            "ip",
            args.source_ip,
            {"ip": args.source_ip, "reason": args.rule_id or args.technique_id or "manual", **detail},
        )
    else:
        raise SystemExit(f"Unsupported action: {args.action}")

    action_record = {"@timestamp": timestamp, **detail, **result}
    append_action(action_record)
    print(json.dumps(action_record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
