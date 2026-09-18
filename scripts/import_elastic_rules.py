from __future__ import annotations

import argparse
import sys
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib
from pathlib import Path

from common import upsert_detection_rule, wait_for_kibana


def iter_rule_files(root: Path, include_deprecated: bool) -> list[Path]:
    candidates = sorted(root.rglob("*.toml"))
    if include_deprecated:
        return candidates
    return [path for path in candidates if "_deprecated" not in path.parts]


def normalize_rule_payload(raw_rule: dict, enable_rules: bool) -> dict:
    payload = dict(raw_rule)
    payload.pop("timeline_id", None)
    payload.pop("timeline_title", None)

    if payload.get("type") == "new_terms" and payload.get("new_terms"):
        new_terms = payload.pop("new_terms")
        field_name = new_terms.get("field")
        if field_name and "value" in new_terms:
            payload[field_name] = new_terms["value"]

        history_window = new_terms.get("history_window_start")
        if isinstance(history_window, list) and history_window:
            payload["history_window_start"] = history_window[0].get("value")
        elif isinstance(history_window, dict):
            payload["history_window_start"] = history_window.get("value")

    if payload.get("exceptions_list"):
        payload["exceptions_list"] = [
            item for item in payload["exceptions_list"] if item.get("list_id") != "endpoint_list"
        ]
        if not payload["exceptions_list"]:
            payload.pop("exceptions_list")

    payload.setdefault("interval", "5m")
    payload.setdefault("from", "now-10m")
    payload["enabled"] = enable_rules and payload.get("type") != "machine_learning"
    return payload


def import_rule_file(path: Path, enable_rules: bool) -> str:
    with path.open("rb") as handle:
        document = tomllib.load(handle)

    if "rule" not in document:
        raise ValueError(f"{path} does not contain a [rule] section")

    payload = normalize_rule_payload(document["rule"], enable_rules)
    return upsert_detection_rule(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Elastic detection-rules TOML into Kibana detections")
    parser.add_argument(
        "--rules-path",
        action="append",
        default=[
            "detection-rules/rules",
            "detection-rules/rules_building_block",
        ],
        help="Path containing detection-rules TOML content",
    )
    parser.add_argument("--include-deprecated", action="store_true", help="Also import deprecated Elastic rules")
    parser.add_argument("--disable-rules", action="store_true", help="Create rules in disabled state")
    parser.add_argument("--max-rules", type=int, default=0, help="Only import the first N rules")
    args = parser.parse_args()

    wait_for_kibana()

    files: list[Path] = []
    for rule_path in args.rules_path:
        files.extend(iter_rule_files(Path(rule_path), args.include_deprecated))

    unique_files = sorted(set(files))
    if args.max_rules:
        unique_files = unique_files[: args.max_rules]

    created = 0
    updated = 0
    failed = 0

    for index, path in enumerate(unique_files, start=1):
        try:
            result = import_rule_file(path, enable_rules=not args.disable_rules)
            if result == "created":
                created += 1
            else:
                updated += 1
            if index % 100 == 0:
                print(f"[elastic-rules] processed {index}/{len(unique_files)}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[elastic-rules] failed {path}: {exc}", file=sys.stderr)

    print(
        f"[elastic-rules] done: created={created} updated={updated} failed={failed} total={len(unique_files)}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
