from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from common import upsert_detection_rule, wait_for_kibana


SIGMA_ROOTS = [
    "sigma/rules",
    "sigma/rules-threat-hunting",
    "sigma/rules-emerging-threats",
    "sigma/rules-compliance",
    "sigma/other",
]

SKIP_PARTS = {"deprecated", "unsupported", "rules-placeholder", "tests", "regression_data"}

RISK_SCORES = {
    "informational": 1,
    "low": 21,
    "medium": 47,
    "high": 73,
    "critical": 99,
}

SEVERITIES = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def iter_sigma_files(roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        for path in Path(root).rglob("*.yml"):
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            files.append(path)
    return sorted(set(files))


def load_sigma_document(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        docs = [doc for doc in yaml.safe_load_all(handle) if doc]
    if not docs:
        raise ValueError(f"{path} is empty")
    return docs[0]


def choose_pipelines(logsource: dict[str, Any]) -> list[str]:
    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    category = (logsource.get("category") or "").lower()

    if product == "windows":
        return ["ecs_windows"]
    if product == "kubernetes":
        return ["ecs_kubernetes"]
    if product == "zeek" or service == "zeek":
        return ["ecs_zeek_beats"]
    if category == "dns" and product == "zeek":
        return ["ecs_zeek_beats"]
    return []


def choose_indices(logsource: dict[str, Any]) -> list[str]:
    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    category = (logsource.get("category") or "").lower()

    if product == "linux" and service == "auditd":
        return ["logs-linux.auditd-*"]
    if product == "linux" and category == "file_event":
        return ["custom-generic-*", "logs-*", "filebeat-*"]
    if product == "windows":
        return ["winlogbeat-*", "logs-windows.*", "logs-system.*"]
    if product == "kubernetes":
        return ["logs-kubernetes.*"]
    if product == "zeek" or service == "zeek":
        return ["filebeat-*", "logs-zeek.*"]
    if product in {"aws", "azure", "gcp"}:
        return [f"logs-{product}.*", "logs-*", "filebeat-*"]
    if category in {"process_creation", "network_connection", "dns_query", "file_event"}:
        return ["logs-*", "filebeat-*", "winlogbeat-*"]
    return ["logs-*", "filebeat-*", "winlogbeat-*"]


def sigma_rule_id(document: dict[str, Any], path: Path) -> str:
    identifier = str(document.get("id") or "").strip()
    if identifier:
        return f"sigma-{identifier}"
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()
    return f"sigma-{digest}"


def convert_sigma_query(path: Path, logsource: dict[str, Any]) -> str:
    command = ["sigma", "convert", "-t", "lucene"]
    pipelines = choose_pipelines(logsource)
    for pipeline in pipelines:
        command.extend(["-p", pipeline])
    if not pipelines:
        command.append("--without-pipeline")
    command.append(str(path))

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(stderr or "sigma conversion failed")

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError("sigma conversion returned an empty query")
    return " ".join(lines)


def sigma_payload(path: Path) -> dict[str, Any]:
    document = load_sigma_document(path)
    title = document.get("title") or path.stem
    description = document.get("description") or title
    author = document.get("author") or []
    references = document.get("references") or []
    logsource = document.get("logsource") or {}
    level = str(document.get("level") or "medium").lower()
    status = str(document.get("status") or "").lower()

    query = convert_sigma_query(path, logsource)
    tags = list(document.get("tags") or [])
    tags.append("Source: Sigma")
    if status:
        tags.append(f"Sigma Status: {status}")
    if logsource.get("product"):
        tags.append(f"Sigma Product: {logsource['product']}")
    if logsource.get("service"):
        tags.append(f"Sigma Service: {logsource['service']}")
    if logsource.get("category"):
        tags.append(f"Sigma Category: {logsource['category']}")

    if isinstance(author, str):
        author = [author]
    if isinstance(references, str):
        references = [references]

    return {
        "author": author,
        "description": description,
        "enabled": True,
        "from": "now-10m",
        "index": choose_indices(logsource),
        "interval": "5m",
        "language": "lucene",
        "name": f"Sigma - {title}",
        "query": query,
        "references": references,
        "risk_score": RISK_SCORES.get(level, 47),
        "rule_id": sigma_rule_id(document, path),
        "severity": SEVERITIES.get(level, "medium"),
        "tags": sorted(set(tags)),
        "type": "query",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Sigma YAML into Kibana detection rules")
    parser.add_argument("--sigma-root", action="append", default=[], help="Sigma content root to import")
    parser.add_argument("--max-rules", type=int, default=0, help="Only import the first N rules")
    args = parser.parse_args()

    wait_for_kibana()
    sigma_roots = args.sigma_root or SIGMA_ROOTS
    files = iter_sigma_files(sigma_roots)
    if args.max_rules:
        files = files[: args.max_rules]

    created = 0
    updated = 0
    failed = 0

    for index, path in enumerate(files, start=1):
        try:
            payload = sigma_payload(path)
            result = upsert_detection_rule(payload)
            if result == "created":
                created += 1
            else:
                updated += 1
            if index % 100 == 0:
                print(f"[sigma-rules] processed {index}/{len(files)}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[sigma-rules] failed {path}: {exc}", file=sys.stderr)

    print(f"[sigma-rules] done: created={created} updated={updated} failed={failed} total={len(files)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
