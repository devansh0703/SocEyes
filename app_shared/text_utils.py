"""Shared text-processing and time helpers used by both the backend and
the orchestration scripts.

This module was consolidated from three previously duplicated locations:
``backend/app/services.py``, ``scripts/run_orchestration_engine.py`` and
``scripts/common.py`` each carried its own copy of ``clean_text`` /
``ANSI_ESCAPE_RE`` / ``now_utc`` — with subtle drift and no shared test
coverage.  Centralising them here gives every caller the same, tested
implementation.
"""
from __future__ import annotations

import ast
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_shared.state_paths import writable_path, write_json

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def clean_text(value: Any) -> str:
    """Strip ANSI escape codes and collapse whitespace."""
    if value is None:
        return ""
    text = ANSI_ESCAPE_RE.sub("", str(value)).strip()
    return re.sub(r"\s+", " ", text)


def deep_get(payload: dict[str, Any], path: list[str], default: Any = "") -> Any:
    """Safely traverse nested dicts without raising KeyError."""
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current not in {None, ""} else default


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def humanize_possible_structured_text(value: Any) -> str:
    """Best-effort humanisation of a blob that may be structured or plain text."""
    text = clean_text(value)
    if not text:
        return ""
    if not (text.startswith("{") and text.endswith("}")):
        return text
    parsed: Any = None
    try:
        parsed = json.loads(text)
    except Exception:
        try:
            parsed = ast.literal_eval(text)
        except Exception:
            return text
    if not isinstance(parsed, dict):
        return text
    command = clean_text(deep_get(parsed, ["response_command", "command"]))
    source_ip = clean_text(deep_get(parsed, ["detection_evidence", "source_ip"]))
    destination_ip = clean_text(deep_get(parsed, ["detection_evidence", "destination_ip"]))
    attack_vector = clean_text(deep_get(parsed, ["attack_mapping", "attack_vector"]))
    attack_path = clean_text(deep_get(parsed, ["attack_mapping", "attack_path"]))
    parts = ["Live evidence mapped to response command."]
    if source_ip or destination_ip:
        parts.append(f"src={source_ip or 'n/a'}, dst={destination_ip or 'n/a'}.")
    if attack_vector or attack_path:
        parts.append(f"attack={attack_vector or 'unknown'} / path={attack_path or 'unknown'}.")
    if command:
        parts.append(f"command={command}")
    return " ".join(parts)


def normalize_severity(value: Any) -> dict[str, Any]:
    """Map a raw severity string/number to {label, score, level}."""
    raw = clean_text(value)
    lowered = raw.lower()
    score = 0
    if re.fullmatch(r"\d+", lowered):
        score = max(0, min(100, int(lowered)))
    elif "critical" in lowered or "fatal" in lowered or "severe" in lowered:
        score = 95
    elif "high" in lowered:
        score = 80
    elif "medium" in lowered or "moderate" in lowered:
        score = 55
    elif "low" in lowered or "info" in lowered or "notice" in lowered:
        score = 25
    elif "warn" in lowered:
        score = 40
    elif "success" in lowered:
        score = 20
    else:
        score = 50 if lowered else 0
    if score >= 90:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "unknown"
    label = raw if raw else level
    return {"label": label, "score": score, "level": level}


def parse_markdown_sections(text: str) -> list[dict[str, Any]]:
    """Split a markdown string into structured sections."""
    sections: list[dict[str, Any]] = []
    current = {"title": "Overview", "paragraphs": [], "bullets": []}

    def push_current() -> None:
        if current["paragraphs"] or current["bullets"]:
            sections.append(
                {
                    "title": current["title"],
                    "slug": slugify(current["title"]),
                    "paragraphs": current["paragraphs"][:6],
                    "bullets": current["bullets"][:10],
                }
            )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("```"):
            continue
        if line.startswith("#"):
            push_current()
            current = {"title": clean_text(line.lstrip("# ")), "paragraphs": [], "bullets": []}
            continue
        if line.startswith(">"):
            line = clean_text(line.lstrip("> "))
        if line.startswith("|") and line.endswith("|"):
            cells = [clean_text(cell) for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-", ":"} for cell in cells):
                continue
            if len(cells) >= 2:
                if cells[0].lower() == "column name" and cells[1].lower() == "value":
                    continue
                current["bullets"].append(f"{cells[0]}: {cells[1]}")
                continue
        if line.startswith("- "):
            current["bullets"].append(clean_text(line[2:]))
            continue
        if re.match(r"^\d+\.\s+", line):
            current["bullets"].append(clean_text(re.sub(r"^\d+\.\s+", "", line)))
            continue
        current["paragraphs"].append(clean_text(line.replace("**", "").replace("`", "").replace("<br>", " ")))
    push_current()
    return sections[:8]


def extract_mitre_from_tags(tags: list[str]) -> list[str]:
    values: list[str] = []
    for tag in tags:
        lower = tag.lower()
        if lower.startswith("attack.t"):
            suffix = tag.split(".", 1)[1]
            values.append(f"T{suffix[1:].upper()}")
    return sorted(set(values))


def extract_rule_mitre(source: dict[str, Any]) -> list[str]:
    mitre_ids = []
    raw = source.get("raw") or {}
    for entry in raw.get("tags", []) or []:
        if isinstance(entry, str) and entry.lower().startswith("attack.t"):
            mitre_ids.append(f"T{entry.split('.', 1)[1][1:].upper()}")
    for threat in raw.get("threat") or []:
        for technique in threat.get("technique") or []:
            technique_id = technique.get("id")
            if technique_id:
                mitre_ids.append(str(technique_id))
            for subtechnique in technique.get("subtechnique") or []:
                subtechnique_id = subtechnique.get("id")
                if subtechnique_id:
                    mitre_ids.append(str(subtechnique_id))
    reports = raw.get("Reports") or {}
    for item in reports.get("MITRE ATT&CK") or []:
        if isinstance(item, str) and ":" in item:
            mitre_ids.append(item.split(":", 1)[1])
    mitre_ids.extend(source.get("mitre_ids") or [])
    return sorted(set(mitre_ids or extract_mitre_from_tags(source.get("tags") or [])))


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json(writable_path(path), payload)
