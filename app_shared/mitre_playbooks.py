from __future__ import annotations

import os
import re
from pathlib import Path


DEFAULT_PLAYBOOK_ROOT = Path(
    os.environ.get("SOAR_PLAYBOOK_ROOT", "vendor/MITRE-ATT_CK-Playbooks/Playbooks")
)


def normalize_mitre_id(technique_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", technique_id or "").upper()


def resolve_playbook_path(technique_id: str, playbook_root: Path | None = None) -> str:
    normalized = normalize_mitre_id(technique_id)
    if not normalized:
        return ""
    root = playbook_root or DEFAULT_PLAYBOOK_ROOT
    if not root.exists():
        return ""
    matches = sorted(root.rglob(f"{normalized}_*.md"))
    return str(matches[0]) if matches else ""


def load_playbook_excerpt(path: str, limit: int = 2400) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8")[:limit]
    except OSError:
        return ""
