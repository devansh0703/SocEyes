"""Rule corpus seeding: index Sigma, Elastic, Wazuh and Panther rule files.

Extracted from main.py. Called once at API startup; also safe to run
standalone to re-index corpora after a fetch (scripts/fetch_rule_corpora.sh).
"""
from __future__ import annotations

import logging
from pathlib import Path

from app_shared.unified_store import index_rule

logger = logging.getLogger("fda.services.seed_rules")


def _load_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def _load_tomllib():
    try:
        import tomllib
        return tomllib
    except ImportError:
        try:
            import tomli as tomllib
            return tomllib
        except ImportError:
            return None


def _seed_sigma(root: Path) -> int:
    yaml = _load_yaml()
    if not yaml:
        return 0
    sigma_dir = root / "sigma" / "rules"
    count = 0
    if sigma_dir.exists():
        for yml in sigma_dir.rglob("*.yml"):
            try:
                data = yaml.safe_load(yml.read_text())
                if isinstance(data, dict) and data.get("id"):
                    index_rule({
                        "rule_id": data["id"], "engine": "sigma",
                        "title": data.get("title", ""),
                        "description": data.get("description", ""),
                        "severity": data.get("level", "medium"),
                        "technique_ids": [], "mitre_ids": [],
                        "file_path": str(yml), "raw": data,
                    })
                    count += 1
            except Exception:
                pass
    return count


def _seed_panther(root: Path) -> int:
    """Panther rules use PascalCase keys (RuleID, Severity, Tags) — different
    schema from Sigma. Correlation rules without a RuleID key by file stem."""
    yaml = _load_yaml()
    if not yaml:
        return 0
    panther_root = root / "panther-analysis"
    count = 0
    if panther_root.exists():
        for sub in ("rules", "correlation_rules", "policies"):
            subdir = panther_root / sub
            if not subdir.exists():
                continue
            for yml in subdir.rglob("*.yml"):
                try:
                    data = yaml.safe_load(yml.read_text())
                    if not isinstance(data, dict):
                        continue
                    rule_id = data.get("RuleID") or data.get("PolicyID") or (data.get("AnalysisType") and yml.stem)
                    if not rule_id:
                        continue
                    tags = [str(t) for t in data.get("Tags", [])]
                    mitre_ids = sorted({
                        str(t).split(".")[0] for t in tags
                        if t.upper().startswith("T") and any(c.isdigit() for c in t[:6])
                    })
                    index_rule({
                        "rule_id": f"panther-{rule_id}", "engine": "panther",
                        "title": data.get("DisplayName") or str(rule_id),
                        "description": data.get("Description") or data.get("Summary") or "",
                        "severity": str(data.get("Severity") or "medium").lower(),
                        "technique_ids": mitre_ids, "mitre_ids": mitre_ids,
                        "file_path": str(yml), "raw": data,
                    })
                    count += 1
                except Exception:
                    pass
    return count


def _seed_elastic(root: Path) -> int:
    tomllib = _load_tomllib()
    if not tomllib:
        return 0
    det_dir = root / "detection-rules" / "rules"
    count = 0
    if det_dir.exists():
        for toml_file in det_dir.rglob("*.toml"):
            try:
                with open(toml_file, "rb") as f:
                    data = tomllib.load(f)
                rule = data.get("rule", {})
                rule_id = rule.get("rule_id") or rule.get("id")
                if rule_id:
                    technique_ids = []
                    for threat in rule.get("threat", []):
                        for tech in threat.get("technique", []):
                            if tech.get("id"):
                                technique_ids.append(tech["id"])
                    index_rule({
                        "rule_id": rule_id, "engine": "elastic",
                        "title": rule.get("name", ""),
                        "description": rule.get("description", ""),
                        "severity": rule.get("severity", "medium"),
                        "technique_ids": technique_ids, "mitre_ids": [],
                        "file_path": str(toml_file), "raw": data,
                    })
                    count += 1
            except Exception:
                pass
    return count


def seed_rules(root: Path) -> dict[str, int]:
    """Index all available detection corpora. Returns per-engine counts."""
    counts = {
        "sigma": _seed_sigma(root),
        "panther": _seed_panther(root),
        "elastic": _seed_elastic(root),
    }
    for engine, count in counts.items():
        if count:
            logger.info("Indexed %d %s rules", count, engine)
    return counts
