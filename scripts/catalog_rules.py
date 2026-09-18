from __future__ import annotations

import hashlib
import json
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

import yaml

from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch


RULE_CATALOG_INDEX = "rule-catalog"


def stable_id(prefix: str, raw: str) -> str:
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}"


def index_catalog() -> None:
    session = elastic_session()
    payload = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "analysis": {
                "analyzer": {
                    "rule_text_analyzer": {
                        "type": "standard",
                        "stopwords": "_none_",
                    }
                }
            },
            "similarity": {
                "default": {
                    "type": "BM25",
                    "b": 0.75,
                    "k1": 1.2,
                }
            },
        },
        "mappings": {
            "dynamic": False,
            "properties": {
                "rule_id": {"type": "keyword"},
                "catalog_id": {"type": "keyword"},
                "source": {"type": "keyword"},
                "engine": {"type": "keyword"},
                "title": {"type": "text", "analyzer": "rule_text_analyzer"},
                "description": {"type": "text", "analyzer": "rule_text_analyzer"},
                "query": {"type": "text", "analyzer": "rule_text_analyzer"},
                "path": {"type": "keyword"},
                "level": {"type": "keyword"},
                "type": {"type": "keyword"},
                "product": {"type": "keyword"},
                "service": {"type": "keyword"},
                "category": {"type": "keyword"},
                "indices": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "references": {"type": "keyword"},
                "mitre_ids": {"type": "keyword"},
                "search_text": {"type": "text", "analyzer": "rule_text_analyzer"},
                "raw": {"type": "object", "enabled": False},
            }
        },
    }
    session.put(f"{ELASTICSEARCH_URL}/{RULE_CATALOG_INDEX}", json=payload, timeout=60)


def make_doc(
    *,
    catalog_id: str,
    rule_id: str,
    source: str,
    engine: str,
    title: str,
    description: str,
    query: str,
    path: str,
    level: str = "",
    rule_type: str = "",
    product: str = "",
    service: str = "",
    category: str = "",
    indices: list[str] | None = None,
    tags: list[str] | None = None,
    references: list[str] | None = None,
    mitre_ids: list[str] | None = None,
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tags = tags or []
    references = references or []
    indices = indices or []
    mitre_ids = mitre_ids or []
    search_text = "\n".join(
        part
        for part in [
            title,
            description,
            query,
            " ".join(tags),
            " ".join(mitre_ids),
            product,
            service,
            category,
        ]
        if part
    )
    return {
        "catalog_id": catalog_id,
        "rule_id": rule_id,
        "source": source,
        "engine": engine,
        "title": title,
        "description": description,
        "query": query,
        "path": path,
        "level": level,
        "type": rule_type,
        "product": product,
        "service": service,
        "category": category,
        "indices": indices,
        "tags": tags,
        "references": references,
        "mitre_ids": mitre_ids,
        "search_text": search_text,
        "raw": raw or {},
    }


def tags_to_mitre_ids(tags: Iterable[str]) -> list[str]:
    values: list[str] = []
    for tag in tags:
        lowered = str(tag).lower()
        if lowered.startswith("attack.t"):
            suffix = str(tag).split(".", 1)[1]
            values.append(f"T{suffix[1:].upper()}")
    return sorted(set(values))


def elastic_threat_mitre_ids(threats: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for threat in threats:
        for technique in threat.get("technique", []) or []:
            technique_id = technique.get("id")
            if technique_id:
                values.append(str(technique_id))
            for subtechnique in technique.get("subtechnique", []) or []:
                subtechnique_id = subtechnique.get("id")
                if subtechnique_id:
                    values.append(str(subtechnique_id))
    return sorted(set(values))


def panther_mitre_ids(document: dict[str, Any]) -> list[str]:
    values: list[str] = []
    reports = document.get("Reports") or {}
    for item in reports.get("MITRE ATT&CK", []) or []:
        if isinstance(item, str) and ":" in item:
            values.append(item.split(":", 1)[1])
    return sorted(set(values))


def iter_elastic_docs() -> Iterable[dict[str, Any]]:
    for root in [Path("detection-rules/rules"), Path("detection-rules/rules_building_block")]:
        for path in sorted(root.rglob("*.toml")):
            with path.open("rb") as handle:
                document = tomllib.load(handle)
            rule = document.get("rule")
            if not rule:
                continue
            yield make_doc(
                catalog_id=stable_id("elastic", str(path)),
                rule_id=str(rule.get("rule_id") or stable_id("elastic-rule", str(path))),
                source="elastic",
                engine="elastic",
                title=str(rule.get("name") or path.stem),
                description=str(rule.get("description") or ""),
                query=str(rule.get("query") or ""),
                path=str(path),
                level=str(rule.get("severity") or ""),
                rule_type=str(rule.get("type") or ""),
                indices=[str(item) for item in rule.get("index", [])],
                tags=[str(item) for item in rule.get("tags", [])],
                references=[str(item) for item in rule.get("references", [])],
                mitre_ids=sorted(
                    set(
                        tags_to_mitre_ids([str(item) for item in rule.get("tags", [])])
                        + elastic_threat_mitre_ids(rule.get("threat", []) or [])
                    )
                ),
                raw=rule,
            )


def iter_sigma_docs() -> Iterable[dict[str, Any]]:
    roots = [
        Path("sigma/rules"),
        Path("sigma/rules-threat-hunting"),
        Path("sigma/rules-emerging-threats"),
        Path("sigma/rules-compliance"),
        Path("sigma/other"),
    ]
    skip_parts = {"deprecated", "unsupported", "rules-placeholder", "tests", "regression_data"}
    for root in roots:
        for path in sorted(root.rglob("*.yml")):
            if any(part in skip_parts for part in path.parts):
                continue
            with path.open("r", encoding="utf-8") as handle:
                docs = [doc for doc in yaml.safe_load_all(handle) if doc]
            if not docs:
                continue
            document = docs[0]
            logsource = document.get("logsource") or {}
            sigma_id = str(document.get("id") or stable_id("sigma", str(path)))
            yield make_doc(
                catalog_id=stable_id("sigma", str(path)),
                rule_id=sigma_id,
                source="sigma",
                engine="sigma",
                title=str(document.get("title") or path.stem),
                description=str(document.get("description") or ""),
                query=json.dumps(document.get("detection") or {}, sort_keys=True),
                path=str(path),
                level=str(document.get("level") or ""),
                product=str(logsource.get("product") or ""),
                service=str(logsource.get("service") or ""),
                category=str(logsource.get("category") or ""),
                tags=[str(item) for item in document.get("tags", [])],
                references=[str(item) for item in document.get("references", [])],
                mitre_ids=tags_to_mitre_ids([str(item) for item in document.get("tags", [])]),
                raw=document,
            )


def iter_panther_docs() -> Iterable[dict[str, Any]]:
    roots = [
        Path("panther-analysis/rules"),
        Path("panther-analysis/queries"),
        Path("panther-analysis/correlation_rules"),
        Path("panther-analysis/policies"),
    ]
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yml")):
            with path.open("r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle) or {}
            title = str(document.get("DisplayName") or document.get("RuleID") or path.stem)
            description = str(document.get("Description") or document.get("Summary") or "")
            rule_id = str(document.get("RuleID") or stable_id("panther", str(path)))
            log_types = [str(item) for item in document.get("LogTypes", [])]
            yield make_doc(
                catalog_id=stable_id("panther", str(path)),
                rule_id=rule_id,
                source="panther",
                engine="panther",
                title=title,
                description=description,
                query=json.dumps(document, sort_keys=True),
                path=str(path),
                level=str(document.get("Severity") or ""),
                rule_type=str(document.get("AnalysisType") or ""),
                product="panther",
                service=",".join(log_types),
                tags=[str(item) for item in document.get("Tags", [])],
                references=[str(item) for item in document.get("References", [])],
                mitre_ids=sorted(
                    set(
                        tags_to_mitre_ids([str(item) for item in document.get("Tags", [])]) + panther_mitre_ids(document)
                    )
                ),
                raw=document,
            )


def iter_wazuh_docs() -> Iterable[dict[str, Any]]:
    for path in [
        Path("config/wazuh/manager/rules/local_rules.xml"),
        Path("config/wazuh/manager/decoders/local_decoder.xml"),
    ]:
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            root = ET.fromstring(f"<root>{content}</root>")
        for rule in root.findall(".//rule"):
            description = "".join(rule.findtext("description", default="")).strip()
            groups = [group.text.strip() for group in rule.findall("group") if group.text]
            fields = []
            for field in rule.findall("field"):
                name = field.attrib.get("name", "")
                value = (field.text or "").strip()
                fields.append(f"{name}:{value}")
            rule_id = rule.attrib.get("id") or stable_id("wazuh", f"{path}:{description}")
            yield make_doc(
                catalog_id=stable_id("wazuh", f"{path}:{rule_id}"),
                rule_id=str(rule_id),
                source="wazuh",
                engine="wazuh",
                title=description or f"Wazuh rule {rule_id}",
                description=description,
                query=" ".join(fields),
                path=str(path),
                level=rule.attrib.get("level", ""),
                rule_type="xml",
                tags=groups,
                mitre_ids=[item.text.strip() for item in rule.findall(".//mitre/id") if item.text and item.text.strip()],
                raw={
                    "rule": rule.attrib,
                    "fields": fields,
                },
            )


def bulk_index(docs: Iterable[dict[str, Any]]) -> tuple[int, int]:
    session = elastic_session()
    ok = 0
    failed = 0
    lines: list[str] = []

    for doc in docs:
        lines.append(json.dumps({"index": {"_index": RULE_CATALOG_INDEX, "_id": doc["catalog_id"]}}))
        lines.append(json.dumps(doc, default=str))
        if len(lines) >= 1000:
            batch_ok, batch_failed = flush_bulk(session, lines)
            ok += batch_ok
            failed += batch_failed
            lines = []

    if lines:
        batch_ok, batch_failed = flush_bulk(session, lines)
        ok += batch_ok
        failed += batch_failed

    session.post(f"{ELASTICSEARCH_URL}/{RULE_CATALOG_INDEX}/_refresh", timeout=30)
    return ok, failed


def flush_bulk(session, lines: list[str]) -> tuple[int, int]:
    payload = "\n".join(lines) + "\n"
    response = session.post(
        f"{ELASTICSEARCH_URL}/_bulk",
        data=payload,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120,
    )
    response.raise_for_status()
    body = response.json()
    ok = 0
    failed = 0
    for item in body.get("items", []):
        if 200 <= item["index"]["status"] < 300:
            ok += 1
        else:
            failed += 1
    return ok, failed


def main() -> int:
    wait_for_elasticsearch()
    index_catalog()
    docs = list(iter_elastic_docs()) + list(iter_sigma_docs()) + list(iter_panther_docs()) + list(iter_wazuh_docs())
    ok, failed = bulk_index(docs)
    print(f"[rule-catalog] indexed={ok} failed={failed} total={len(docs)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
