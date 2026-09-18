from __future__ import annotations

import hashlib
import json
from typing import Any

from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch


LOG_CATALOG_INDEX = "log-catalog"
SOURCE_PATTERNS = [
    "security-response-*",
    "logs-linux.auditd-*",
    "fda-suricata.eve-*",
    "custom-generic-*",
    "logs-generic-*",
    "fda-syslog-*",
    ".alerts-security.alerts-*",
    "wazuh-alerts-*",
    "wazuh-archives-*",
]
PAGE_SIZE = 2000


def stable_id(index: str, doc_id: str) -> str:
    digest = hashlib.sha1(f"{index}:{doc_id}".encode("utf-8")).hexdigest()
    return f"log-{digest}"


def ensure_index() -> None:
    session = elastic_session()
    payload = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "analysis": {
                "analyzer": {
                    "log_text_analyzer": {
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
                "catalog_id": {"type": "keyword"},
                "source_index": {"type": "keyword"},
                "source_id": {"type": "keyword"},
                "@timestamp": {"type": "date"},
                "message": {"type": "text", "analyzer": "log_text_analyzer"},
                "event_original": {"type": "text", "analyzer": "log_text_analyzer"},
                "process_name": {"type": "keyword"},
                "process_command_line": {"type": "text", "analyzer": "log_text_analyzer"},
                "rule_id": {"type": "keyword"},
                "rule_description": {"type": "text", "analyzer": "log_text_analyzer"},
                "decoder_name": {"type": "keyword"},
                "scenario_id": {"type": "keyword"},
                "run_id": {"type": "keyword"},
                "sensor_signature": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "destination_port": {"type": "integer"},
                "network_transport": {"type": "keyword"},
                "suricata_event_type": {"type": "keyword"},
                "url_path": {"type": "wildcard"},
                "http_user_agent": {"type": "text", "analyzer": "log_text_analyzer"},
                "tags": {"type": "keyword"},
                "search_text": {"type": "text", "analyzer": "log_text_analyzer"},
                "raw": {"type": "object", "enabled": False},
            }
        },
    }
    session.put(f"{ELASTICSEARCH_URL}/{LOG_CATALOG_INDEX}", json=payload, timeout=60)


def extract_message(source: dict[str, Any]) -> str:
    for key in ["message", "full_log"]:
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def extract_event_original(source: dict[str, Any]) -> str:
    event = source.get("event") or {}
    if isinstance(event, dict):
        value = event.get("original")
        if isinstance(value, str):
            return value
    return ""


def extract_rule(source: dict[str, Any]) -> tuple[str, str]:
    rule = source.get("rule") or {}
    if isinstance(rule, dict):
        return str(rule.get("id") or ""), str(rule.get("description") or "")
    return "", ""


def parse_json_string(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {}
    text = value.strip()
    if not text.startswith("{"):
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def make_doc(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    message = extract_message(source)
    event_original = extract_event_original(source)
    process = source.get("process") or {}
    process_name = str(process.get("name") or "")
    process_command_line = str(process.get("command_line") or "")
    rule_id, rule_description = extract_rule(source)
    decoder = source.get("decoder") or {}
    decoder_name = str(decoder.get("name") or "")
    embedded = parse_json_string(source.get("full_log"))
    if not embedded and event_original:
        alert_original = parse_json_string(event_original)
        embedded = parse_json_string(alert_original.get("full_log")) if alert_original else {}
    labels = source.get("labels") or embedded.get("labels") or {}
    sensor = source.get("sensor") or embedded.get("sensor") or {}
    url = source.get("url") or embedded.get("url") or {}
    http = source.get("http") or embedded.get("http") or {}
    tags = [hit.get("_index", "")]
    scenario_id = str(labels.get("scenario_id") or "")
    run_id = str(labels.get("run_id") or "")
    sensor_signature = str(sensor.get("signature") or "")
    url_path = str(url.get("path") or "")
    http_user_agent = str(http.get("user_agent") or "")
    source_ip = str((source.get("source") or {}).get("ip") or source.get("src_ip") or "")
    destination_ip = str((source.get("destination") or {}).get("ip") or source.get("dest_ip") or "")
    destination_port = (source.get("destination") or {}).get("port") or source.get("dest_port") or 0
    network_transport = str((source.get("network") or {}).get("transport") or source.get("proto") or "")
    suricata_event_type = str(source.get("event_type") or "")
    search_text = "\n".join(
        value
        for value in [
            message,
            event_original,
            process_name,
            process_command_line,
            rule_id,
            rule_description,
            decoder_name,
            scenario_id,
            run_id,
            sensor_signature,
            source_ip,
            destination_ip,
            str(destination_port),
            network_transport,
            suricata_event_type,
            url_path,
            http_user_agent,
        ]
        if value
    )
    return {
        "catalog_id": stable_id(hit["_index"], hit["_id"]),
        "source_index": hit["_index"],
        "source_id": hit["_id"],
        "@timestamp": source.get("@timestamp"),
        "message": message,
        "event_original": event_original,
        "process_name": process_name,
        "process_command_line": process_command_line,
        "rule_id": rule_id,
        "rule_description": rule_description,
        "decoder_name": decoder_name,
        "scenario_id": scenario_id,
        "run_id": run_id,
        "sensor_signature": sensor_signature,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": int(destination_port or 0),
        "network_transport": network_transport,
        "suricata_event_type": suricata_event_type,
        "url_path": url_path,
        "http_user_agent": http_user_agent,
        "tags": tags,
        "search_text": search_text,
        "raw": source,
    }


def iter_hits() -> list[dict[str, Any]]:
    session = elastic_session()
    results: list[dict[str, Any]] = []
    for pattern in SOURCE_PATTERNS:
        payload: dict[str, Any] = {
            "size": PAGE_SIZE,
            "sort": ["_doc"],
            "_source": True,
            "query": {"match_all": {}},
        }
        response = session.get(f"{ELASTICSEARCH_URL}/{pattern}/_search", json=payload, timeout=120)
        if response.status_code == 404:
            continue
        response.raise_for_status()
        results.extend(response.json().get("hits", {}).get("hits", []))
    return results


def bulk_index(docs: list[dict[str, Any]]) -> tuple[int, int]:
    if not docs:
        return 0, 0
    session = elastic_session()
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": LOG_CATALOG_INDEX, "_id": doc["catalog_id"]}}))
        lines.append(json.dumps(doc))
    response = session.post(
        f"{ELASTICSEARCH_URL}/_bulk",
        data="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120,
    )
    response.raise_for_status()
    body = response.json()
    ok = 0
    failed = 0
    for item in body.get("items", []):
        if item.get("index", {}).get("status", 500) < 300:
            ok += 1
        else:
            failed += 1
    return ok, failed


def main() -> int:
    wait_for_elasticsearch()
    ensure_index()
    hits = iter_hits()
    docs = [make_doc(hit) for hit in hits]
    ok, failed = bulk_index(docs)
    print(f"[log-catalog] indexed={ok} failed={failed} total={len(docs)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
