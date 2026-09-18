from __future__ import annotations

import argparse
import json
from typing import Any

from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch


ALERT_INDEX = ".alerts-security.alerts-*"
LOG_CATALOG_INDEX = "log-catalog"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find logs or alerts associated with a rule")
    parser.add_argument("--rule-id", required=True, help="Rule ID from Elastic, Sigma, Panther, or Wazuh catalog")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of logs/alerts to return")
    return parser.parse_args()


def find_rule(rule_id: str) -> dict[str, Any]:
    session = elastic_session()
    candidate_ids = [rule_id]
    if rule_id.startswith("sigma-"):
        candidate_ids.append(rule_id.removeprefix("sigma-"))

    hits: list[dict[str, Any]] = []
    for candidate in candidate_ids:
        payload = {
            "size": 1,
            "query": {
                "term": {
                    "rule_id": candidate,
                }
            },
        }
        response = session.get(f"{ELASTICSEARCH_URL}/rule-catalog/_search", json=payload, timeout=30)
        response.raise_for_status()
        hits = response.json()["hits"]["hits"]
        if hits:
            break
    if not hits:
        raise SystemExit(f"Rule {rule_id} not found in rule-catalog")
    return hits[0]["_source"]


def query_alerts(rule: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    session = elastic_session()
    payload = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"term": {"kibana.alert.rule.rule_id": rule["rule_id"]}},
                    {"term": {"signal.rule.rule_id": rule["rule_id"]}},
                    {"term": {"rule.id": rule["rule_id"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    response = session.get(f"{ELASTICSEARCH_URL}/{ALERT_INDEX}/_search", json=payload, timeout=60)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def query_wazuh(rule: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    session = elastic_session()
    payload = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"term": {"rule.id": rule["rule_id"]}},
                    {"term": {"rule.description.keyword": rule["title"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    response = session.get(f"{ELASTICSEARCH_URL}/wazuh-alerts-*/_search", json=payload, timeout=60)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def query_direct_logs(rule: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    session = elastic_session()
    indices = rule.get("indices") or ["logs-*"]
    query = rule.get("query") or ""
    rule_type = rule.get("type") or ""

    if not query:
        return []

    if rule["engine"] == "wazuh":
        return query_wazuh(rule, limit)

    if rule_type in {"query", "threshold", "new_terms", "threat_match", "exists", "phrase", "mapping"}:
        payload = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "query_string": {
                    "query": query,
                    "default_operator": "AND",
                    "lenient": True,
                }
            },
        }
        response = session.get(f"{ELASTICSEARCH_URL}/{','.join(indices)}/_search", json=payload, timeout=60)
        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])

    if rule_type == "eql":
        payload = {
            "query": query,
            "size": limit,
        }
        response = session.post(f"{ELASTICSEARCH_URL}/{','.join(indices)}/_eql/search", json=payload, timeout=60)
        if response.status_code >= 400:
            return []
        body = response.json()
        return body.get("events", []) or body.get("hits", {}).get("events", [])

    if rule_type == "esql":
        payload = {"query": query}
        response = session.post(f"{ELASTICSEARCH_URL}/_query", json=payload, timeout=60)
        if response.status_code >= 400:
            return []
        return response.json().get("values", [])[:limit]

    return []


def query_bm25_logs(rule: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    session = elastic_session()
    query_text = "\n".join(
        value
        for value in [
            str(rule.get("title") or ""),
            str(rule.get("description") or ""),
            str(rule.get("query") or ""),
            " ".join(rule.get("tags") or []),
            str(rule.get("product") or ""),
            str(rule.get("service") or ""),
            str(rule.get("category") or ""),
        ]
        if value
    )
    if not query_text.strip():
        return []

    payload = {
        "size": limit,
        "_source": [
            "source_index",
            "source_id",
            "@timestamp",
            "message",
            "event_original",
            "process_name",
            "process_command_line",
            "rule_id",
            "rule_description",
        ],
        "query": {
            "multi_match": {
                "query": query_text,
                "type": "best_fields",
                "fields": [
                    "message^4",
                    "event_original^3",
                    "process_name^5",
                    "process_command_line^4",
                    "rule_description^2",
                    "search_text^6",
                ],
            }
        },
    }
    response = session.get(f"{ELASTICSEARCH_URL}/{LOG_CATALOG_INDEX}/_search", json=payload, timeout=60)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def main() -> int:
    args = parse_args()
    wait_for_elasticsearch()
    rule = find_rule(args.rule_id)
    alerts = query_alerts(rule, args.limit)
    direct_hits = query_direct_logs(rule, args.limit) if not alerts else []
    bm25_hits = query_bm25_logs(rule, args.limit)
    print(
        json.dumps(
            {
                "rule": rule,
                "alert_hits": alerts,
                "direct_log_hits": direct_hits,
                "bm25_log_hits": bm25_hits,
            },
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
