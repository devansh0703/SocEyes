from __future__ import annotations

import json
import time
from typing import Any

import requests

# Shared ES / Kibana client factory — single source of truth for auth,
# connection pooling and env-var configuration.  All three names below are
# re-exported so that ``from common import ...`` callers are unaffected.
from app_shared.es_client import (
    ELASTICSEARCH_URL,
    ELASTIC_PASSWORD,
    KIBANA_URL,
    get_kibana_client as kibana_session,
    get_es_client as elastic_session,
)


def wait_for_elasticsearch(timeout_seconds: int = 600) -> None:
    session = elastic_session()
    deadline = time.time() + timeout_seconds
    last_error = ""

    while time.time() < deadline:
        try:
            response = session.get(f"{ELASTICSEARCH_URL}/_cluster/health", timeout=15)
            if response.ok:
                health = response.json()
                if health.get("status") in {"yellow", "green"}:
                    return
                last_error = f"cluster status is {health.get('status')}"
            else:
                last_error = f"unexpected status {response.status_code}: {response.text}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(5)

    raise TimeoutError(f"Elasticsearch did not become healthy in time: {last_error}")


def wait_for_kibana(timeout_seconds: int = 600) -> None:
    session = kibana_session()
    deadline = time.time() + timeout_seconds
    last_error = ""

    while time.time() < deadline:
        try:
            response = session.get(f"{KIBANA_URL}/api/status", timeout=15)
            if response.ok:
                payload = response.json()
                if payload.get("status", {}).get("overall", {}).get("level") == "available":
                    return
                last_error = json.dumps(payload)
            else:
                last_error = f"unexpected status {response.status_code}: {response.text}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(5)

    raise TimeoutError(f"Kibana did not become available in time: {last_error}")


def ensure_linux_auditd_template() -> None:
    session = elastic_session()
    payload: dict[str, Any] = {
        "index_patterns": ["logs-linux.auditd-*"],
        "priority": 500,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "type": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "a0": {"type": "keyword"},
                    "a1": {"type": "keyword"},
                    "a2": {"type": "keyword"},
                    "a3": {"type": "keyword"},
                    "event": {
                        "properties": {
                            "action": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "dataset": {"type": "keyword"},
                            "module": {"type": "keyword"},
                            "type": {"type": "keyword"},
                        }
                    },
                    "file": {
                        "properties": {
                            "directory": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "path": {"type": "keyword"},
                        }
                    },
                    "host": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "os": {
                                "properties": {
                                    "type": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "process": {
                        "properties": {
                            "args": {"type": "keyword"},
                            "args_count": {"type": "integer"},
                            "command_line": {"type": "wildcard"},
                            "name": {"type": "keyword"},
                        }
                    },
                },
            },
        },
    }

    response = session.put(
        f"{ELASTICSEARCH_URL}/_index_template/logs-linux-auditd",
        json=payload,
        timeout=30,
    )
    response.raise_for_status()


def ensure_suricata_template() -> None:
    session = elastic_session()
    payload: dict[str, Any] = {
        "index_patterns": ["fda-suricata.eve-*"],
        "priority": 550,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message": {"type": "wildcard"},
                    "event_type": {"type": "keyword"},
                    "event": {
                        "properties": {
                            "action": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "dataset": {"type": "keyword"},
                            "kind": {"type": "keyword"},
                            "outcome": {"type": "keyword"},
                            "ingested": {"type": "date"},
                            "type": {"type": "keyword"},
                        }
                    },
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                        }
                    },
                    "destination": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                        }
                    },
                    "network": {
                        "properties": {
                            "protocol": {"type": "keyword"},
                            "transport": {"type": "keyword"},
                        }
                    },
                    "url": {
                        "properties": {
                            "path": {"type": "wildcard"},
                        }
                    },
                    "rule": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "description": {"type": "keyword"},
                        }
                    },
                },
            },
        },
    }

    response = session.put(
        f"{ELASTICSEARCH_URL}/_index_template/fda-suricata-eve",
        json=payload,
        timeout=30,
    )
    response.raise_for_status()


def ensure_custom_generic_template() -> None:
    session = elastic_session()
    payload: dict[str, Any] = {
        "index_patterns": ["custom-generic-*"],
        "priority": 520,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message": {"type": "wildcard"},
                    "event": {
                        "properties": {
                            "action": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "ingested": {"type": "date"},
                            "kind": {"type": "keyword"},
                            "outcome": {"type": "keyword"},
                            "type": {"type": "keyword"},
                        }
                    },
                    "host": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "os": {
                                "properties": {
                                    "type": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                        }
                    },
                    "destination": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                        }
                    },
                    "network": {
                        "properties": {
                            "protocol": {"type": "keyword"},
                            "transport": {"type": "keyword"},
                        }
                    },
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    },
                    "labels": {
                        "properties": {
                            "validation_rule_id": {"type": "keyword"},
                            "validation_rule_path": {"type": "keyword"},
                        }
                    },
                },
            },
        },
    }

    response = session.put(
        f"{ELASTICSEARCH_URL}/_index_template/custom-generic",
        json=payload,
        timeout=30,
    )
    response.raise_for_status()


def ensure_kibana_security_indices() -> None:
    session = kibana_session()
    security_indices = [
        "logs-*",
        "logs-linux.auditd-*",
        "fda-suricata.eve-*",
        "fda-syslog-*",
        "winlogbeat-*",
        "filebeat-*",
        "auditbeat-*",
        "wazuh-alerts-*",
        "wazuh-archives-*",
    ]
    threat_indices = [
        "filebeat-*",
        "logs-ti_*",
        "logs-threat*",
    ]

    payload = {
        "changes": {
            "securitySolution:defaultIndex": json.dumps(security_indices),
            "securitySolution:defaultThreatIndex": json.dumps(threat_indices),
        }
    }
    response = session.post(f"{KIBANA_URL}/api/kibana/settings", json=payload, timeout=30)
    # Kibana 9.x may reject this route depending on enabled settings plugins.
    # Detection imports and the rest of the pipeline can still function, so
    # treat this as best-effort instead of aborting bootstrap.
    if response.status_code not in {200, 204}:
        print(
            "warning: unable to update Kibana advanced security index settings: "
            f"{response.status_code} {response.text[:300]}",
            flush=True,
        )


def ensure_data_view(title: str, name: str) -> None:
    session = kibana_session()
    payload = {
        "data_view": {
            "title": title,
            "name": name,
            "timeFieldName": "@timestamp",
            "allowNoIndex": True,
        }
    }
    response = session.post(f"{KIBANA_URL}/api/data_views/data_view", json=payload, timeout=30)
    if response.status_code not in {200, 201} and "duplicate" not in response.text.lower():
        response.raise_for_status()


def upsert_detection_rule(payload: dict[str, Any]) -> str:
    session = kibana_session()
    rule_id = payload["rule_id"]

    existing = session.get(f"{KIBANA_URL}/api/detection_engine/rules", params={"rule_id": rule_id}, timeout=30)
    if existing.status_code == 200:
        response = session.put(f"{KIBANA_URL}/api/detection_engine/rules", json=payload, timeout=60)
        if response.status_code >= 400:
            raise RuntimeError(f"update failed for {rule_id}: {response.status_code} {response.text}")
        return "updated"

    if existing.status_code != 404:
        existing.raise_for_status()

    response = session.post(f"{KIBANA_URL}/api/detection_engine/rules", json=payload, timeout=60)
    if response.status_code >= 400:
        raise RuntimeError(f"create failed for {rule_id}: {response.status_code} {response.text}")
    return "created"
