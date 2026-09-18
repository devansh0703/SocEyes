from __future__ import annotations

import json
import time
from pathlib import Path

from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch


def write_test_log() -> None:
    now = int(time.time())
    payload = (
        f'type=EXECVE msg=audit({now}.123:{now % 100000 + 1}): argc=1 a0="uname"\n'
        f'type=EXECVE msg=audit({now + 1}.123:{(now + 1) % 100000 + 1}): argc=2 a0="passwd" a1="-S"\n'
    )
    with Path("ingest/auditd/audit.log").open("a", encoding="utf-8") as handle:
        handle.write(payload)


def wait_for_index(index_pattern: str, query: dict, timeout_seconds: int = 180) -> dict:
    session = elastic_session()
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        response = session.get(
            f"{ELASTICSEARCH_URL}/{index_pattern}/_search",
            json={"size": 20, "query": query},
            timeout=30,
        )
        if response.status_code in {200, 201}:
            body = response.json()
            if body.get("hits", {}).get("total", {}).get("value", 0) > 0:
                return body
        time.sleep(5)
    raise TimeoutError(f"No hits found in {index_pattern} for query {query}")


def main() -> int:
    wait_for_elasticsearch()
    write_test_log()

    audit_hits = wait_for_index(
        "logs-linux.auditd-*",
        {"bool": {"should": [{"term": {"process.name": "uname"}}, {"term": {"process.name": "passwd"}}], "minimum_should_match": 1}},
    )

    result = {
        "logs_linux_auditd_hits": audit_hits["hits"]["hits"],
    }

    try:
        wazuh_hits = wait_for_index(
            "wazuh-alerts-*",
            {"terms": {"rule.id": ["100500", "100501"]}},
            timeout_seconds=180,
        )
        result["wazuh_alert_hits"] = wazuh_hits["hits"]["hits"]
    except TimeoutError as exc:
        result["wazuh_alert_hits"] = []
        result["wazuh_note"] = str(exc)

    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
