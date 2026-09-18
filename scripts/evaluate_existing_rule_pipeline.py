from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.state_paths import state_path
from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch, wait_for_kibana


REPORT_FILE = state_path("orchestration", "existing_rule_validation.json")
LATENCY_FILE = state_path("orchestration", "existing_rule_latency.jsonl")

SIGMA_RULES = {
    "sigma_system_info": "sigma-f34047d9-20d3-4e8b-8672-0a35cc50dc71",
    "sigma_password_policy": "sigma-ca94a6db-8106-4737-9ed2-3e3bb826af0a",
    "sigma_file_event_sudoers": "sigma-ddb26b76-4447-4807-871f-1b035b2bfa5d",
}

ELASTIC_RULES = {
    "elastic_external_ssh_bruteforce": "fa210b61-b627-4e5e-86f4-17e8270656ab",
    "suricata_network_sweep": "781f8746-2180-4691-890c-4c96d11ca91d",
}

WAZUH_RULES = {
    "sigma_system_info": "100500",
    "sigma_password_policy": "100501",
    "wazuh_failed_ssh": "100511",
    "suricata_network_sweep": "100622",
}


def run_step(command: list[str]) -> None:
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def emit(name: str) -> datetime:
    started = datetime.now(timezone.utc)
    run_step([sys.executable, "scripts/manual_rules/emit_existing_rule_signals.py", name])
    return started


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def query_rule_hits(
    index: str,
    field: str,
    value: str,
    started: datetime | None = None,
    extra_filters: list[dict] | None = None,
) -> list[dict]:
    filters: list[dict] = [{"term": {field: value}}]
    if started:
        filters.append({"range": {"@timestamp": {"gte": iso(started)}}})
    filters.extend(extra_filters or [])
    response = elastic_session().get(
        f"{ELASTICSEARCH_URL}/{index}/_search",
        json={
            "size": 20,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        },
        timeout=30,
    )
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def wait_for_hit(index: str, field: str, value: str, started: datetime, timeout_seconds: int = 180) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        hits = query_rule_hits(index, field, value, started)
        if hits:
            source = hits[0].get("_source") or {}
            timestamp = source.get("@timestamp") or iso(started)
            detected = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            latency = (detected - started).total_seconds()
            record = {
                "index": index,
                "field": field,
                "value": value,
                "detected_at": timestamp,
                "latency_seconds": round(latency, 3),
            }
            LATENCY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LATENCY_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record))
                handle.write("\n")
            return record
        time.sleep(3)
    return {"index": index, "field": field, "value": value, "detected_at": "", "latency_seconds": None}


def control_result(name: str, index: str, field: str, value: str, started: datetime, extra_filters: list[dict]) -> dict:
    hits = query_rule_hits(index, field, value, started, extra_filters)
    latest = hits[0].get("_source", {}) if hits else {}
    return {
        "name": name,
        "index": index,
        "field": field,
        "value": value,
        "matched": bool(hits),
        "hit_count": len(hits),
        "latest_at": latest.get("@timestamp", ""),
        "latest_message": latest.get("message") or latest.get("kibana.alert.reason") or "",
    }


def main() -> int:
    wait_for_elasticsearch()
    wait_for_kibana()
    run_step([sys.executable, "scripts/manual_rules/prime_existing_rule_validators.py"])

    malicious = {
        "sigma_system_info": emit("sigma_system_info"),
        "sigma_password_policy": emit("sigma_password_policy"),
        "sigma_file_event_sudoers": emit("sigma_file_event_sudoers"),
        "elastic_external_ssh_bruteforce": emit("elastic_external_ssh_bruteforce"),
        "wazuh_failed_ssh": emit("wazuh_failed_ssh"),
        "suricata_network_sweep": emit("suricata_network_sweep"),
    }
    benign = {
        "benign_auth": emit("benign_auth"),
        "benign_file_event": emit("benign_file_event"),
        "benign_suricata": emit("benign_suricata"),
    }

    results: dict[str, dict] = {"sigma": {}, "elastic": {}, "wazuh": {}, "controls": {}, "metrics": {}}

    for scenario, rule_id in SIGMA_RULES.items():
        results["sigma"][scenario] = wait_for_hit(".alerts-security.alerts-*", "kibana.alert.rule.rule_id", rule_id, malicious[scenario])

    for scenario, rule_id in ELASTIC_RULES.items():
        results["elastic"][scenario] = wait_for_hit(".alerts-security.alerts-*", "kibana.alert.rule.rule_id", rule_id, malicious[scenario])

    for scenario, rule_id in WAZUH_RULES.items():
        if scenario not in malicious:
            continue
        results["wazuh"][scenario] = wait_for_hit("wazuh-alerts-*", "rule.id", rule_id, malicious[scenario])

    time.sleep(10)
    controls = {
        "elastic_ssh_on_benign_auth": control_result(
            "elastic_ssh_on_benign_auth",
            ".alerts-security.alerts-*",
            "kibana.alert.rule.rule_id",
            ELASTIC_RULES["elastic_external_ssh_bruteforce"],
            benign["benign_auth"],
            [{"match_phrase": {"message": "Successful ssh login for ops-admin"}}],
        ),
        "sigma_sudoers_on_benign_file": control_result(
            "sigma_sudoers_on_benign_file",
            ".alerts-security.alerts-*",
            "kibana.alert.rule.rule_id",
            SIGMA_RULES["sigma_file_event_sudoers"],
            benign["benign_file_event"],
            [{"match_phrase": {"message": "Benign file creation in tmp"}}],
        ),
        "elastic_network_sweep_on_benign_suricata": control_result(
            "elastic_network_sweep_on_benign_suricata",
            ".alerts-security.alerts-*",
            "kibana.alert.rule.rule_id",
            ELASTIC_RULES["suricata_network_sweep"],
            benign["benign_suricata"],
            [{"term": {"source.ip": "10.10.10.20"}}],
        ),
        "wazuh_failed_ssh_on_benign_auth": control_result(
            "wazuh_failed_ssh_on_benign_auth",
            "wazuh-alerts-*",
            "rule.id",
            WAZUH_RULES["wazuh_failed_ssh"],
            benign["benign_auth"],
            [{"match_phrase": {"full_log": "Accepted password for ops-admin"}}],
        ),
    }
    tp = sum(1 for engine in ["sigma", "elastic", "wazuh"] for item in results[engine].values() if item["detected_at"])
    fn = sum(1 for engine in ["sigma", "elastic", "wazuh"] for item in results[engine].values() if not item["detected_at"])
    fp = sum(1 for item in controls.values() if item["matched"])
    tn = sum(1 for item in controls.values() if not item["matched"])
    results["controls"] = controls
    results["metrics"] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn}

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0 if fn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
