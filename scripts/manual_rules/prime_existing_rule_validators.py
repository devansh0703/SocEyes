from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from scripts.common import wait_for_kibana, upsert_detection_rule
from scripts.import_elastic_rules import normalize_rule_payload
from scripts.import_sigma_rules import load_sigma_document, sigma_payload

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


SIGMA_RULES = [
    Path("sigma/rules/linux/auditd/lnx_auditd_system_info_discovery.yml"),
    Path("sigma/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml"),
    Path("sigma/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml"),
]

ELASTIC_RULES = [
    Path("detection-rules/rules/network/discovery_potential_network_sweep_detected.toml"),
    Path("detection-rules/rules/linux/credential_access_potential_linux_ssh_bruteforce_external.toml"),
]


def prime_sigma(path: Path) -> None:
    payload = sigma_payload(path)
    payload["interval"] = "1m"
    payload["from"] = "now-2m"
    document = load_sigma_document(path)
    logsource = document.get("logsource") or {}
    if (logsource.get("category") or "").lower() == "file_event":
        payload["index"] = ["custom-generic-*"]
    upsert_detection_rule(payload)
    print(f"Primed Sigma rule {document.get('id')} from {path}")


def prime_elastic(path: Path) -> None:
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    payload = normalize_rule_payload(document["rule"], enable_rules=True)
    payload["interval"] = "1m"
    payload["from"] = "now-2m"
    if path.name == "discovery_potential_network_sweep_detected.toml":
        payload["index"] = ["soc-suricata.eve-*"]
    else:
        payload["index"] = ["custom-generic-*"]
    upsert_detection_rule(payload)
    print(f"Primed Elastic rule {payload['rule_id']} from {path}")


def main() -> int:
    wait_for_kibana()
    for path in SIGMA_RULES:
        prime_sigma(path)
    for path in ELASTIC_RULES:
        prime_elastic(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
