from __future__ import annotations

import subprocess
import sys

from common import (
    ensure_custom_generic_template,
    ensure_data_view,
    ensure_kibana_security_indices,
    ensure_linux_auditd_template,
    ensure_suricata_template,
    wait_for_elasticsearch,
    wait_for_kibana,
)


def run_step(command: list[str]) -> None:
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    wait_for_elasticsearch()
    wait_for_kibana()

    ensure_linux_auditd_template()
    ensure_suricata_template()
    ensure_custom_generic_template()
    ensure_kibana_security_indices()
    ensure_data_view("logs-linux.auditd-*", "Linux Auditd Logs")
    ensure_data_view("soc-suricata.eve-*", "Suricata EVE")
    ensure_data_view("custom-generic-*", "Custom Generic Logs")
    ensure_data_view("wazuh-alerts-*", "Wazuh Alerts")

    run_step([sys.executable, "scripts/import_elastic_rules.py"])
    run_step([sys.executable, "scripts/import_sigma_rules.py"])
    run_step([sys.executable, "scripts/catalog_rules.py"])
    run_step([sys.executable, "scripts/catalog_logs.py"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
