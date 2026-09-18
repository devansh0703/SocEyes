from __future__ import annotations

import argparse

from _common import emitters


def emit_attack_set() -> None:
    emitters.emit_sigma_system_info()
    emitters.emit_sigma_password_policy()
    emitters.emit_sigma_file_event_sudoers()
    emitters.emit_elastic_network_sweep()
    emitters.emit_elastic_external_ssh_bruteforce()
    emitters.emit_wazuh_failed_ssh()
    emitters.emit_suricata_network_sweep_pcap()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a broad attack telemetry set across auditd, JSON, syslog, and Suricata PCAP sources"
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=1,
        help="How many full attack sets to emit (minimum 1)",
    )
    args = parser.parse_args()

    rounds = max(1, args.rounds)
    for idx in range(rounds):
        emit_attack_set()
        print(f"Completed attack telemetry round {idx + 1}/{rounds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
