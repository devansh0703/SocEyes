from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


AUDIT_LOG = Path("ingest/auditd/audit.log")
JSON_LOG = Path("ingest/json/events.jsonl")
SYSLOG_LOG = Path("ingest/syslog/soc.log")
PCAP_DIR = Path("ingest/pcap")


def _scapy():
    """Lazy import scapy — only needed for PCAP generation."""
    try:
        from scapy.all import IP, TCP, wrpcap
        return IP, TCP, wrpcap
    except ImportError:
        return None, None, None


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def append_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line)
            handle.write("\n")


def emit_sigma_system_info() -> None:
    epoch = int(datetime.now(timezone.utc).timestamp())
    line = f'type=EXECVE msg=audit({epoch}.123:66836): argc=1 a0="uname"'
    append_lines(AUDIT_LOG, [line])
    print("Emitted auditd signal for sigma/rules/linux/auditd/lnx_auditd_system_info_discovery.yml")


def emit_sigma_password_policy() -> None:
    epoch = int(datetime.now(timezone.utc).timestamp())
    line = f'type=EXECVE msg=audit({epoch}.456:66837): argc=2 a0="chage" a1="--list"'
    append_lines(AUDIT_LOG, [line])
    print("Emitted auditd signal for sigma/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml")


def emit_elastic_network_sweep() -> None:
    events = []
    for offset in range(110):
        event_time = (datetime.now(timezone.utc) + timedelta(milliseconds=offset * 150)).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "@timestamp": event_time,
                "event": {
                    "action": "network_flow",
                    "category": ["network"],
                    "kind": "event",
                    "type": ["connection"],
                    "ingested": event_time,
                },
                "host": {"name": "sensor-01"},
                "source": {"ip": "10.10.10.50"},
                "destination": {"ip": f"10.10.20.{offset + 1}", "port": 22},
                "network": {"transport": "tcp", "protocol": "ssh"},
                "message": f"Manual existing-rule validation event for destination 10.10.20.{offset + 1}:22",
                "labels": {
                    "validation_rule_id": "781f8746-2180-4691-890c-4c96d11ca91d",
                    "validation_rule_path": "detection-rules/rules/network/discovery_potential_network_sweep_detected.toml",
                },
            }
        )
    append_lines(JSON_LOG, [json.dumps(event, sort_keys=True) for event in events])
    print("Emitted JSON network flow signals for detection-rules/rules/network/discovery_potential_network_sweep_detected.toml")


def emit_elastic_external_ssh_bruteforce() -> None:
    events = []
    base = datetime.now(timezone.utc)
    for offset in range(60):
        event_time = (base + timedelta(milliseconds=offset * 450)).isoformat().replace("+00:00", "Z")
        events.append(
            {
                "@timestamp": event_time,
                "event": {
                    "action": "ssh_login",
                    "category": ["authentication"],
                    "kind": "event",
                    "type": ["start"],
                    "outcome": "failure",
                    "ingested": event_time,
                },
                "host": {"id": "linux-host-01", "name": "linux-host-01", "os": {"type": "linux"}},
                "source": {"ip": "8.8.8.8"},
                "user": {"name": "devansh"},
                "message": "Failed ssh login for devansh from 8.8.8.8",
                "labels": {
                    "validation_rule_id": "fa210b61-b627-4e5e-86f4-17e8270656ab",
                    "validation_rule_path": "detection-rules/rules/linux/credential_access_potential_linux_ssh_bruteforce_external.toml",
                },
            }
        )
    append_lines(JSON_LOG, [json.dumps(event, sort_keys=True) for event in events])
    print("Emitted JSON auth signals for detection-rules/rules/linux/credential_access_potential_linux_ssh_bruteforce_external.toml")


def emit_sigma_file_event_sudoers() -> None:
    event_time = iso_now()
    event = {
        "@timestamp": event_time,
        "event": {
            "category": ["file"],
            "kind": "event",
            "type": ["change"],
            "ingested": event_time,
        },
        "host": {"name": "linux-host-01", "os": {"type": "linux"}},
        "TargetFilename": "/etc/sudoers.d/devansh",
        "file": {"path": "/etc/sudoers.d/devansh"},
        "message": "Sudoers drop-in file created for persistence",
        "labels": {
            "validation_rule_id": "ddb26b76-4447-4807-871f-1b035b2bfa5d",
            "validation_rule_path": "sigma/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml",
        },
    }
    append_lines(JSON_LOG, [json.dumps(event, sort_keys=True)])
    print("Emitted JSON file event for sigma/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml")


def emit_wazuh_failed_ssh() -> None:
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    line = f'{stamp} lab sshd[4242]: Failed password for devansh from 8.8.8.8 port 42222 ssh2'
    append_lines(SYSLOG_LOG, [line])
    print("Emitted syslog failed SSH event for Wazuh SSH detection")


def emit_suricata_network_sweep_pcap() -> None:
    IP, TCP, wrpcap = _scapy()
    if IP is None:
        print("scapy not available — skipping PCAP generation for network sweep")
        return
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    packets = []
    for offset in range(110):
        dst = f"10.10.20.{offset + 1}"
        packets.append(IP(src="10.10.10.50", dst=dst) / TCP(sport=40000 + offset, dport=22, flags="S"))
    path = PCAP_DIR / f"network-sweep-{int(datetime.now(timezone.utc).timestamp())}.pcap"
    wrpcap(str(path), packets)
    print("Emitted Suricata PCAP for detection-rules/rules/network/discovery_potential_network_sweep_detected.toml")


def emit_benign_auth() -> None:
    event_time = iso_now()
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    event = {
        "@timestamp": event_time,
        "event": {
            "action": "ssh_login",
            "category": ["authentication"],
            "kind": "event",
            "type": ["start"],
            "outcome": "success",
            "ingested": event_time,
        },
        "host": {"id": "linux-host-01", "name": "linux-host-01", "os": {"type": "linux"}},
        "source": {"ip": "10.0.0.4"},
        "user": {"name": "ops-admin"},
        "message": "Successful ssh login for ops-admin from 10.0.0.4",
    }
    append_lines(JSON_LOG, [json.dumps(event, sort_keys=True)])
    append_lines(SYSLOG_LOG, [f"{stamp} lab sshd[4243]: Accepted password for ops-admin from 10.0.0.4 port 42223 ssh2"])
    print("Emitted benign auth control event")


def emit_benign_file_event() -> None:
    event_time = iso_now()
    event = {
        "@timestamp": event_time,
        "event": {
            "category": ["file"],
            "kind": "event",
            "type": ["change"],
            "ingested": event_time,
        },
        "host": {"name": "linux-host-01", "os": {"type": "linux"}},
        "TargetFilename": "/tmp/notes.txt",
        "file": {"path": "/tmp/notes.txt"},
        "message": "Benign file creation in tmp",
    }
    append_lines(JSON_LOG, [json.dumps(event, sort_keys=True)])
    print("Emitted benign file-event control")


def emit_benign_suricata_pcap() -> None:
    IP, TCP, wrpcap = _scapy()
    if IP is None:
        print("scapy not available — skipping benign PCAP generation")
        return
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    packets = [IP(src="10.10.10.20", dst="10.10.20.20") / TCP(sport=41000, dport=443, flags="S")]
    path = PCAP_DIR / f"benign-flow-{int(datetime.now(timezone.utc).timestamp())}.pcap"
    wrpcap(str(path), packets)
    print("Emitted benign Suricata control PCAP")


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit safe validation telemetry for existing rules")
    parser.add_argument(
        "scenario",
        choices=[
            "sigma_system_info",
            "sigma_password_policy",
            "sigma_file_event_sudoers",
            "elastic_network_sweep",
            "elastic_external_ssh_bruteforce",
            "wazuh_failed_ssh",
            "suricata_network_sweep",
            "benign_auth",
            "benign_file_event",
            "benign_suricata",
        ],
    )
    args = parser.parse_args()

    if args.scenario == "sigma_system_info":
        emit_sigma_system_info()
    elif args.scenario == "sigma_password_policy":
        emit_sigma_password_policy()
    elif args.scenario == "sigma_file_event_sudoers":
        emit_sigma_file_event_sudoers()
    elif args.scenario == "elastic_network_sweep":
        emit_elastic_network_sweep()
    elif args.scenario == "elastic_external_ssh_bruteforce":
        emit_elastic_external_ssh_bruteforce()
    elif args.scenario == "wazuh_failed_ssh":
        emit_wazuh_failed_ssh()
    elif args.scenario == "suricata_network_sweep":
        emit_suricata_network_sweep_pcap()
    elif args.scenario == "benign_auth":
        emit_benign_auth()
    elif args.scenario == "benign_file_event":
        emit_benign_file_event()
    elif args.scenario == "benign_suricata":
        emit_benign_suricata_pcap()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
