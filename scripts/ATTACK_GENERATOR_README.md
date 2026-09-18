# Fake Attack Generator for FDA Detection System

This script generates realistic fake attacks that will trigger detection rules in the FDA (Forensic Detection Analytics) system.

## Overview

The `generate_fake_attacks.py` script creates fake attack logs across multiple detection engines:
- **Linux auditd** - Command execution and system events
- **Wazuh** - Host-based intrusion detection
- **Syslog** - SSH and sudo events
- **Suricata** - Network-based intrusion detection

## Attack Types Supported

| Type | Description | Detection Engine | MITRE ATT&CK |
|------|-------------|------------------|-------------|
| `discovery` | System reconnaissance (uname, uptime, lsmod, etc.) | Wazuh auditd | T1082 (System Information Discovery) |
| `credential_access` | Password management commands (passwd, chage) | Wazuh auditd | T1110 (Brute Force) |
| `execution` | Suspicious command execution (curl, wget, python, bash) | Wazuh auditd | T1059 (Command and Scripting Interpreter) |
| `privilege_escalation` | Privilege escalation attempts (sudo -i, su -) | Wazuh auditd | T1169 (Obtain Elevated Execution) |
| `ssh_brute_force` | SSH failed login attempts | Syslog/Wazuh | T1110.001 (SSH Brute Force) |
| `sudo_execution` | Suspicious sudo command execution | Syslog/Wazuh | T1548.003 (Sudo and Sudo Caching) |
| `network_recon` | Network reconnaissance and port scanning | Suricata | T1046 (Network Service Discovery) |

## Installation

No external dependencies required beyond Python 3.7+.

```bash
cd /home/devansh/fda
python3 scripts/generate_fake_attacks.py --help
```

## Usage

### Generate All Attack Types (Default)
Generates 10 attacks of each type (50 total logs):
```bash
python3 scripts/generate_fake_attacks.py
```

### Generate Specific Attack Type
Generate 20 discovery attacks only:
```bash
python3 scripts/generate_fake_attacks.py --type discovery --count 20
```

### Other Options
```bash
# Generate 15 credential access attacks
python3 scripts/generate_fake_attacks.py --type credential_access --count 15

# Generate all types with custom count
python3 scripts/generate_fake_attacks.py --count 20

# Clear existing logs and generate fresh ones
python3 scripts/generate_fake_attacks.py --clear

# Use custom output directory
python3 scripts/generate_fake_attacks.py --output-dir /tmp/logs
```

## Command Reference

### Full Command Line Options

```
options:
  -h, --help            Show this help message and exit
  
  --type {discovery,credential_access,execution,privilege_escalation,ssh_brute_force,sudo_execution,network_recon}
                        Specific attack type to generate (default: all)
  
  --count COUNT         Number of attacks per type (default: 10)
  
  --output-dir OUTPUT_DIR
                        Output directory for logs (default: /home/devansh/fda/ingest)
  
  --clear               Clear existing logs before generating new ones
```

## Output

Generated logs are written to the `ingest/` directory structure:

```
ingest/
├── auditd/
│   └── audit.log          # Linux auditd EXECVE events
├── syslog/
│   └── syslog.log         # SSH and sudo events
├── json/
│   └── alerts.json        # JSON alerts (when implemented)
└── suricata/
    └── alerts.json        # Suricata network alerts
```

### Example Output

**auditd log (Discovery):**
```
type=EXECVE msg=audit(1776606336.001:100501): argc=1 a0="uname"
```

**auditd log (Privilege Escalation):**
```
type=EXECVE msg=audit(1776606336.002:102000): argc=2 a0="sudo" a1="-i"
```

**syslog (SSH Brute Force):**
```
Apr 19 19:15:35 localhost sshd[1000]: Failed password for root from 192.168.1.50 port 45123 ssh2
```

**syslog (Sudo Execution):**
```
Apr 19 19:15:36 localhost sudo: attacker : TTY=pts/0 ; PWD=/home/attacker ; USER=root ; COMMAND=cat /etc/shadow
```

**Suricata Network Alert (JSON):**
```json
{
  "timestamp": "2026-04-19T19:15:40",
  "event_type": "alert",
  "src_ip": "192.168.1.204",
  "dest_port": 22,
  "alert": {
    "signature": "ET POLICY SSH Inbound Connection",
    "severity": 2
  }
}
```

## Integration with Detection Pipeline

### 1. Testing with Wazuh

Once logs are generated, Wazuh will process them and trigger rules:

```bash
# View Wazuh alerts for discovery commands
curl -s 'http://localhost:9201/wazuh-alerts-*/_search?q=FDA' | jq '.hits.hits[] | .["_source"]'

# Check specific rule (discovery - T1082)
curl -s 'http://localhost:9201/wazuh-alerts-*/_search?q=rule.id:100500' | jq '.hits.total'
```

### 2. Testing with Elasticsearch

Query generated logs in Elasticsearch:

```bash
# Search for discovery attacks in auditd logs
curl -s 'http://localhost:9201/logs-linux.auditd-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "match": {
        "audit.execve.a0": "uname"
      }
    }
  }' | jq '.hits.total'

# View latest ingested alerts
curl -s 'http://localhost:9201/_cat/indices?v' | grep -E '(wazuh|logs|suricata)'
```

### 3. Testing with Kibana

1. Open Kibana: `http://localhost:5602`
2. Go to **Discover** → Select index pattern
3. Search for generated logs:
   - `audit.type: EXECVE` (auditd events)
   - `event_type: alert` (network alerts)
   - `message: Failed password` (SSH brute force)

### 4. Using Test Pipeline Command

After generating fake attacks:

```bash
# Run the built-in test pipeline
make test-pipeline

# Map logs to rules
python3 scripts/map_logs_to_rules.py --log-message 'type=EXECVE msg=audit(1776546835.123:66836): argc=1 a0="uname"' --top-k 5

# Map rules to logs
python3 scripts/map_rules_to_logs.py --rule-id 100500 --limit 5
```

## Example Workflows

### Scenario 1: Test Discovery Detection (MITRE T1082)

```bash
# Generate 5 discovery attack logs
python3 scripts/generate_fake_attacks.py --type discovery --count 5

# Wait a moment for ingestion
sleep 5

# Query for detection in Elasticsearch
curl -s 'http://localhost:9201/wazuh-alerts-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"rule.id": 100500}}}' | jq '.hits.hits[].["_source"] | {timestamp: .timestamp, rule_id: .rule.id, message: .message}'
```

### Scenario 2: Test SSH Brute Force Detection

```bash
# Generate 20 failed SSH login attempts
python3 scripts/generate_fake_attacks.py --type ssh_brute_force --count 20

# Check syslog ingestion
tail -10 /home/devansh/fda/ingest/syslog/syslog.log

# Wait for Wazuh processing, then query
curl -s 'http://localhost:9201/wazuh-alerts-*/_search?q=sshd' | jq '.hits.total'
```

### Scenario 3: Test Privilege Escalation Detection (MITRE T1169)

```bash
# Generate privilege escalation attempts
python3 scripts/generate_fake_attacks.py --type privilege_escalation --count 10

# Check the generated logs
tail -10 /home/devansh/fda/ingest/auditd/audit.log

# Map to detection rules
python3 scripts/map_logs_to_rules.py \
  --log-message 'type=EXECVE msg=audit(1776606336.001:102000): argc=2 a0="sudo" a1="-i"' \
  --top-k 5
```

### Scenario 4: Full End-to-End Test

```bash
# Clear existing logs and generate complete attack scenario
python3 scripts/generate_fake_attacks.py --clear --count 10

# Start a fresh detection run (if running the backend)
curl -X POST http://localhost:8000/api/runs/start \
  -H "Content-Type: application/json" \
  -d '{"name": "Attack Generation Test", "note": "Testing fake attack generation"}'

# Wait for ingestion and processing
sleep 10

# View dashboard
open http://localhost:5602

# Check detection metrics
curl http://localhost:8000/api/dashboard | jq '.alerts_count, .logs_count'
```

## Customization

### Modify Command Lists

Edit `generate_fake_attacks.py` to add custom commands or attack patterns:

```python
# Add more discovery commands
commands = ["uname", "uptime", "lsmod", "hostname", "env", "kmod", "whoami", "id"]

# Add more execution commands
commands = ["bash", "sh", "curl", "wget", "perl", "python", "ruby", "nc", "netcat"]
```

### Add New Attack Types

Extend the script by adding a new method:

```python
def generate_lateral_movement_attacks(self, count: int = 10) -> List[str]:
    """Generate lateral movement attacks (T1570)."""
    logs = []
    for i in range(count):
        # Generate logs...
        pass
    return logs
```

Then register it in `generate_all()` and add to the `AttackType` enum.

## Limitations & Notes

1. **Timestamps**: Generated logs use sequential timestamps starting from script execution time. For historical testing, modify `self.start_time` in the constructor.

2. **Realism**: While logs match the expected format for Wazuh and Elasticsearch, they are simplified representations. Real attack logs may include additional fields and context.

3. **Volume**: Large `--count` values will generate many logs. Start with small counts for testing.

4. **No Actual Attacks**: This script generates benign, formatted logs only. No system is actually compromised or damaged.

5. **Detection Lag**: There may be a 5-30 second delay between log ingestion and alert generation, depending on Wazuh/Logstash configuration.

## Troubleshooting

**Q: Logs not appearing in Elasticsearch**
- A: Check that `make up` and `make bootstrap` have completed successfully
- Check Logstash logs: `docker logs fda-logstash-1`
- Verify Wazuh is running: `docker ps | grep wazuh`

**Q: Wazuh alerts not triggering**
- A: Confirm rules are loaded: Check `config/wazuh/manager/rules/local_rules.xml`
- Verify rule IDs are correct (100500, 100501, etc.)
- Check Wazuh manager logs: `docker logs fda-wazuh-manager-1`

**Q: Permission denied when writing logs**
- A: Ensure `ingest/` directory has correct permissions:
  ```bash
  chmod -R 777 /home/devansh/fda/ingest
  ```

**Q: High memory usage**
- A: Generate fewer attacks at a time with smaller `--count` values
- Monitor Elasticsearch: `curl http://localhost:9201/_nodes/stats/jvm | jq '.nodes[].jvm'`

## Performance Tips

1. Generate in batches: `for i in {1..5}; do python3 scripts/generate_fake_attacks.py --type discovery --count 5 && sleep 2; done`
2. Monitor ingestion: `watch 'curl -s http://localhost:9201/_cat/indices | tail -5'`
3. Clear old logs periodically: `python3 scripts/generate_fake_attacks.py --clear`

## Support & Debugging

For issues or questions:
1. Check the main README.md in `/home/devansh/fda/`
2. Review Wazuh rules: `cat config/wazuh/manager/rules/local_rules.xml`
3. Check detection-rules: `ls -la detection-rules/`
4. View Kibana: http://localhost:5602

## License

Same as the FDA project.
