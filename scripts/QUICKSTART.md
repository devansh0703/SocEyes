# Quick Start: Fake Attack Generator

## Installation
No dependencies required! Just Python 3.7+

## 30-Second Quick Start

```bash
cd /home/devansh/fda

# Generate all attack types (5 of each)
python3 scripts/generate_fake_attacks.py --count 5

# Check the generated logs
ls -lh ingest/auditd/audit.log ingest/syslog/syslog.log ingest/suricata/alerts.json
```

## Common Tasks

### Generate Only Discovery Attacks (MITRE T1082)
```bash
python3 scripts/generate_fake_attacks.py --type discovery --count 10
# Output: System info commands (uname, uptime, lsmod, etc.)
```

### Generate SSH Brute Force Attempts
```bash
python3 scripts/generate_fake_attacks.py --type ssh_brute_force --count 20
# Output: Failed SSH login attempts in syslog format
```

### Generate Privilege Escalation Attempts
```bash
python3 scripts/generate_fake_attacks.py --type privilege_escalation --count 5
# Output: sudo -i, su -, sudo -s attempts
```

### Generate Execution Attempts (Suspicious Commands)
```bash
python3 scripts/generate_fake_attacks.py --type execution --count 10
# Output: curl, wget, python, bash, netcat, etc.
```

### Clear Old Logs & Generate Fresh Ones
```bash
python3 scripts/generate_fake_attacks.py --clear --count 10
```

## View Generated Logs

```bash
# View latest auditd logs
tail -10 ingest/auditd/audit.log

# View latest syslog entries
tail -10 ingest/syslog/syslog.log

# View network alerts (pretty-printed)
tail -1 ingest/suricata/alerts.json | python3 -m json.tool
```

## Integration with Wazuh/Elasticsearch

Once logs are generated, they're automatically processed by:
1. **Logstash** - Indexes them to Elasticsearch
2. **Wazuh** - Fires detection rules
3. **Kibana** - Visualizes in dashboards

```bash
# Check if logs were ingested into Elasticsearch
curl -s 'http://localhost:9201/_cat/indices?v' | grep -E '(auditd|syslog|suricata)'

# Search for a specific attack
curl -s 'http://localhost:9201/logs-linux.auditd-*/_search?q=uname' | jq '.hits.total'
```

## All Attack Types

```
--type discovery              # System reconnaissance (T1082)
--type credential_access      # Password/account attacks (T1110)
--type execution              # Suspicious command execution (T1059)
--type privilege_escalation   # Sudo/su escalation (T1169)
--type ssh_brute_force        # SSH brute force attempts
--type sudo_execution         # Suspicious sudo commands
--type network_recon          # Network reconnaissance
```

## Examples in Real Scenarios

### Test Scenario: Attacker Performs Reconnaissance
```bash
# Attacker first discovers the system
python3 scripts/generate_fake_attacks.py --type discovery --count 5

# Then tries to escalate privileges
python3 scripts/generate_fake_attacks.py --type privilege_escalation --count 3

# Then executes suspicious commands
python3 scripts/generate_fake_attacks.py --type execution --count 5
```

### Test Scenario: Brute Force Attack
```bash
# Generate 50 failed SSH login attempts
python3 scripts/generate_fake_attacks.py --type ssh_brute_force --count 50

# Check Wazuh alert count
curl -s 'http://localhost:9201/wazuh-alerts-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"message": "Failed password"}}}' | jq '.hits.total'
```

## See Also
- Full documentation: [ATTACK_GENERATOR_README.md](./ATTACK_GENERATOR_README.md)
- Main project docs: [README.md](../README.md)
- Technical overview: [TECHNICAL_OVERVIEW.md](../TECHNICAL_OVERVIEW.md)

## Help
```bash
python3 scripts/generate_fake_attacks.py --help
```
