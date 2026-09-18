# Demo Guide

## Goal of the Demo

The goal is to demonstrate that:

- the pipeline is already running
- live telemetry can be generated manually in another terminal
- existing rules detect the activity automatically
- logs and alerts appear live in the UI
- rules map to logs
- logs map back to rules
- MITRE techniques and playbooks are shown
- response preview is shown before execution
- response execution changes live runtime state

Important operator-note:

- generator commands are intentionally documented in this file and not rendered in the command center UI.
- run control now lives in the global sidebar (start/save/stop + selected run context).

## Windows for the Demo

Recommended layout:

1. Browser window on the frontend
2. Terminal for generator commands
3. Optional terminal for API verification

## Frontend Pages to Keep Open

Open these pages:

- `http://localhost:3000/dashboard`
- `http://localhost:3000/logs`
- `http://localhost:3000/playbooks`
- `http://localhost:3000/responses`
- `http://localhost:3000/agents`

You do not need every page visible at once. A good flow is:

- start on Dashboard
- move to Dashboard
- move to Logs
- move to Playbooks
- move to Responses
- end on Agents

## Before the Demo

Make sure the stack is up:

```bash
docker compose up -d --build
docker compose ps
```

Optional validation:

```bash
curl -s http://localhost:8000/api/health
curl -s http://localhost:8000/api/zeroclaw/status
curl -s http://localhost:9393/health
```

## Demo Start

### Step 1. Start a run

In the UI:

- use the global left sidebar
- click `Start` in the `Run controls` panel
- optional: click `Save` to snapshot the run while it remains active

Or from a terminal:

```bash
curl -s http://localhost:8000/api/runs/start \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"Live demo","note":"Existing-rule live detection demo"}'
```

What the audience should see:

- the run state becomes active
- the run ID is visible in sidebar `Run controls`
- the selected run can be switched in sidebar `Selected run`

## Demo Scenario Set

These are the live generator commands currently available.

### 1. Linux system information discovery

Command:

```bash
python3 scripts/generators/generate_linux_system_info_discovery.py
```

What it generates:

- auditd `uname` execution event

What should detect:

- Sigma `f34047d9-20d3-4e8b-8672-0a35cc50dc71`
- Wazuh `100500`

What to show in UI:

- Dashboard alerts
- Logs page live entry
- clicked log mapped back to Sigma and Wazuh rules
- Playbook `T1082`

### 2. Linux password policy discovery

Command:

```bash
python3 scripts/generators/generate_linux_password_policy_discovery.py
```

What it generates:

- auditd `chage --list` execution event

What should detect:

- Sigma `ca94a6db-8106-4737-9ed2-3e3bb826af0a`
- Wazuh `100501`

What to show:

- log card
- rule card
- playbook mapping

### 3. Linux sudoers persistence file event

Command:

```bash
python3 scripts/generators/generate_linux_sudoers_persistence.py
```

What it generates:

- file event under `/etc/sudoers.d/`

What should detect:

- Sigma `ddb26b76-4447-4807-871f-1b035b2bfa5d`

What to show:

- rule studio or logs page detail
- readable rule logic

### 4. External SSH brute force

Command:

```bash
python3 scripts/generators/generate_external_ssh_bruteforce.py
```

What it generates:

- repeated failed SSH login events

What should detect:

- Elastic `fa210b61-b627-4e5e-86f4-17e8270656ab`

What to show:

- Dashboard detection
- Playbook `T1110`
- Response preview with account-disabling command

### 5. Wazuh failed SSH signal

Command:

```bash
python3 scripts/generators/generate_wazuh_failed_ssh.py
```

What it generates:

- failed SSH syslog lines for Wazuh correlation

What should detect:

- Wazuh `100511`

What to show:

- Wazuh alert in dashboard
- log detail in Logs page

### 6. Network sweep PCAP

Command:

```bash
python3 scripts/generators/generate_network_sweep_pcap.py
```

What it generates:

- PCAP containing sweep traffic

What should detect:

- Elastic `781f8746-2180-4691-890c-4c96d11ca91d`
- Wazuh `100622`

What to show:

- Suricata-backed network evidence
- playbook mapping
- response preview

### 7. Benign controls

Commands:

```bash
python3 scripts/generators/generate_benign_auth.py
python3 scripts/generators/generate_benign_file_event.py
python3 scripts/generators/generate_benign_suricata.py
```

Purpose:

- demonstrate true-negative coverage
- show that benign events do not create those specific detections

## Suggested Demo Story

### Sequence A. Realtime detection

1. Start the run.
2. Execute:

```bash
python3 scripts/generators/generate_linux_system_info_discovery.py
```

3. Show the Dashboard page updating.
4. Move to Logs and click the new event.
5. Show the mapped rules.
6. Move to Playbooks and show the `T1082` playbook in readable sections.

### Sequence B. Response preview and enforcement

1. Execute:

```bash
python3 scripts/generators/generate_external_ssh_bruteforce.py
```

2. Show the Response preview in the dashboard or Responses page.
3. Execute the response from the UI or API.
4. Explain that the action updates the live runtime control state.
5. Show the Responses page with:
   - the command
   - the summary
   - the live control entry

### Sequence C. Packet-driven network detection

1. Execute:

```bash
python3 scripts/generators/generate_network_sweep_pcap.py
```

2. Show:
   - Dashboard
   - Logs page
   - Playbooks page
   - Agents page

3. Highlight that Suricata, Elastic, Wazuh, and mapping are all visible in one operator flow.

### Sequence D. Validation state

Show the Agents page and explain:

- orchestration hands
- validation agent
- bandwidth governor
- ZeroClaw runtime status
- step-by-step execution records

## Demo End

Stop the run:

```bash
curl -s http://localhost:8000/api/runs/stop \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Then use sidebar `Selected run` to review previous run snapshots while staying on Logs, Playbooks, or Responses.

## Optional Full Validation Demo

If you want to show the automated validation metrics:

```bash
docker compose --profile tools run --rm detector-tools python scripts/evaluate_existing_rule_pipeline.py
```

Current expected result:

- `tp=9`
- `fn=0`
- `fp=0`
- `tn=4`

## Best Talking Points

- Existing rules are being used.
- Logs are visible while they are being generated.
- Logs are mapped back to real rules.
- Rules are mapped to MITRE and playbooks.
- Response commands are readable before execution.
- Response controls take effect live.
- ZeroClaw runtime status and orchestration are visible.
- The UI is split into focused dashboards instead of one overloaded page.
