# Detection Pipeline

## Project Docs

- [explanations.md](https://github.com/syn3rgy2026/Bitflippers_Syn3rgy_AtharvSKulkarni/blob/main/INSTRUCTIONS.md)
- [technical.md](https://github.com/syn3rgy2026/Bitflippers_Syn3rgy_AtharvSKulkarni/blob/main/technical.md)
- [INSTRUCTIONS.md](https://github.com/syn3rgy2026/Bitflippers_Syn3rgy_AtharvSKulkarni/blob/main/INSTRUCTIONS.md)
- [demo.md](https://github.com/syn3rgy2026/Bitflippers_Syn3rgy_AtharvSKulkarni/blob/main/demo.md)

This workspace now has a real local detection pipeline around the content already present in:

- `detection-rules/`
- `sigma/`
- `wazuh/`
- `panther-analysis/`

The runtime is:

- `Elasticsearch + Kibana` in Docker for storage, search, and Elastic Security detections
- `Logstash` in Docker for log ingestion and Linux auditd normalization
- `Wazuh manager` in Docker for native Wazuh detections
- `Logstash` also tails Wazuh JSON alerts and archives and forwards them into Elasticsearch
- `detector-tools` container for importing Elastic rules, converting/importing Sigma rules, and running Panther Analysis Tool
- `rule-catalog` in Elasticsearch for fast BM25 rule/log lookup
- `log-catalog` in Elasticsearch for fast BM25 rule->log lookup across ingested indices

## What this gives you

- Linux auditd logs dropped into [ingest/auditd](/home/devansh/fda/ingest/auditd) are processed in parallel by:
  - Logstash -> Elasticsearch index `logs-linux.auditd-*`
  - Wazuh manager -> Logstash -> Elasticsearch indices `wazuh-alerts-*` and `wazuh-archives-*`
- Elastic `detection-rules` TOML rules can be loaded directly into Kibana detections.
- Sigma rules are converted into Elastic detection rules and loaded into Kibana detections.
- Local Wazuh XML rules in [config/wazuh/manager/rules/local_rules.xml](/home/devansh/fda/config/wazuh/manager/rules/local_rules.xml) fire on auditd `EXECVE` events and are indexed into `wazuh-alerts-*`.
- Panther detections can be tested locally with PAT.
- Rules from Elastic, Sigma, Wazuh local XML, and Panther content are indexed into a unified BM25-backed catalog for fast lookup.
- Ingested logs from `logs-*`, `wazuh-alerts-*`, and `wazuh-archives-*` are indexed into a BM25-backed `log-catalog` for reverse lookup from rules to candidate logs.

## Bring it up

1. Create your local environment file (it is git-ignored - never commit it):

```bash
cp .env.example .env
# then edit .env: set ELASTIC_PASSWORD, KIBANA_PASSWORD, KIBANA_ENCRYPTION_KEY
# GROQ_API_KEY is optional and only powers the LLM summaries
```

2. Start the detection pipeline:

```bash
make up
```

That starts Elasticsearch, Kibana, Logstash, the Wazuh manager, the API and the
frontend - roughly 3.5 GB of RAM, every container capped by the CPU/memory
limits in `docker-compose.yml`.

Optional automation (Suricata capture, ZeroClaw, response + orchestration
engines) is deliberately opt-in, because those services idle at high CPU/RAM for
no benefit while you are only running detections:

```bash
make up-soar     # add the SOAR containers
make up-full     # same, rebuilding images first
```

3. Load the Kibana detections:

```bash
make bootstrap
```

4. Open Kibana:

- URL: `http://localhost:5602`
- User: `elastic`
- Password: value of `ELASTIC_PASSWORD` in `.env`

## Feed logs

- Put Linux auditd logs into [ingest/auditd](/home/devansh/fda/ingest/auditd).
- The Wazuh manager is configured to read `/var/log/audit/audit.log`, so the simplest path is to place a real audit log file at:
  - [ingest/auditd/audit.log](/home/devansh/fda/ingest/auditd/audit.log)

For remote shippers:

- Beats input: `localhost:5045`
- Syslog TCP/UDP input: `localhost:5514`

## Main commands

```bash
make up            # core pipeline
make up-soar       # core + Suricata / ZeroClaw / response / orchestration
make bootstrap
make rule-catalog
make log-catalog
make elastic-rules
make sigma-rules
make panther-test
make test-pipeline
make test          # unit test suite (runs inside the api container)
make validate      # compose config + python syntax check
make stats         # live CPU / RAM per container
make logs
make down          # stop containers, keep the Elasticsearch volume
make clean         # stop + delete volumes, project images and build cache
make honeypot-prune# remove honeypot containers left by response actions
```

## Verify end to end

```bash
make test-pipeline
python3 scripts/map_logs_to_rules.py --log-message 'type=EXECVE msg=audit(1776546835.123:66836): argc=1 a0="uname"' --top-k 5
python3 scripts/map_rules_to_logs.py --rule-id 100500 --limit 5
```

- The helper scripts default to the published local endpoints `http://localhost:9201` and `http://localhost:5602`.
- `make test-pipeline` appends fresh auditd `EXECVE` events and waits for both `logs-linux.auditd-*` and `wazuh-alerts-*` hits.
- Syslog files dropped into [ingest/syslog](/home/devansh/fda/ingest/syslog) are ingested by Logstash and Wazuh in parallel, with Logstash storing them in `fda-syslog-*`.

## Resource use and cleanup

- Every service has `deploy.resources.limits` (CPU + memory) and json-file log
  rotation (`LOG_MAX_SIZE` / `LOG_MAX_FILE`), so a forgotten stack cannot fill
  the disk or starve the host.
- Only `make up` services run by default; `docker compose up -d` with no service
  names starts the core pipeline only.
- Runtime state (runs, responses, honeypot sessions) lives under `state/`
  (`$FDA_STATE_DIR`). App containers run as your host uid/gid, so those files
  stay yours instead of becoming root-owned.
- Honeypot containers are created with hard memory/CPU/PID limits, a read-only
  root filesystem, a loopback-only port, and a TTL (`HONEYPOT_TTL_SECONDS`,
  default 15 minutes). Expired ones are reaped automatically on the next
  response action; `make honeypot-prune` removes them all immediately.
- `make clean` is the full teardown: containers, named volumes, project images
  and dangling build cache.

## Publishing this repository

- `.env` is git-ignored; `.env.example` documents every variable with safe
  placeholders. No credentials are committed.
- `.dockerignore` keeps the build context to a few MB, so builds no longer ship
  `.git`, `.venv-tools`, `frontend/.next` or `state/` to the Docker daemon.
- No host-specific absolute paths remain: ZeroClaw's binary and config locations
  come from `ZEROCLAW_BIN_DIR` / `ZEROCLAW_HOME_DIR` (defaults under
  `.runtime/`, or point them at `$HOME/.zeroclaw`).

## Important limit

`panther-analysis` is real Panther detection content, but Panther's live streaming detection backend is not self-hosted here. This setup gives you real local validation/testing via `panther_analysis_tool`, while live runtime detection is implemented through Elastic and Wazuh.
