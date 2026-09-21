# SocEyes — Standalone Makefile
# No Docker, no Elasticsearch, no JVM.  Single-process Python server.

SHELL := /bin/bash
PYTHON := python3
VENV := .venv-soceyes
PID_FILE := state/soceyes_server.pid
FRONTEND_OUT := frontend/out

.PHONY: help install start stop restart status logs dashboard stats bootstrap clean agent cloud-check

help:
	@echo "SocEyes — Standalone"
	@echo ""
	@echo "  make install    - Create .env, set up venv, install deps, build frontend"
	@echo "  make start      - Start the standalone server"
	@echo "  make stop       - Stop the server"
	@echo "  make restart    - Restart the server"
	@echo "  make status     - Show server health + DB stats"
	@echo "  make logs       - Tail server logs"
	@echo "  make dashboard  - Open the web UI"
	@echo "  make stats      - Show process resource usage"
	@echo "  make bootstrap  - Index detection rules"
	@echo "  make clean      - Remove all runtime state"
	@echo "  make package    - Build distributable tarball"

install:
	$(PYTHON) soceyes install

start:
	$(PYTHON) soceyes start

stop:
	$(PYTHON) soceyes stop

restart:
	$(PYTHON) soceyes restart

status:
	$(PYTHON) soceyes status

logs:
	@tail -n 100 -f state/soceyes_server.log 2>/dev/null || echo "No log file"

dashboard:
	$(PYTHON) soceyes dashboard

stats:
	$(PYTHON) soceyes stats

bootstrap:
	$(PYTHON) soceyes bootstrap

clean:
	$(PYTHON) soceyes clean

agent:
	@echo "Building Go capture agent..."
	@cd agent && go build -o ../bin/soceyes-agent ./main.go
	@echo "Agent built: bin/soceyes-agent (run with sudo)"

cloud-check:
	@echo "Running cloud exposure checks..."
	@$(PYTHON) scripts/check_cloud_exposure.py

# ── Testing ──────────────────────────────────────────────────────────────
.PHONY: test lint compile

compile:
	$(PYTHON) -m compileall -q backend app_shared scripts

lint: compile

test: compile
	$(PYTHON) -m pytest tests/ -v 2>/dev/null || $(PYTHON) -m unittest discover -s tests -t . -v

# ── Packaging ────────────────────────────────────────────────────────────
.PHONY: package

package:
	@echo "Building distributable package..."
	@rm -rf /tmp/soceyes-package
	@mkdir -p /tmp/soceyes-package
	@if [ ! -d "frontend/out" ] && [ -f "frontend/package.json" ]; then \
		echo "Building frontend..."; \
		npm --prefix frontend install 2>/dev/null && npm --prefix frontend run build 2>/dev/null; \
	fi
	@# Core source
	@cp -r backend app_shared scripts zeroclaw agents /tmp/soceyes-package/
	@mkdir -p /tmp/soceyes-package/agent && cp -r agent/capture /tmp/soceyes-package/agent/ 2>/dev/null || true
	@cp agent/go.mod /tmp/soceyes-package/agent/ 2>/dev/null || true
	@cp -r frontend/out /tmp/soceyes-package/frontend 2>/dev/null || echo "WARNING: frontend/out not found, run 'npm run build'"
	@# CLI + config
	@cp soceyes soceyes.sh install.sh install-full.sh Makefile .env.example README.md INSTRUCTIONS.md /tmp/soceyes-package/ 2>/dev/null || true
	@# Vendor rules + playbooks
	@cp -r vendor /tmp/soceyes-package/ 2>/dev/null || echo "WARNING: vendor/ not found"
	@cp -r detection-rules /tmp/soceyes-package/ 2>/dev/null || echo "WARNING: detection-rules/ not found"
	@# Wazuh rules + decoders
	@cp -r wazuh /tmp/soceyes-package/ 2>/dev/null || echo "WARNING: wazuh/ not found"
	@# Sigma rules
	@cp -r sigma /tmp/soceyes-package/ 2>/dev/null || echo "WARNING: sigma/ not found"
	@# Tests
	@cp -r tests /tmp/soceyes-package/ 2>/dev/null || true
	@# Requirements
	@cp -r requirements /tmp/soceyes-package/ 2>/dev/null || true
	@# ── Exclude Docker files ──
	@rm -f /tmp/soceyes-package/Dockerfile.* 2>/dev/null || true
	@rm -f /tmp/soceyes-package/docker-compose*.yml 2>/dev/null || true
	@# ── Exclude state/runtime dirs ──
	@rm -rf /tmp/soceyes-package/state
	@# ── Exclude IDE/cache ──
	@rm -rf /tmp/soceyes-package/.venv* /tmp/soceyes-package/.pytest_cache /tmp/soceyes-package/__pycache__
	@find /tmp/soceyes-package -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find /tmp/soceyes-package -name "*.pyc" -delete 2>/dev/null || true
	@# ── Create tarball ──
	@tar czf /tmp/soceyes-linux-x86_64.tar.gz -C /tmp/soceyes-package .
	@rm -rf /tmp/soceyes-package
	@echo "Package: /tmp/soceyes-linux-x86_64.tar.gz"
	@echo "Size: $$(du -h /tmp/soceyes-linux-x86_64.tar.gz | cut -f1)"
