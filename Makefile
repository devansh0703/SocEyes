# FDA Cyber Control — Standalone Makefile
# No Docker, no Elasticsearch, no JVM.  Single-process Python server.

SHELL := /bin/bash
PYTHON := python3
VENV := .venv-fda
PID_FILE := state/fda_server.pid
FRONTEND_OUT := frontend/out

.PHONY: help install start stop restart status logs dashboard stats bootstrap clean

help:
	@echo "FDA Cyber Control — Standalone"
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
	$(PYTHON) fda install

start:
	$(PYTHON) fda start

stop:
	$(PYTHON) fda stop

restart:
	$(PYTHON) fda restart

status:
	$(PYTHON) fda status

logs:
	@tail -n 100 -f state/fda_server.log 2>/dev/null || echo "No log file"

dashboard:
	$(PYTHON) fda dashboard

stats:
	$(PYTHON) fda stats

bootstrap:
	$(PYTHON) fda bootstrap

clean:
	$(PYTHON) fda clean

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
	@rm -rf /tmp/fda-package
	@mkdir -p /tmp/fda-package
	@if [ ! -d "frontend/out" ] && [ -f "frontend/package.json" ]; then \
		echo "Building frontend..."; \
		npm --prefix frontend install 2>/dev/null && npm --prefix frontend run build 2>/dev/null; \
	fi
	@# Core source
	@cp -r backend app_shared scripts zeroclaw agents /tmp/fda-package/
	@cp -r frontend/out /tmp/fda-package/frontend 2>/dev/null || echo "WARNING: frontend/out not found, run 'npm run build'"
	@# CLI + config
	@cp fda fda.sh install.sh install-full.sh Makefile .env.example README.md INSTRUCTIONS.md /tmp/fda-package/ 2>/dev/null || true
	@# Vendor rules + playbooks
	@cp -r vendor /tmp/fda-package/ 2>/dev/null || echo "WARNING: vendor/ not found"
	@cp -r detection-rules /tmp/fda-package/ 2>/dev/null || echo "WARNING: detection-rules/ not found"
	@# Wazuh rules + decoders
	@cp -r wazuh /tmp/fda-package/ 2>/dev/null || echo "WARNING: wazuh/ not found"
	@# Sigma rules
	@cp -r sigma /tmp/fda-package/ 2>/dev/null || echo "WARNING: sigma/ not found"
	@# Tests
	@cp -r tests /tmp/fda-package/ 2>/dev/null || true
	@# Requirements
	@cp -r requirements /tmp/fda-package/ 2>/dev/null || true
	@# ── Exclude Docker files ──
	@rm -f /tmp/fda-package/Dockerfile.* 2>/dev/null || true
	@rm -f /tmp/fda-package/docker-compose*.yml 2>/dev/null || true
	@# ── Exclude state/runtime dirs ──
	@rm -rf /tmp/fda-package/state
	@# ── Exclude IDE/cache ──
	@rm -rf /tmp/fda-package/.venv* /tmp/fda-package/.pytest_cache /tmp/fda-package/__pycache__
	@find /tmp/fda-package -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find /tmp/fda-package -name "*.pyc" -delete 2>/dev/null || true
	@# ── Create tarball ──
	@tar czf /tmp/fda-cyber-control-linux-x86_64.tar.gz -C /tmp/fda-package .
	@rm -rf /tmp/fda-package
	@echo "Package: /tmp/fda-cyber-control-linux-x86_64.tar.gz"
	@echo "Size: $$(du -h /tmp/fda-cyber-control-linux-x86_64.tar.gz | cut -f1)"
