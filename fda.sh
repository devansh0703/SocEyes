#!/bin/bash
#=============================================================================
# FDA Cyber Control — Native IDS Process Manager
# 
# Manages the full intrusion detection stack as native processes:
#   - Elasticsearch (search engine + storage)
#   - Kibana (analytics UI)
#   - Logstash (log pipeline)
#   - Wazuh manager (HIDS)
#   - Suricata (NIDS/PCAP analysis)
#   - FastAPI backend
#   - Next.js frontend
#   - Response engine
#   - Orchestration engine
#   - Retention cron
#   - ZeroClaw agents
#
# Usage: ./fda.sh {install|start|stop|restart|status|attack|clean}
#=============================================================================

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────
FDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$FDA_DIR/state"
LOG_DIR="$STATE_DIR/logs"
PID_DIR="$STATE_DIR/pids"
DATA_DIR="$STATE_DIR/data"
CONFIG_DIR="$STATE_DIR/config"
PCAP_DIR="$FDA_DIR/pcap"
VENV_DIR="$FDA_DIR/.venv-fda"

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

mkdir -p "$STATE_DIR" "$LOG_DIR" "$PID_DIR" "$DATA_DIR" "$CONFIG_DIR" "$PCAP_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────
is_running() {
    local pidfile="$PID_DIR/${1}.pid"
    [ -f "$pidfile" ] || return 1
    local pid; pid=$(cat "$pidfile" 2>/dev/null) || return 1
    kill -0 "$pid" 2>/dev/null
}

start_service() {
    local name="$1"; shift
    local pidfile="$PID_DIR/${name}.pid"
    nohup "$@" >"$LOG_DIR/${name}.log" 2>&1 &
    echo $! > "$pidfile"
    ok "$name started (PID $(cat "$pidfile"))"
}

stop_service() {
    local name="$1"
    local pidfile="$PID_DIR/${name}.pid"
    if [ -f "$pidfile" ]; then
        local pid; pid=$(cat "$pidfile" 2>/dev/null) || true
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
        rm -f "$pidfile"
        ok "$name stopped"
    fi
}

wait_for_port() {
    local port=$1 timeout=${2:-90}
    local count=0
    while ! ss -tlnp 2>/dev/null | grep -q ":$port "; do
        sleep 2; count=$((count + 2))
        [ $count -ge $timeout ] && return 1
    done
    return 0
}

# ── Install ──────────────────────────────────────────────────────────────
do_install() {
    echo -e "${BOLD}FDA Cyber Control — Installation${RESET}"
    echo "=================================="
    
    # Python venv
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR"
        ok "venv created"
    fi
    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    "$VENV_DIR/bin/pip" install -r "$FDA_DIR/requirements/api.txt" -q
    ok "dependencies installed"
    
    # .env
    if [ ! -f "$FDA_DIR/.env" ]; then
        cp "$FDA_DIR/.env.example" "$FDA_DIR/.env"
        ok "Created .env"
    fi
    
    # Frontend
    if [ ! -f "$FDA_DIR/frontend/index.html" ] && [ -f "$FDA_DIR/frontend/package.json" ]; then
        if command -v npm >/dev/null 2>&1; then
            info "Building frontend..."
            (cd "$FDA_DIR/frontend" && npm install --silent 2>/dev/null && npm run build)
            ok "frontend built"
        else
            warn "npm not found — frontend will not be available"
        fi
    fi
    
    # Bootstrap rules (all four engines via the real seeder)
    info "Indexing detection rules (sigma, elastic, panther, wazuh)..."
    cd "$FDA_DIR"
    "$VENV_DIR/bin/python" -c "
import sys
sys.path.insert(0, '.')
from pathlib import Path
from app_shared.sqlite_store import init_db
from backend.app.services.seed_rules import seed_rules
init_db()
print('Indexed:', seed_rules(Path('.')))
"
    
    echo ""
    echo -e "${GREEN}Installation complete!${RESET}"
    echo "Start with: ./fda.sh start"
    echo "Then open:  http://localhost:8000/"
}

# ── Start ─────────────────────────────────────────────────────────────────
do_start() {
    echo -e "${BOLD}FDA Cyber Control — Starting${RESET}"
    echo "==============================="
    cd "$FDA_DIR"
    
    # 1. Elasticsearch
    if ! is_running elasticsearch; then
        if command -v elasticsearch >/dev/null 2>&1; then
            info "Starting Elasticsearch..."
            local es_data="$DATA_DIR/elasticsearch"
            local es_heap="${ES_HEAP:-512m}"
            ES_PATH_CONF="$CONFIG_DIR/elasticsearch" elasticsearch \
                -d -p "$PID_DIR/elasticsearch.pid" \
                -Epath.data="$es_data" \
                -Epath.logs="$LOG_DIR/elasticsearch" \
                -Ehttp.port=9200 \
                -Ediscovery.type=single-node \
                -Expack.security.enabled=true \
                -E"xpack.security.authc.api_key.enabled=true" \
                -E"xpack.security.transport.ssl.enabled=false" \
                -Expack.ml.enabled=false 2>/dev/null || \
            elasticsearch -d -p "$PID_DIR/elasticsearch.pid"
            if wait_for_port 9200 120; then
                ok "Elasticsearch running on :9200"
                # Set passwords
                [ -f "$CONFIG_DIR/.es_pass" ] || echo "elastic" > "$CONFIG_DIR/.es_pass"
            else
                warn "Elasticsearch did not start in time"
            fi
        else
            warn "Elasticsearch not installed — using SQLite mode"
        fi
    else
        ok "Elasticsearch already running"
    fi
    
    # 2. Logstash
    if ! is_running logstash; then
        if command -v logstash >/dev/null 2>&1; then
            info "Starting Logstash..."
            start_service logstash logstash --path.settings "$CONFIG_DIR/logstash"
        else
            warn "Logstash not installed"
        fi
    else
        ok "Logstash already running"
    fi
    
    # 3. Kibana
    if ! is_running kibana; then
        if command -v kibana >/dev/null 2>&1; then
            info "Starting Kibana..."
            start_service kibana kibana --server.port=5601
        else
            warn "Kibana not installed"
        fi
    else
        ok "Kibana already running"
    fi
    
    # 4. Wazuh manager
    if ! is_running wazuh; then
        if command -v wazuh-control >/dev/null 2>&1; then
            info "Starting Wazuh manager..."
            wazuh-control start 2>/dev/null || true
            ok "Wazuh manager started"
        else
            warn "Wazuh manager not installed"
        fi
    else
        ok "Wazuh manager already running"
    fi
    
    # 5. Suricata (if installed and interfaces available)
    if ! is_running suricata; then
        if command -v suricata >/dev/null 2>&1; then
            info "Starting Suricata (offline PCAP mode)..."
            mkdir -p "$DATA_DIR/suricata"
            start_service suricata suricata -c "$CONFIG_DIR/suricata/suricata.yaml" --pcap-file-continuous -r "$PCAP_DIR"
        else
            warn "Suricata not installed"
        fi
    else
        ok "Suricata already running"
    fi
    
    # 6. API Backend
    if ! is_running api; then
        [ -d "$VENV_DIR" ] || do_install
        info "Starting FastAPI backend..."
        start_service api "$VENV_DIR/bin/python" -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
        wait_for_port 8000 15
        ok "API running on :8000"
    else
        ok "API already running"
    fi
    
    # 7. Response Engine
    if ! is_running response-engine; then
        info "Starting response engine..."
        start_service response-engine "$VENV_DIR/bin/python" agents/response_engine.py
    else
        ok "Response engine already running"
    fi
    
    # 8. Orchestration Engine
    if ! is_running orchestration-engine; then
        info "Starting orchestration engine..."
        start_service orchestration-engine "$VENV_DIR/bin/python" agents/orchestration_engine.py
    else
        ok "Orchestration engine already running"
    fi
    
    # 9. Retention Cron
    if ! is_running retention-cron; then
        info "Starting retention cron..."
        start_service retention-cron "$VENV_DIR/bin/python" agents/retention_cron.py
    else
        ok "Retention cron already running"
    fi
    
    # 10. ZeroClaw Agents
    if ! is_running zeroclaw-daemon; then
        if [ -d "$FDA_DIR/zeroclaw" ]; then
            info "Starting ZeroClaw agent daemon..."
            start_service zeroclaw-daemon "$VENV_DIR/bin/python" agents/zeroclaw_daemon.py
        fi
    fi
    
    # 11. Capture agent (packet capture -> /api/events/ingest)
    if ! is_running capture-agent; then
        AGENT_BIN="$FDA_DIR/bin/fda-agent"
        [ -x "$AGENT_BIN" ] || AGENT_BIN="$FDA_DIR/agent/fda-agent"
        if [ -x "$AGENT_BIN" ]; then
            info "Starting capture agent ($AGENT_BIN)..."
            start_service capture-agent "$AGENT_BIN"
        else
            warn "Capture agent binary not found — build it with: cd agent && go build -o ../bin/fda-agent ."
        fi
    else
        ok "Capture agent already running"
    fi
    
    echo ""
    echo -e "${GREEN}All services started!${RESET}"
    echo "  Dashboard:   http://localhost:8000/"
    echo "  API Docs:    http://localhost:8000/docs"
    echo "  Kibana:      http://localhost:5601/"
    echo "  Elasticsearch: http://localhost:9200/"
}

# ── Stop ──────────────────────────────────────────────────────────────────
do_stop() {
    echo "Stopping FDA Cyber Control..."
    for svc in capture-agent zeroclaw-daemon retention-cron orchestration-engine response-engine api suricata wazuh kibana logstash elasticsearch; do
        stop_service "$svc" 2>/dev/null || true
    done
    echo -e "${GREEN}All services stopped${RESET}"
}

# ── Restart ───────────────────────────────────────────────────────────────
do_restart() {
    do_stop
    sleep 2
    do_start
}

# ── Status ────────────────────────────────────────────────────────────────
do_status() {
    echo -e "${BOLD}FDA Cyber Control — Status${RESET}"
    echo "=============================="
    local services="capture-agent elasticsearch logstash kibana wazuh suricata api response-engine orchestration-engine retention-cron zeroclaw-daemon"
    for svc in $services; do
        if is_running "$svc"; then
            local pid; pid=$(cat "$PID_DIR/${svc}.pid" 2>/dev/null)
            echo -e "  ${GREEN}● $svc${RESET} (PID $pid)"
        else
            echo -e "  ${RED}○ $svc${RESET} (stopped)"
        fi
    done
    
    # Port check
    echo ""
    echo "Ports:"
    for port in 8000 9200 5601 514 55000; do
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            echo -e "  ${GREEN}● :$port${RESET} (listening)"
        fi
    done
}

# ── Attack (generate test attacks) ──────────────────────────────────────
do_attack() {
    echo -e "${BOLD}Generating test attack traffic...${RESET}"
    cd "$FDA_DIR"
    [ -d "$VENV_DIR" ] || do_install
    
    if [ -d "scripts/generators" ]; then
        info "Running attack generators..."
        "$VENV_DIR/bin/python" scripts/generators/generate_all_attack_logs.py --rounds 2 2>&1 || true
        ok "Attack traffic generated"
    fi
    
    # Generate PCAP if suricata is available
    if [ -d "scripts/generators" ] && command -v suricata >/dev/null 2>&1; then
        info "Generating PCAP file..."
        "$VENV_DIR/bin/python" scripts/generators/generate_network_sweep_pcap.py 2>&1 || true
        ok "PCAP generated"
    fi
    
    echo "Check the dashboard to see detected attacks"
}

# ── Clean ─────────────────────────────────────────────────────────────────
do_clean() {
    read -p "This will remove all data. Continue? [y/N] " ans
    [ "$ans" = "y" ] || [ "$ans" = "Y" ] || exit 0
    
    do_stop
    rm -rf "$STATE_DIR"
    [ -f "$FDA_DIR/state/fda_events.sqlite" ] && rm -f "$FDA_DIR/state/fda_events.sqlite"*
    echo -e "${GREEN}All data cleaned${RESET}"
}

# ── Main ──────────────────────────────────────────────────────────────────
case "${1:-help}" in
    install) do_install ;;
    start)   do_start   ;;
    stop)    do_stop    ;;
    restart) do_restart ;;
    status)  do_status  ;;
    attack)  do_attack   ;;
    clean)   do_clean   ;;
    help|*)
        echo "Usage: ./fda.sh {install|start|stop|restart|status|attack|clean}"
        echo ""
        echo "Commands:"
        echo "  install   Install dependencies, build frontend, index rules"
        echo "  start     Start all IDS services"
        echo "  stop      Stop all services"
        echo "  restart   Restart all services"
        echo "  status    Show service status"
        echo "  attack    Generate test attack traffic"
        echo "  clean     Remove all runtime data"
        exit 0
        ;;
esac
