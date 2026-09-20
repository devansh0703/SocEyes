#!/bin/bash
#=============================================================================
# FDA Cyber Control — Native Full-Stack Installer
#
# Installs and configures the complete IDS stack natively:
#   - Elasticsearch 9.x (search engine)
#   - Kibana 9.x (analytics UI)
#   - Logstash 9.x (log pipeline)
#   - Wazuh 4.x (HIDS + rules + decoders)
#   - Suricata (NIDS/PCAP)
#   - FastAPI backend
#   - Next.js frontend
#
# Tested on: Ubuntu 22.04/24.04, Debian 12
# Usage: sudo ./fda install-full
#=============================================================================

set -euo pipefail

# ── Variables ─────────────────────────────────────────────────────────────
FDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$FDA_DIR/state"
LOG_DIR="$STATE_DIR/logs"
DATA_DIR="$STATE_DIR/data"
CONFIG_DIR="$STATE_DIR/config"
PID_DIR="$STATE_DIR/pids"
VENV_DIR="$FDA_DIR/.venv-fda"

ES_VERSION="9.3.2"
WAZUH_VERSION="4.14.4"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

mkdir -p "$STATE_DIR" "$LOG_DIR" "$DATA_DIR" "$CONFIG_DIR" "$PID_DIR"

# ── Check root for native installs ────────────────────────────────────────
check_root() {
    [ "$(id -u)" = "0" ] || fail "Native install requires root. Run: sudo ./fda install-full"
}

# ── Detect OS ────────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        fail "Cannot detect OS"
    fi
    info "Detected: $OS $VER"
}

# ── Install Elasticsearch ─────────────────────────────────────────────────
install_elasticsearch() {
    if command -v elasticsearch >/dev/null 2>&1; then
        ok "Elasticsearch already installed"
        return
    fi
    
    info "Installing Elasticsearch $ES_VERSION..."
    
    # Install dependencies
    apt-get update -qq
    apt-get install -y -qq apt-transport-https openjdk-17-jre-headless wget curl
    
    # Add Elastic repo
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" > /etc/apt/sources.list.d/elastic-9.x.list
    apt-get update -qq
    apt-get install -y -qq elasticsearch=$ES_VERSION 2>/dev/null || apt-get install -y -qq elasticsearch
    
    # Configure
    mkdir -p "$DATA_DIR/elasticsearch"
    mkdir -p "$LOG_DIR/elasticsearch"
    
    cat > /etc/elasticsearch/elasticsearch.yml << EOF
path.data: $DATA_DIR/elasticsearch
path.logs: $LOG_DIR/elasticsearch
http.port: 9200
network.host: 127.0.0.1
discovery.type: single-node
xpack.security.enabled: true
xpack.security.authc.api_key.enabled: true
xpack.security.transport.ssl.enabled: false
xpack.ml.enabled: false
EOF
    
    # Set password
    echo "elastic:elastic" | chpasswd 2>/dev/null || true
    /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -i <<< "elastic
elastic" 2>/dev/null || true
    
    systemctl daemon-reload
    systemctl enable elasticsearch
    ok "Elasticsearch installed"
}

# ── Install Kibana ───────────────────────────────────────────────────────
install_kibana() {
    if command -v kibana >/dev/null 2>&1; then
        ok "Kibana already installed"
        return
    fi
    
    info "Installing Kibana..."
    apt-get install -y -qq kibana 2>/dev/null || apt-get install -y -qq kibana=$ES_VERSION 2>/dev/null || apt-get install -y -qq kibana
    
    cat > /etc/kibana/kibana.yml << EOF
server.port: 5601
server.host: "127.0.0.1"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "elastic"
EOF
    
    # Generate enrollment token and set kibana password
    /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana 2>/dev/null || true
    
    systemctl daemon-reload
    systemctl enable kibana
    ok "Kibana installed"
}

# ── Install Logstash ─────────────────────────────────────────────────────
install_logstash() {
    if command -v logstash >/dev/null 2>&1; then
        ok "Logstash already installed"
        return
    fi
    
    info "Installing Logstash..."
    apt-get install -y -qq logstash 2>/dev/null || apt-get install -y -qq logstash=$ES_VERSION 2>/dev/null || apt-get install -y -qq logstash
    
    mkdir -p "$CONFIG_DIR/logstash"
    mkdir -p "$DATA_DIR/logstash"
    
    cat > "$CONFIG_DIR/logstash/logstash.yml" << EOF
path.data: $DATA_DIR/logstash
path.logs: $LOG_DIR/logstash
http.host: "127.0.0.1"
http.port: 9600
EOF
    
    cat > "$CONFIG_DIR/logstash/pipelines.yml" << EOF
- pipeline.id: fda-main
  path.config: "$CONFIG_DIR/logstash/pipeline/*.conf"
EOF
    
    mkdir -p "$CONFIG_DIR/logstash/pipeline"
    
    # Default input pipeline
    cat > "$CONFIG_DIR/logstash/pipeline/10-inputs.conf" << 'INPUT'
input {
  beats {
    port => 5044
    host => "127.0.0.1"
  }
  syslog {
    port => 5514
    host => "127.0.0.1"
    type => "syslog"
  }
  tcp {
    port => 5045
    type => "json_lines"
    codec => json_lines
  }
}
INPUT
    
    cat > "$CONFIG_DIR/logstash/pipeline/90-output.conf" << 'OUTPUT'
output {
  elasticsearch {
    hosts => ["http://127.0.0.1:9200"]
    user => "elastic"
    password => "elastic"
    index => "logs-%{+YYYY.MM.dd}"
    ssl => false
    ssl_certificate_verification => false
  }
}
OUTPUT
    
    systemctl daemon-reload
    systemctl enable logstash
    ok "Logstash installed"
}

# ── Install Wazuh Manager ────────────────────────────────────────────────
install_wazuh() {
    if command -v wazuh-control >/dev/null 2>&1 || [ -f /var/ossec/bin/wazuh-control ]; then
        ok "Wazuh manager already installed"
        return
    fi
    
    info "Installing Wazuh manager $WAZUH_VERSION..."
    
    # Add Wazuh repo
    wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    apt-get install -y -qq wazuh-manager=$WAZUH_VERSION* 2>/dev/null || apt-get install -y -qq wazuh-manager
    
    # Copy rules/decoders from repo to wazuh
    if [ -d "$FDA_DIR/wazuh/ruleset/rules" ]; then
        cp -r "$FDA_DIR/wazuh/ruleset/rules/"* /var/ossec/etc/rules/ 2>/dev/null || true
        cp -r "$FDA_DIR/wazuh/ruleset/decoders/"* /var/ossec/etc/decoders/ 2>/dev/null || true
        ok "Wazuh rules copied from repo"
    fi
    
    # Configure
    mkdir -p "$DATA_DIR/wazuh"
    
    systemctl daemon-reload
    systemctl enable wazuh-manager
    ok "Wazuh manager installed"
}

# ── Install Suricata ────────────────────────────────────────────────────
install_suricata() {
    if command -v suricata >/dev/null 2>&1; then
        ok "Suricata already installed"
        return
    fi
    
    info "Installing Suricata..."
    apt-get install -y -qq suricata 2>/dev/null || apt-get install -y -qq suricata
    
    mkdir -p "$CONFIG_DIR/suricata"
    mkdir -p "$DATA_DIR/suricata"
    
    cat > "$CONFIG_DIR/suricata/suricata.yaml" << EOF
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert: {payload: yes, payload-printable: yes, packet: yes}
        - http
        - dns
        - tls
        - flow
EOF
    
    systemctl daemon-reload
    systemctl enable suricata
    ok "Suricata installed"
}

# ── Install Python environment ────────────────────────────────────────────
install_python_env() {
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating Python virtual environment..."
        python3 -m venv "$VENV_DIR"
        ok "venv created"
    fi
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    "$VENV_DIR/bin/pip" install -r "$FDA_DIR/requirements/api.txt" -q
    ok "Python dependencies installed"
}

# ── Create .env ──────────────────────────────────────────────────────────
create_env() {
    if [ ! -f "$FDA_DIR/.env" ]; then
        cat > "$FDA_DIR/.env" << EOF
# FDA Cyber Control — Native Configuration
ELASTICSEARCH_URL=http://127.0.0.1:9200
KIBANA_URL=http://127.0.0.1:5601
ELASTIC_PASSWORD=elastic
ELASTIC_USER=elastic
FDA_PORT=8000
FDA_HOST=0.0.0.0
NVIDIA_API_KEY=${NVIDIA_API_KEY:-}
NVIDIA_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
RETENTION_HOURS=24
RESPONSE_AUTO_EXECUTE=false
EOF
        ok ".env created"
    fi
}

# ── Build frontend ────────────────────────────────────────────────────────
build_frontend() {
    if [ ! -f "$FDA_DIR/frontend/index.html" ] && [ -f "$FDA_DIR/frontend/package.json" ]; then
        if command -v npm >/dev/null 2>&1; then
            info "Building frontend..."
            (cd "$FDA_DIR/frontend" && npm install --silent 2>/dev/null && npm run build)
            ok "frontend built"
        fi
    fi
}

# ── Bootstrap detection rules ────────────────────────────────────────────
bootstrap_rules() {
    info "Indexing detection rules..."
    cd "$FDA_DIR"
    "$VENV_DIR/bin/python" -c "
import sys, yaml
sys.path.insert(0, '.')
from pathlib import Path
from app_shared.unified_store import init_db, index_rule
init_db()
count = 0
for yml in (Path('sigma')/'rules').rglob('*.yml'):
    try:
        d = yaml.safe_load(yml.read_text())
        if isinstance(d, dict) and d.get('id'):
            index_rule({'rule_id': d['id'], 'engine': 'sigma', 'title': d.get('title',''),
                        'description': d.get('description',''), 'severity': d.get('level','medium'),
                        'technique_ids': [], 'file_path': str(yml), 'raw': d})
            count += 1
    except: pass
try:
    import tomllib
except:
    import tomli as tomllib
for toml in (Path('detection-rules')/'rules').rglob('*.toml'):
    try:
        with open(toml,'rb') as f: d = tomllib.load(f)
        r = d.get('rule',{})
        rid = r.get('rule_id') or r.get('id')
        if rid:
            index_rule({'rule_id': rid, 'engine': 'elastic', 'title': r.get('name',''),
                        'description': r.get('description',''), 'severity': r.get('severity','medium'),
                        'technique_ids': [t['id'] for th in r.get('threat',[]) for t in th.get('technique',[]) if t.get('id')],
                        'file_path': str(toml), 'raw': d})
            count += 1
    except: pass
print(f'Indexed {count} rules')
"
}

# ── Start all services ──────────────────────────────────────────────────
start_all() {
    echo -e "${BOLD}Starting all services...${RESET}"
    
    for svc in elasticsearch logstash kibana wazuh-manager suricata; do
        if systemctl is-active --quiet $svc 2>/dev/null; then
            ok "$svc already running"
        else
            systemctl start $svc 2>/dev/null || warn "$svc failed to start"
        fi
    done
    
    # Start API
    cd "$FDA_DIR"
    nohup "$VENV_DIR/bin/python" -m uvicorn backend.app.main:app \
        --host 0.0.0.0 --port 8000 > "$LOG_DIR/api.log" 2>&1 &
    echo $! > "$PID_DIR/api.pid"
    ok "API started"
    
    echo ""
    echo -e "${GREEN}All services started!${RESET}"
    echo "  Dashboard:     http://localhost:8000/"
    echo "  Kibana:        http://localhost:5601/"
    echo "  Elasticsearch: http://localhost:9200/"
}

# ── Main ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}FDA Cyber Control — Full Installer${RESET}"
echo "===================================="
echo ""

check_root
detect_os
install_elasticsearch
install_kibana
install_logstash
install_wazuh
install_suricata
install_python_env
create_env
build_frontend
bootstrap_rules

echo ""
echo -e "${GREEN}Installation complete!${RESET}"
echo "Start services with: ./fda.sh start"
