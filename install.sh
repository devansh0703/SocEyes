#!/bin/bash
#=============================================================================
# FDA Cyber Control — Complete IDS Installer
# Installs and configures all IDS engines: Sigma, Elastic, Wazuh, Suricata
#=============================================================================
set -euo pipefail

FDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$FDA_DIR/state"
VENV_DIR="$FDA_DIR/.venv-fda"
LOG_DIR="$STATE_DIR/logs"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo ""
echo -e "${BOLD}FDA Cyber Control — Installer${RESET}"
echo "=============================="
echo ""

command -v python3 >/dev/null 2>&1 || fail "Python 3.10+ required"
info "Python detected"

# ── Step 1: Virtual environment ──────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 1: Virtual environment${RESET}"
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    ok "venv created"
fi

PIP="$VENV_DIR/bin/python -m pip"
$PIP install --upgrade pip -q 2>/dev/null
$PIP install -r "$FDA_DIR/requirements/api.txt" -q 2>/dev/null
ok "Dependencies installed"

# ── Step 2: Configuration ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 2: Configuration${RESET}"
if [ ! -f "$FDA_DIR/.env" ]; then
    cp "$FDA_DIR/.env.example" "$FDA_DIR/.env"
    ok "Created .env"
    warn "Edit .env to set NVIDIA_API_KEY for LLM features"
fi

# ── Step 3: State directory ──────────────────────────────────────────────
mkdir -p "$STATE_DIR"/{logs,pids,data,config}
ok "State directories created"

# ── Step 4: Frontend build ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 3: Frontend${RESET}"
if [ ! -f "$FDA_DIR/frontend/index.html" ] && [ -f "$FDA_DIR/frontend/package.json" ]; then
    if command -v npm >/dev/null 2>&1; then
        info "Building frontend..."
        (cd "$FDA_DIR/frontend" && npm install --silent 2>/dev/null && npm run build)
        ok "Frontend built"
    else
        warn "npm not found — frontend will not be available"
    fi
else
    ok "Frontend already built"
fi

# ── Step 5: Build Go capture agent ─────────────────────────────────────
echo ""
echo -e "${BOLD}Step 5: Go capture agent${RESET}"
if command -v go >/dev/null 2>&1; then
    info "Building Go agent..."
    (cd "$FDA_DIR/agent" && go build -o "$FDA_DIR/bin/fda-agent" . 2>/dev/null)
    if [ -f "$FDA_DIR/bin/fda-agent" ]; then
        # Packet capture needs CAP_NET_RAW; grant it to the binary so the
        # agent runs unprivileged (no root process in the stack).
        if sudo -n setcap cap_net_raw=ep "$FDA_DIR/bin/fda-agent" 2>/dev/null \
            || setcap cap_net_raw=ep "$FDA_DIR/bin/fda-agent" 2>/dev/null; then
            ok "Go agent built: $FDA_DIR/bin/fda-agent (cap_net_raw granted)"
        else
            ok "Go agent built: $FDA_DIR/bin/fda-agent (run: sudo setcap cap_net_raw=ep $FDA_DIR/bin/fda-agent)"
        fi
    else
        warn "Go agent build failed (run 'cd agent && go build' manually)"
    fi
else
    warn "Go not found — skipping agent build (install Go 1.25+ for packet capture)"
fi

# ── Step 6: Rule corpora ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 6: Rule corpora${RESET}"
if [ ! -d "$FDA_DIR/sigma/rules" ] || [ ! -d "$FDA_DIR/panther-analysis/rules" ]; then
    info "Fetching detection rule corpora (Sigma, Elastic, Wazuh, Panther)..."
    bash "$FDA_DIR/scripts/fetch_rule_corpora.sh" || warn "Some corpora failed to fetch — run scripts/fetch_rule_corpora.sh to retry"
else
    ok "Rule corpora already present"
fi

# ── Step 7: Index ALL detection rules ───────────────────────────────────
echo ""
echo -e "${BOLD}Step 7: Indexing all IDS rules${RESET}"
cd "$FDA_DIR"
"$VENV_DIR/bin/python" -c "
import sys, yaml
sys.path.insert(0, '.')
from pathlib import Path
from app_shared.sqlite_store import init_db, index_rule
init_db()
engines = {}

# 1. Sigma rules (sigma/rules/**/*.yml)
sigma_dir = Path('sigma/rules')
count = 0
if sigma_dir.exists():
    for yml in sigma_dir.rglob('*.yml'):
        try:
            data = yaml.safe_load(yml.read_text())
            if isinstance(data, dict) and data.get('id'):
                index_rule({'rule_id': data['id'], 'engine': 'sigma',
                            'title': data.get('title', ''), 'description': data.get('description', ''),
                            'severity': data.get('level', 'medium'), 'technique_ids': [],
                            'mitre_ids': [], 'file_path': str(yml), 'raw': data})
                count += 1
        except: pass
    engines['Sigma'] = count

# 2. Elastic detection-rules (detection-rules/rules/**/*.toml)
try:
    import tomllib
except:
    import tomli as tomllib
det_dir = Path('detection-rules/rules')
count = 0
if det_dir.exists():
    for toml in det_dir.rglob('*.toml'):
        try:
            with open(toml, 'rb') as f:
                data = tomllib.load(f)
            rule = data.get('rule', {})
            rule_id = rule.get('rule_id') or rule.get('id')
            if rule_id:
                tech_ids = [t['id'] for th in rule.get('threat', []) for t in th.get('technique', []) if t.get('id')]
                index_rule({'rule_id': rule_id, 'engine': 'elastic',
                            'title': rule.get('name', ''), 'description': rule.get('description', ''),
                            'severity': rule.get('severity', 'medium'), 'technique_ids': tech_ids,
                            'mitre_ids': [], 'file_path': str(toml), 'raw': data})
                count += 1
        except: pass
    engines['Elastic'] = count

# 3. Suricata rules (detection-rules with suricata in name)
count = 0
for toml in det_dir.rglob('*suricata*.toml'):
    try:
        with open(toml, 'rb') as f:
            data = tomllib.load(f)
        rule = data.get('rule', {})
        rule_id = rule.get('rule_id') or rule.get('id')
        if rule_id:
            tech_ids = [t['id'] for th in rule.get('threat', []) for t in th.get('technique', []) if t.get('id')]
            index_rule({'rule_id': rule_id, 'engine': 'suricata',
                        'title': rule.get('name', ''), 'description': rule.get('description', ''),
                        'severity': rule.get('severity', 'medium'), 'technique_ids': tech_ids,
                        'mitre_ids': [], 'file_path': str(toml), 'raw': data})
            count += 1
    except: pass
engines['Suricata'] = count

# 4. Wazuh SCA policies (sca/**/*.yml)
sca_dir = Path('wazuh/ruleset/sca')
count = 0
if sca_dir.exists():
    for yml in sca_dir.rglob('*.yml'):
        try:
            data = yaml.safe_load(yml.read_text())
            if isinstance(data, dict) and data.get('id'):
                index_rule({'rule_id': f'sca-{data[\"id\"]}', 'engine': 'wazuh',
                            'title': data.get('title', data.get('name', '')),
                            'description': data.get('description', ''),
                            'severity': 'medium', 'technique_ids': [],
                            'mitre_ids': [], 'file_path': str(yml), 'raw': data})
                count += 1
        except: pass
    engines['Wazuh SCA'] = count

total = sum(engines.values())
for engine, cnt in engines.items():
    print(f'  {engine}: {cnt} rules')
print(f'\\nTotal: {total} rules indexed')
"

# ── Verification ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Verification${RESET}"
RULE_COUNT=$("$VENV_DIR/bin/python" -c "
import sys; sys.path.insert(0, '.')
from app_shared.sqlite_store import init_db
conn = init_db()
row = conn.execute('SELECT COUNT(*) as c FROM rules').fetchone()
print(row['c'])
")
echo -e "  Rules indexed: ${GREEN}${RULE_COUNT}${RESET}"

if [ -f "$FDA_DIR/bin/fda-agent" ]; then
    echo -e "  Go agent: ${GREEN}built${RESET}"
else
    echo -e "  Go agent: ${YELLOW}not built${RESET} (install Go 1.25+ for packet capture)"
fi

# ── Done ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}========================${RESET}"
echo -e "${GREEN}Installation complete!${RESET}"
echo ""
echo "Start the server:"
echo "  ${BOLD}./fda start${RESET}"
echo ""
echo "Then open:"
echo "  ${CYAN}http://localhost:8000/${RESET}"
echo ""
echo "Run the capture agent (requires root):"
echo "  ${BOLD}sudo ./bin/fda-agent${RESET}"
echo ""
echo "Commands:"
echo "  ./fda start          Start server"
echo "  ./fda stop           Stop server"
echo "  ./fda status         Show status"
echo "  ./fda logs           View logs"
echo "========================"
