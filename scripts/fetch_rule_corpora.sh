#!/bin/bash
#=============================================================================
# SocEyes — Rule Corpus Fetcher
#
# Fetches the vendored detection corpora (gitignored, mounted at runtime):
#   - SigmaHQ/sigma                     -> sigma/           (community Sigma rules)
#   - elastic/detection-rules           -> detection-rules/ (Elastic TOML rules)
#   - wazuh/wazuh-ruleset               -> wazuh-ruleset/  (Wazuh detection rules XML)
#   - panther-labs/panther-analysis     -> panther-analysis/ (Panther rules)
#
# Tries a shallow git clone first, then falls back to a GitHub codeload
# tarball (works where git-over-HTTPS is blocked). Only fetches what is
# missing, so it is safe to re-run. Skip one with SOC_SKIP_<NAME>=1.
#
# Usage: ./scripts/fetch_rule_corpora.sh
#=============================================================================
set -euo pipefail

SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SOC_DIR"

BRANCH="${SOC_CORPORA_BRANCH:-master}"

fetch() {
    local name="$1" url="$2" dir="$3"
    if [ "${4:-0}" = "skip" ]; then
        echo "[!] $name skipped (SOC_SKIP_${name^^}=1)"
        return 0
    fi
    if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
        echo "[✓] $name already present ($dir)"
        return 0
    fi
    echo "[*] Fetching $name ..."
    if git clone --depth 1 --single-branch "$url" "$dir" 2>/dev/null; then
        rm -rf "$dir/.git"
        echo "[✓] $name fetched (git) -> $dir"
        return 0
    fi
    # Fallback: codeload tarball (no git auth needed).
    local repo="${url#https://github.com/}" tmp="/tmp/${name}.tar.gz"
    for branch in "$BRANCH" main; do
        if curl -fsSL --max-time 300 -o "$tmp" "https://github.com/${repo}/archive/refs/heads/${branch}.tar.gz" 2>/dev/null; then
            mkdir -p "$dir"
            if tar xzf "$tmp" -C "$dir" --strip-components=1 2>/dev/null; then
                rm -f "$tmp"
                echo "[✓] $name fetched (tarball, branch=$branch) -> $dir"
                return 0
            fi
            rmdir "$dir" 2>/dev/null || true
        fi
    done
    echo "[!] Failed to fetch $name ($url) — detection coverage reduced" >&2
    return 1
}

failures=0

fetch "Sigma"        "https://github.com/SigmaHQ/sigma.git"                      "sigma"            "${SOC_SKIP_SIGMA:-0}"    || failures=$((failures+1))
fetch "Elastic"      "https://github.com/elastic/detection-rules.git"            "detection-rules"  "${SOC_SKIP_ELASTIC:-0}"  || failures=$((failures+1))
fetch "Wazuh"        "https://github.com/wazuh/wazuh-ruleset.git"                "wazuh-ruleset"    "${SOC_SKIP_WAZUH:-0}"    || failures=$((failures+1))
fetch "Panther"      "https://github.com/panther-labs/panther-analysis.git"      "panther-analysis" "${SOC_SKIP_PANTHER:-0}"  || failures=$((failures+1))

echo ""
if [ "$failures" -gt 0 ]; then
    echo "Completed with $failures fetch failure(s). Re-run to retry." >&2
    exit 1
fi
echo "All rule corpora present."
