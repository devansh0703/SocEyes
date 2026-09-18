#!/bin/bash
#=============================================================================
# FDA Cyber Control — Wazuh Rules Installer

# Downloads and installs the latest Wazuh rules, decoders, and SCA policies
# from the official Wazuh repository when wazuh-manager is installed.

set -euo pipefail

WAZUH_RULES_VERSION="4.14.4"
WAZUH_RULES_URL="https://github.com/wazuh/wazuh-ruleset/archive/refs/tags/v${WAZUH_RULES_VERSION}.tar.gz"

FDA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSSEC_DIR="/var/ossec"

if [ ! -d "$OSSEC_DIR" ]; then
    echo "Wazuh manager not installed. Install with: sudo apt install wazuh-manager"
    exit 1
fi

echo "Installing Wazuh rules from v${WAZUH_RULES_VERSION}..."

# Download ruleset
TMPDIR=$(mktemp -d)
wget -q "$WAZUH_RULES_URL" -O "$TMPDIR/wazuh-ruleset.tar.gz"
tar xzf "$TMPDIR/wazuh-ruleset.tar.gz" -C "$TMPDIR"

# Copy rules
if [ -d "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/rules" ]; then
    cp -r "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/rules/"* "$OSSEC_DIR/etc/rules/"
    echo "  Rules installed"
fi

# Copy decoders
if [ -d "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/decoders" ]; then
    cp -r "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/decoders/"* "$OSSEC_DIR/etc/decoders/"
    echo "  Decoders installed"
fi

# Copy SCA policies
if [ -d "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/sca" ]; then
    cp -r "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/sca/"* "$OSSEC_DIR/etc/shared/"
    echo "  SCA policies installed"
fi

# Copy rootchecks
if [ -d "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/rootchecks" ]; then
    cp -r "$TMPDIR/wazuh-ruleset-${WAZUH_RULES_VERSION}/rootchecks/"* "$OSSEC_DIR/etc/shared/"
    echo "  Rootchecks installed"
fi

# Cleanup
rm -rf "$TMPDIR"

# Set ownership
chown -R wazuh:wazuh "$OSSEC_DIR/etc/" 2>/dev/null || true

echo "Wazuh rules installation complete!"
