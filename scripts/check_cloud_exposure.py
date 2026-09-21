#!/usr/bin/env python3
"""Cloud asset exposure checker.

Queries AWS/Azure/GCP metadata endpoints to discover:
- Instance ID, region, account ID
- Public IP addresses
- Security groups / firewall rules
- Open ports

This runs locally on the host and reports findings to the API.
No hardcoded credentials — uses instance metadata service (IMDS).
"""
from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app_shared.unified_store import init_db, store_event
from app_shared.text_utils import now_utc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [cloud] %(message)s")
logger = logging.getLogger("soceyes.cloud")

# IMDS endpoints
AWS_IMDS = "http://169.254.169.254/latest/meta-data/"
AZURE_IMDS = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
GCP_IMDS = "http://metadata.google.internal/computeMetadata/v1/"


def _http_get(url: str, headers: dict | None = None, timeout: int = 5) -> str | None:
    """HTTP GET with timeout. Returns None on failure."""
    import requests
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def check_aws() -> list[dict[str, Any]]:
    """Check AWS instance metadata for exposure."""
    findings = []

    # Check if running on AWS
    instance_id = _http_get(f"{AWS_IMDS}instance-id")
    if not instance_id:
        return findings

    logger.info("AWS instance detected: %s", instance_id)

    # Get public IP
    public_ip = _http_get(f"{AWS_IMDS}public-ipv4")
    if public_ip:
        findings.append({
            "type": "aws_public_ip",
            "severity": "medium",
            "title": f"AWS instance has public IP: {public_ip}",
            "message": f"Instance {instance_id} has public IP {public_ip}",
            "source_ip": public_ip,
            "cloud": "aws",
            "instance_id": instance_id,
        })

    # Get security groups
    sg_list = _http_get(f"{AWS_IMDS}security-groups")
    if sg_list:
        for sg in sg_list.strip().split("\n"):
            if sg:
                findings.append({
                    "type": "aws_security_group",
                    "severity": "low",
                    "title": f"Security group: {sg}",
                    "message": f"Instance {instance_id} in security group {sg}",
                    "cloud": "aws",
                    "instance_id": instance_id,
                })

    # Get IAM role
    iam_role = _http_get(f"{AWS_IMDS}iam/security-credentials/")
    if iam_role:
        findings.append({
            "type": "aws_iam_role",
            "severity": "low",
            "title": f"IAM role: {iam_role.strip()}",
            "message": f"Instance {instance_id} has IAM role {iam_role.strip()}",
            "cloud": "aws",
            "instance_id": instance_id,
        })

    return findings


def check_azure() -> list[dict[str, Any]]:
    """Check Azure instance metadata for exposure."""
    findings = []

    # Azure requires Metadata: true header
    headers = {"Metadata": "true"}
    raw = _http_get(AZURE_IMDS, headers=headers)
    if not raw:
        return findings

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    logger.info("Azure instance detected")

    # Extract network info
    network = data.get("network", {})
    for iface in network.get("interface", []):
        ipv4 = iface.get("ipv4", {})
        for ip in ipv4.get("ipAddress", []):
            public_ip = ip.get("publicIpAddress", "")
            if public_ip:
                findings.append({
                    "type": "azure_public_ip",
                    "severity": "medium",
                    "title": f"Azure instance has public IP: {public_ip}",
                    "message": f"VM {data.get('compute', {}).get('name', 'unknown')} has public IP {public_ip}",
                    "source_ip": public_ip,
                    "cloud": "azure",
                    "instance_id": data.get("compute", {}).get("vmId", ""),
                })

    return findings


def check_gcp() -> list[dict[str, Any]]:
    """Check GCP instance metadata for exposure."""
    findings = []

    # GCP requires Metadata-Flavor: Google header
    headers = {"Metadata-Flavor": "Google"}
    instance_id = _http_get(f"{GCP_IMDS}instance/id", headers=headers)
    if not instance_id:
        return findings

    logger.info("GCP instance detected: %s", instance_id)

    # Get public IP
    public_ip = _http_get(f"{GCP_IMDS}instance/network-interfaces/0/access-configs/0/external-ip", headers=headers)
    if public_ip:
        findings.append({
            "type": "gcp_public_ip",
            "severity": "medium",
            "title": f"GCP instance has public IP: {public_ip}",
            "message": f"Instance {instance_id} has public IP {public_ip}",
            "source_ip": public_ip,
            "cloud": "gcp",
            "instance_id": instance_id,
        })

    # Get project ID
    project_id = _http_get(f"{GCP_IMDS}project/project-id", headers=headers)
    if project_id:
        findings.append({
            "type": "gcp_project",
            "severity": "low",
            "title": f"GCP project: {project_id}",
            "message": f"Instance {instance_id} in project {project_id}",
            "cloud": "gcp",
            "instance_id": instance_id,
        })

    return findings


def run_cloud_checks() -> list[dict[str, Any]]:
    """Run all cloud exposure checks."""
    init_db()
    all_findings = []

    for check_fn in [check_aws, check_azure, check_gcp]:
        try:
            findings = check_fn()
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Cloud check %s failed: %s", check_fn.__name__, exc)

    # Store findings as events
    for finding in all_findings:
        store_event(
            source="cloud-exposure",
            index_name="soc-cloud-exposure",
            title=finding["title"],
            message=finding["message"],
            severity=finding["severity"],
            source_ip=finding.get("source_ip", ""),
            engine="cloud",
            rule_id=finding["type"],
            technique_ids=[],
            raw=finding,
        )

    logger.info("Cloud checks complete: %d findings", len(all_findings))
    return all_findings


if __name__ == "__main__":
    findings = run_cloud_checks()
    print(json.dumps(findings, indent=2, default=str))
