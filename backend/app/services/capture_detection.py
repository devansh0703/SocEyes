"""Capture detection: real-time alert generation from Go-agent packet events.

Extracted from main.py. The detection loop scans recent capture-agent events
for suspicious patterns (port scans) and cross-matches IDS alerts against the
indexed detection-rule catalog. Logs under "fda.services.capture_detection".
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

from app_shared.response_policy import action_detail, choose_action, render_command_preview
from app_shared.state_paths import state_path
from app_shared.unified_store import query_events, store_alert, store_event

logger = logging.getLogger("fda.services.capture_detection")

_CAPTURE_DETECT_RUNNING = threading.Event()
_capture_detect_thread: threading.Thread | None = None
_capture_detect_cursor: int = 0  # Last processed event ID


def _detect_from_capture_loop() -> None:
    """Scan capture-agent events for suspicious patterns and match against indexed rules."""
    logger.info("Capture detection loop started")

    while _CAPTURE_DETECT_RUNNING.is_set():
        try:
            # Phase 1: Detect port scans from capture-agent events
            events = query_events(sources=["capture-agent"], start=None, end=None, limit=500)

            if events:
                ip_port_map: dict[str, set[int]] = {}
                ip_event_count: dict[str, int] = {}

                for ev in events:
                    src_ip = ev.get("source_ip", "")
                    if not src_ip or src_ip == "0.0.0.0":
                        continue
                    port = ev.get("destination_port") or 0
                    ip_port_map.setdefault(src_ip, set()).add(port)
                    ip_event_count[src_ip] = ip_event_count.get(src_ip, 0) + 1

                # Detect port scans: many distinct ports from one IP
                for src_ip, ports in ip_port_map.items():
                    if len(ports) >= 20:  # 20+ distinct ports = port scan
                        _emit_port_scan_alert(src_ip, len(ports), ip_event_count[src_ip])

            # Phase 2: Match ALL recent events (capture + IDS alerts) against indexed rules
            _match_events_to_rules()

        except Exception as exc:
            logger.warning("Capture detection error: %s", exc)

        time.sleep(10)  # Scan every 10 seconds


def _emit_port_scan_alert(src_ip: str, port_count: int, event_count: int) -> None:
    severity = "medium" if port_count < 50 else "high"
    title = "Port scan reconnaissance (T1046)"
    technique_id = "T1046"
    tech = [technique_id]
    ts = datetime.now(timezone.utc).isoformat()
    message = (
        f"Detected {port_count} distinct ports scanned from {src_ip} across "
        f"{event_count} capture events. Real detection from Go agent packet capture."
    )

    store_event(
        "suricata", "fda-capture-detection",
        engine="suricata",
        title=title,
        message=message,
        severity=severity,
        rule_id=f"CAPTURE-{technique_id}",
        source_ip=src_ip,
        technique_ids=tech,
        timestamp=ts,
    )
    store_event(
        "elastic", ".alerts-security.alerts-fda",
        engine="elastic",
        title=title,
        message=message,
        severity=severity,
        rule_id=f"CAPTURE-{technique_id}",
        source_ip=src_ip,
        technique_ids=tech,
        timestamp=ts,
    )

    action = choose_action(tech)
    detail = action_detail(action)
    preview = {
        "title": detail["title"],
        "summary": detail["summary"],
        "preview_command": render_command_preview(
            action, {"source_ip": src_ip, "rule_id": f"CAPTURE-{technique_id}", "technique_id": technique_id}
        ),
        "success_criteria": f"{src_ip} is present in the runtime blocklist.",
    }
    store_alert(
        "correlated", severity, title,
        message=f"{title} — Detected by real-time capture analysis from Go agent packets.",
        rule_id=f"CAPTURE-{technique_id}",
        source_ip=src_ip,
        technique_ids=tech,
        response_preview=preview,
        timestamp=ts,
    )
    logger.info("Capture detection: port scan from %s (%d ports) -> alert CAPTURE-%s",
                src_ip, port_count, technique_id)


def _parse_technique_ids(raw) -> list[str]:
    """technique_ids arrives as JSON string or list depending on the store path."""
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            return []
    if isinstance(raw, list):
        return raw
    return []


def _load_rule_matches(db_path, ids_alerts, matched_alerts) -> dict[str, list[sqlite3.Row]]:
    """Map each alert id to candidate detection rules via parent-technique lookup."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        alert_to_rules: dict[str, list[sqlite3.Row]] = {}
        for alert in ids_alerts:
            alert_id = alert.get("id", "")
            if not alert_id or alert_id in matched_alerts:
                continue
            tech_ids = _parse_technique_ids(alert.get("technique_ids", "[]") or "[]")
            if not tech_ids:
                continue

            # Resolve sub-techniques (T1059.001) to parents (T1059) for matching
            parent_techs = {t.split(".")[0] if "." in t else t for t in tech_ids}

            rule_rows: list[sqlite3.Row] = []
            for parent in parent_techs:
                cursor.execute(
                    "SELECT rule_id, title, description, severity, technique_ids FROM rules "
                    "WHERE technique_ids LIKE '%' || ? || '%' LIMIT 5",
                    [parent],
                )
                rule_rows.extend(cursor.fetchall())
            alert_to_rules[alert_id] = rule_rows
        return alert_to_rules
    finally:
        conn.close()


def _match_events_to_rules() -> None:
    """Match recent IDS alerts against all indexed detection rules.

    Queries alerts from suricata/wazuh/elastic (which carry technique_ids) and
    matches them to detection rules via parent-technique resolution.
    Sub-techniques like T1059.001 resolve to parent T1059 for rule matching.

    This wires all indexed rules (Elastic + Panther + Sigma) into live detection.
    """
    matched_rules: set[str] = set()
    matched_alerts: set[str] = set()

    ids_alerts = query_events(sources=["suricata", "wazuh", "elastic"], start=None, end=None, limit=100, query="")
    if not ids_alerts:
        return

    # Capture-agent events provide network context enrichment
    capture_events = query_events(sources=["capture-agent"], start=None, end=None, limit=100, query="")
    ip_ports: dict[str, set[int]] = {}
    for ev in capture_events:
        src = ev.get("source_ip", "") or ""
        port = ev.get("destination_port") or 0
        if src and src != "0.0.0.0" and port:
            ip_ports.setdefault(src, set()).add(port)

    db_path = state_path("fda_events.sqlite")
    if not db_path or not os.path.exists(db_path):
        return

    try:
        alert_to_rules = _load_rule_matches(db_path, ids_alerts, matched_alerts)

        for alert in ids_alerts:
            alert_id = alert.get("id", "")
            if not alert_id or alert_id in matched_alerts:
                continue
            candidate_rules = alert_to_rules.get(alert_id) or []
            if not candidate_rules:
                continue

            tech_ids = _parse_technique_ids(alert.get("technique_ids", "[]") or "[]")
            if not tech_ids:
                continue

            source_ip = alert.get("source_ip", "") or ""
            dest_ip = alert.get("destination_ip", "") or ""
            host_name = alert.get("host_name", "") or ""
            ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

            port_count = len(ip_ports.get(source_ip, set()))
            port_context = f" (scanning {port_count} ports)" if port_count > 5 else ""

            for rule in candidate_rules:
                rule_id_matched = rule["rule_id"]
                if not rule_id_matched or rule_id_matched in matched_rules:
                    continue
                matched_rules.add(rule_id_matched)

                tech_ids_rule = json.loads(rule["technique_ids"]) if rule["technique_ids"] else []
                severity = rule["severity"] or "medium"
                rule_title = rule["title"] or rule_id_matched
                rule_desc = rule["description"] or ""

                alert_title = f"{rule_title} (matched from IDS alert)"
                alert_message = (
                    f"Detection rule '{rule_id_matched}' matched IDS alert via technique {tech_ids[0]}. "
                    f"Rule: {rule_desc[:200]}. "
                    f"Source: {source_ip or 'unknown'}, Host: {host_name or 'unknown'}{port_context}. "
                    f"Cross-matched against {len(matched_rules)} indexed detection rules."
                )

                store_event(
                    "suricata", ".alerts-security.alerts-fda",
                    engine="suricata",
                    title=alert_title,
                    message=alert_message,
                    severity=severity,
                    rule_id=rule_id_matched,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    host_name=host_name,
                    technique_ids=tech_ids_rule,
                    timestamp=ts,
                )

                action = choose_action(tech_ids_rule)
                detail = action_detail(action)
                preview = {
                    "title": detail["title"],
                    "summary": detail["summary"],
                    "preview_command": render_command_preview(
                        action,
                        {"source_ip": source_ip, "destination_ip": dest_ip, "rule_id": rule_id_matched,
                         "technique_id": tech_ids_rule[0] if tech_ids_rule else "", "host_name": host_name},
                    ),
                    "success_criteria": f"{source_ip or dest_ip or 'target'} is present in the runtime blocklist.",
                }
                store_alert(
                    "correlated", severity, alert_title,
                    message=alert_message,
                    rule_id=rule_id_matched,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    technique_ids=tech_ids_rule,
                    response_preview=preview,
                    timestamp=ts,
                )
                matched_alerts.add(alert_id)
                logger.info("Rule match: %s -> IDS from %s (rule %s, tech %s)",
                            alert_title, source_ip or "unknown", rule_id_matched, tech_ids[0])

    except Exception as exc:
        logger.warning("Rule matching SQLite error: %s", exc)


def start_capture_detection() -> None:
    """Start the capture event detection loop."""
    global _capture_detect_thread
    if _capture_detect_thread and _capture_detect_thread.is_alive():
        return
    _CAPTURE_DETECT_RUNNING.set()
    _capture_detect_thread = threading.Thread(
        target=_detect_from_capture_loop, daemon=True, name="capture-detection"
    )
    _capture_detect_thread.start()
    logger.info("Capture detection loop started (scanning for port scans, brute force)")


def stop_capture_detection() -> None:
    """Stop the capture event detection loop."""
    _CAPTURE_DETECT_RUNNING.clear()
    logger.info("Capture detection loop stopped")
