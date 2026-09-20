"""Capture detection: real-time alert generation from Go-agent packet events.

Extracted from main.py so the API layer stays thin. Owns two detection phases:

1. Port-scan detection over capture-agent packets (distinct TCP destination
   ports per source inside a sliding window, with a per-source cooldown).
2. Rule matching: IDS alerts (suricata / wazuh / elastic indices) are matched
   against the indexed detection-rule catalog via MITRE technique lookup, and
   each match produces one correlated alert with a response preview.

Correctness rules enforced here:
- Events are fetched by watermark (last processed timestamp), persisted in
  state_kv, so restarts never replay old events into duplicate alerts.
- Synthetic events produced by this module are stored under the fda-internal
  source so phase 2 never re-ingests its own output (no feedback loops).
- Port-scan alerts are rate-limited per source (SCAN_COOLDOWN_SEC) and
  require burst density: the distinct ports must be touched within a short
  sub-burst (SCAN_BURST_SEC). Ambient traffic spreads over the window and
  does not alert; scans do.

Logs under "fda.services.capture_detection".
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from datetime import datetime, timezone

from app_shared.response_policy import action_detail, choose_action, render_command_preview
from app_shared.state_paths import state_path
from app_shared.unified_store import get_kv, query_events, set_kv, store_alert, store_event

logger = logging.getLogger("fda.services.capture_detection")

_CAPTURE_DETECT_RUNNING = threading.Event()
_capture_detect_thread: threading.Thread | None = None

# --- port-scan detection tuning -------------------------------------------
# All knobs env-tunable so operators can match their traffic profile without
# a redeploy (correlation tuning).
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


_SCAN_WINDOW_SEC = _env_int("FDA_SCAN_WINDOW_SEC", 60)       # sliding window for distinct-port counting
_SCAN_PORT_THRESHOLD = _env_int("FDA_SCAN_PORT_THRESHOLD", 20)  # distinct TCP dst ports in window => scan
_SCAN_BURST_SEC = _env_int("FDA_SCAN_BURST_SEC", 15)         # those ports must be touched within this burst
_SCAN_COOLDOWN_SEC = _env_int("FDA_SCAN_COOLDOWN_SEC", 300)  # min seconds between alerts for the same source
_SCAN_READ_LIMIT = _env_int("FDA_SCAN_READ_LIMIT", 20000)    # max events read per detector pass
# Loopback-to-loopback traffic is local service chatter, not reconnaissance;
# counting it false-positives constantly on busy hosts. Disable suppression
# only when deliberately testing scan detection on loopback.
_SCAN_SUPPRESS_LOOPBACK = os.environ.get("FDA_SCAN_SUPPRESS_LOOPBACK", "true").lower() in ("true", "1", "yes")

# --- rule-match phase tuning ----------------------------------------------
_MATCH_WATERMARK_KEY = "capture_detection.match_watermark"
_MATCH_BATCH_LIMIT = 100

_scan_state_lock = threading.Lock()
# src_ip -> (window_start_epoch, last_alert_epoch, [(ts, dst_port), ...])
_scan_windows: dict[str, tuple[float, float, list[tuple[float, int]]]] = {}

_SEVERITY_ORDER_SQL = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 ELSE 3 END"
)


def _detect_from_capture_loop() -> None:
    """Scan capture-agent events for suspicious patterns and match IDS alerts against indexed rules."""
    logger.info("Capture detection loop started")

    while _CAPTURE_DETECT_RUNNING.is_set():
        try:
            _detect_port_scans()
            _match_alerts_to_rules()
        except Exception as exc:
            logger.warning("Capture detection error: %s", exc)

        time.sleep(10)


def _parse_event_ts(value) -> float:
    """Parse an event timestamp to epoch seconds; fall back to now."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, AttributeError):
        return time.time()


def _detect_port_scans() -> None:
    """Detect port scans from recent capture-agent TCP packets.

    Maintains a sliding per-source list of (timestamp, dst port) probes.
    An alert fires when the source touches at least SCAN_PORT_THRESHOLD
    distinct ports inside a SCAN_BURST_SEC sub-burst (scans are dense;
    ambient traffic is not) and the source has not alerted within
    SCAN_COOLDOWN_SEC.
    """
    # Time-windowed read, not count-limited: on a busy network the newest
    # 500 events can cover barely a second of traffic, so scans would scroll
    # past unseen. Pull everything inside the scan window (bounded by
    # _SCAN_READ_LIMIT; the idx_events_src_ts index makes this a range scan).
    window_start_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=_SCAN_WINDOW_SEC)
    ).isoformat()
    events = query_events(sources=["capture"], start=window_start_iso, limit=_SCAN_READ_LIMIT)
    if not events:
        return
    # query_events returns newest-first; the window logic below assumes
    # chronological order (window_start comes from the FIRST packet seen).
    # Sort ascending by parsed timestamp so a newest-first feed cannot
    # poison the window with a single future-dated probe.
    events = sorted(events, key=lambda ev: _parse_event_ts(ev.get("timestamp")))

    now = time.time()
    cutoff = now - _SCAN_WINDOW_SEC

    with _scan_state_lock:
        for ev in events:
            ev_ts = _parse_event_ts(ev.get("timestamp"))
            if ev_ts < cutoff:
                continue
            src_ip = ev.get("source_ip", "") or ""
            dst_ip = ev.get("destination_ip", "") or ""
            dst_port = ev.get("destination_port") or 0
            proto = (ev.get("protocol", "") or ev.get("network_transport", "") or "").upper()
            if not src_ip or src_ip == "0.0.0.0" or not dst_port:
                continue
            if _SCAN_SUPPRESS_LOOPBACK and (
                src_ip.startswith("127.") and dst_ip.startswith("127.")
            ):
                continue  # local service chatter, not reconnaissance
            if proto and proto not in ("TCP", "TCP6"):
                continue
            entry = _scan_windows.get(src_ip)
            if entry is None:
                _scan_windows[src_ip] = (ev_ts, 0.0, [(ev_ts, dst_port)])
                continue
            window_start, last_alert, probes = entry
            if ev_ts < window_start:
                continue  # packet predates the current window
            probes.append((ev_ts, dst_port))

        for src_ip in list(_scan_windows.keys()):
            window_start, last_alert, probes = _scan_windows[src_ip]
            # Prune to the sliding window.
            probes = [tp for tp in probes if tp[0] >= now - _SCAN_WINDOW_SEC]
            distinct = len({p for _, p in probes})
            burst = _max_burst_distinct(probes, _SCAN_BURST_SEC)
            if burst >= _SCAN_PORT_THRESHOLD and now - last_alert >= _SCAN_COOLDOWN_SEC:
                _emit_port_scan_alert(src_ip, distinct, burst)
                # Fresh window + cooldown stamp so counting restarts cleanly.
                _scan_windows[src_ip] = (now, now, [])
            else:
                _scan_windows[src_ip] = (window_start, last_alert, probes)


def _max_burst_distinct(probes: list[tuple[float, int]], burst_sec: float) -> int:
    """Max distinct ports touched within any sliding burst_sec sub-window.

    Two-pointer sweep over time-sorted probes: O(n) per source per cycle.
    """
    if not probes:
        return 0
    ordered = sorted(probes)
    counts: dict[int, int] = {}
    best = 0
    left = 0
    for right, (ts, port) in enumerate(ordered):
        counts[port] = counts.get(port, 0) + 1
        while ts - ordered[left][0] > burst_sec:
            lport = ordered[left][1]
            counts[lport] -= 1
            if counts[lport] == 0:
                del counts[lport]
            left += 1
        if len(counts) > best:
            best = len(counts)
    return best


def _emit_port_scan_alert(src_ip: str, port_count: int, burst: int) -> None:
    severity = "medium" if port_count < 50 else "high"
    title = "Port scan reconnaissance (T1046)"
    technique_id = "T1046"
    tech = [technique_id]
    ts = datetime.now(timezone.utc).isoformat()
    message = (
        f"{port_count} distinct TCP ports probed by {src_ip} within "
        f"{_SCAN_WINDOW_SEC}s ({burst} within a {_SCAN_BURST_SEC}s burst; "
        f"packet capture)."
    )

    # fda-internal source: detection output must never be re-ingested as input.
    store_event(
        "fda-internal", "fda-detection",
        engine="fda-internal",
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
        message=message,
        rule_id=f"CAPTURE-{technique_id}",
        source_ip=src_ip,
        technique_ids=tech,
        response_preview=preview,
        timestamp=ts,
    )
    logger.info("Port scan detected: %s probed %d TCP ports -> alert CAPTURE-%s",
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
    """Map each alert id to candidate detection rules via technique lookup.

    Sub-techniques (T1059.001) resolve to parents (T1059). Candidates are
    ordered by severity so the strongest rule wins when capped to one match.
    """
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

            parent_techs = {t.split(".")[0] if "." in t else t for t in tech_ids}

            rule_rows: list[sqlite3.Row] = []
            seen_rules: set[str] = set()
            for parent in parent_techs:
                cursor.execute(
                    "SELECT rule_id, title, description, severity, technique_ids FROM rules "
                    "WHERE technique_ids LIKE '%' || ? || '%' "
                    f"ORDER BY {_SEVERITY_ORDER_SQL} LIMIT 5",
                    [parent],
                )
                for row in cursor.fetchall():
                    if row["rule_id"] not in seen_rules:
                        seen_rules.add(row["rule_id"])
                        rule_rows.append(row)
            if rule_rows:
                alert_to_rules[alert_id] = rule_rows
        return alert_to_rules
    finally:
        conn.close()


def _match_alerts_to_rules() -> None:
    """Match recent IDS alerts against the indexed detection-rule catalog.

    Uses a persisted timestamp watermark so each IDS alert is processed
    exactly once across loop iterations and process restarts. Each IDS alert
    produces at most ONE correlated alert (the strongest matching rule).
    """
    watermark = str(get_kv(_MATCH_WATERMARK_KEY, "") or "")
    ids_alerts = query_events(
        sources=["suricata", "wazuh", "elastic"],
        start=watermark or None,
        limit=_MATCH_BATCH_LIMIT,
    )
    if not ids_alerts:
        return

    # Strict watermark: skip events at or before the last processed timestamp
    # (start filter is inclusive, and identical timestamps can span batches).
    if watermark:
        ids_alerts = [a for a in ids_alerts if str(a.get("timestamp", "")) > watermark]

    # Capture-agent events provide network context enrichment
    capture_events = query_events(sources=["capture"], limit=100)
    ip_ports: dict[str, set[int]] = {}
    for ev in capture_events:
        src = ev.get("source_ip", "") or ""
        port = ev.get("destination_port") or 0
        if src and src != "0.0.0.0" and port:
            ip_ports.setdefault(src, set()).add(port)

    db_path = state_path("fda_events.sqlite")
    if not db_path or not os.path.exists(db_path):
        return

    matched_rules: set[str] = set()
    matched_alerts: set[str] = set()

    try:
        alert_to_rules = _load_rule_matches(db_path, ids_alerts, matched_alerts)

        max_ts = watermark
        for alert in ids_alerts:
            alert_ts = str(alert.get("timestamp", ""))
            if alert_ts > max_ts:
                max_ts = alert_ts

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
            ts = alert_ts or datetime.now(timezone.utc).isoformat()

            # One correlated alert per IDS alert: the strongest candidate rule.
            rule = candidate_rules[0]
            rule_id_matched = rule["rule_id"]
            if rule_id_matched and rule_id_matched not in matched_rules:
                matched_rules.add(rule_id_matched)

                tech_ids_rule = _parse_technique_ids(rule["technique_ids"])
                severity = rule["severity"] or "medium"
                rule_title = rule["title"] or rule_id_matched
                rule_desc = rule["description"] or ""

                alert_title = f"{rule_title} (matched from IDS alert)"
                port_count = len(ip_ports.get(source_ip, set()))
                port_context = f" (scanning {port_count} ports)" if port_count > 5 else ""
                alert_message = (
                    f"Detection rule '{rule_id_matched}' matched IDS alert via technique {tech_ids[0]}. "
                    f"Rule: {rule_desc[:200]}. "
                    f"Source: {source_ip or 'unknown'}, Host: {host_name or 'unknown'}{port_context}."
                )

                # fda-internal source: enrichment output is never re-ingested.
                store_event(
                    "fda-internal", "fda-detection",
                    engine="fda-internal",
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
                logger.info("Rule match: %s -> IDS from %s (rule %s, tech %s)",
                            alert_title, source_ip or "unknown", rule_id_matched, tech_ids[0])

            matched_alerts.add(alert_id)

        if max_ts and max_ts != watermark:
            set_kv(_MATCH_WATERMARK_KEY, max_ts)

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
    logger.info("Capture detection loop started (port scans + rule matching)")


def stop_capture_detection() -> None:
    """Stop the capture event detection loop."""
    _CAPTURE_DETECT_RUNNING.clear()
    logger.info("Capture detection loop stopped")
