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
- Synthetic events produced by this module are stored under the soc-internal
  source so phase 2 never re-ingests its own output (no feedback loops).
- Port-scan alerts are rate-limited per source (SCAN_COOLDOWN_SEC) and
  require burst density: the distinct ports must be touched within a short
  sub-burst (SCAN_BURST_SEC). Ambient traffic spreads over the window and
  does not alert; scans do.

Logs under "soceyes.services.capture_detection".
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from app_shared.response_policy import action_detail, choose_action, render_command_preview
from app_shared.state_paths import state_path
from app_shared.unified_store import exfil_volumes, get_kv, query_events, set_kv, store_alert, store_event

logger = logging.getLogger("soceyes.services.capture_detection")

_CAPTURE_DETECT_RUNNING = threading.Event()
_capture_detect_thread: threading.Thread | None = None

# --- port-scan detection tuning -------------------------------------------
# All knobs env-tunable so operators can match their traffic profile without
# a redeploy (correlation tuning).
# Legacy note: pre-rebrand deployments set SOC_* names; both are honored
# (SOC_* wins) so existing systemd units and compose files keep working.
def _env(name: str, default: str) -> str:
    return os.environ.get(name) or os.environ.get(name.replace("SOC_", "SOC_", 1)) or default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


_SCAN_WINDOW_SEC = _env_int("SOC_SCAN_WINDOW_SEC", 60)       # sliding window for distinct-port counting
_SCAN_PORT_THRESHOLD = _env_int("SOC_SCAN_PORT_THRESHOLD", 20)  # distinct TCP dst ports in window => scan
_SCAN_BURST_SEC = _env_int("SOC_SCAN_BURST_SEC", 15)         # those ports must be touched within this burst
_SCAN_COOLDOWN_SEC = _env_int("SOC_SCAN_COOLDOWN_SEC", 300)  # min seconds between alerts for the same source
_SCAN_READ_LIMIT = _env_int("SOC_SCAN_READ_LIMIT", 20000)    # max events read per detector pass
# Loopback-to-loopback traffic is local service chatter, not reconnaissance;
# counting it false-positives constantly on busy hosts. Disable suppression
# only when deliberately testing scan detection on loopback.
_SCAN_SUPPRESS_LOOPBACK = os.environ.get("SOC_SCAN_SUPPRESS_LOOPBACK", "true").lower() in ("true", "1", "yes")

# Self-block safety net: the local host's own addresses (learned at loop
# start from the routing table) are never emitted as scan sources. A
# self-inflicted nftables block of the API host takes the whole console
# down with it — including the rollback sweeper.
_self_ips: set[str] = set()


def _refresh_self_ips() -> None:
    try:
        import socket
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            _self_ips.add(info[4][0])
        _self_ips.add("127.0.0.1")
    except OSError:
        pass

# --- SSH brute-force detection tuning ---------------------------------------
# Repeated connection attempts to a single SSH port: real logins are rare;
# credential-stuffing retries dozens of times per minute.
_BRUTE_WINDOW_SEC = _env_int("SOC_BRUTE_WINDOW_SEC", 120)     # sliding window for attempts
_BRUTE_THRESHOLD = _env_int("SOC_BRUTE_THRESHOLD", 15)        # SYN attempts to port 22 => brute force
_BRUTE_COOLDOWN_SEC = _env_int("SOC_BRUTE_COOLDOWN_SEC", 300)

# --- SYN flood detection tuning ---------------------------------------------
# Half-open SYN storm against one port: more than N SYNs/sec to a single
# dst port with no completed handshakes observed is a flood signature.
_FLOOD_WINDOW_SEC = _env_int("SOC_FLOOD_WINDOW_SEC", 10)
_FLOOD_THRESHOLD = _env_int("SOC_FLOOD_THRESHOLD", 100)       # SYNs to one port within window
_FLOOD_COOLDOWN_SEC = _env_int("SOC_FLOOD_COOLDOWN_SEC", 300)

# --- C2 beaconing detection tuning -----------------------------------------
# A command-and-control implant checks in on a fixed schedule. Random human
# traffic has irregular timing; beacon flows show near-constant intervals
# (low jitter) across many connections inside the window.
_BEACON_WINDOW_SEC = _env_int("SOC_BEACON_WINDOW_SEC", 600)     # analysis window
_BEACON_MIN_CONNECTIONS = _env_int("SOC_BEACON_MIN_CONNECTIONS", 8)  # SYNs per flow
_BEACON_MAX_JITTER = 0.25 if not (os.environ.get("SOC_BEACON_MAX_JITTER") or os.environ.get("SOC_BEACON_MAX_JITTER")) else float(os.environ.get("SOC_BEACON_MAX_JITTER") or os.environ.get("SOC_BEACON_MAX_JITTER"))
_BEACON_MIN_INTERVAL_SEC = 0.5    # below this, regularity is keepalive chatter
_BEACON_MAX_INTERVAL_SEC = 3600.0
_BEACON_COOLDOWN_SEC = _env_int("SOC_BEACON_COOLDOWN_SEC", 1800)

# --- data exfiltration tuning -----------------------------------------------
# One source pushing an unusual volume to a single destination inside the
# window: staging + upload, or a compromised host streaming data out.
_EXFIL_WINDOW_SEC = _env_int("SOC_EXFIL_WINDOW_SEC", 60)
_EXFIL_BYTES_THRESHOLD = _env_int("SOC_EXFIL_BYTES_THRESHOLD", 100_000_000)  # 100 MB / window
_EXFIL_COOLDOWN_SEC = _env_int("SOC_EXFIL_COOLDOWN_SEC", 600)

# --- rule-match phase tuning ----------------------------------------------
_MATCH_WATERMARK_KEY = "capture_detection.match_watermark"
_MATCH_BATCH_LIMIT = 100

_scan_state_lock = threading.Lock()
# src_ip -> (window_start_epoch, last_alert_epoch, [(ts, dst_port), ...])
_scan_windows: dict[str, tuple[float, float, list[tuple[float, int]]]] = {}

_brute_state_lock = threading.Lock()
# src_ip -> (last_alert_epoch, [attempt_epochs])  (attempts = SYNs to SSH port)
_brute_windows: dict[str, tuple[float, list[float]]] = {}

_flood_state_lock = threading.Lock()
# (src_ip, dst_port) -> (last_alert_epoch, [syn_epochs])
_flood_windows: dict[tuple[str, int], tuple[float, list[float]]] = {}

_beacon_state_lock = threading.Lock()
# (src_ip, dst_ip, dst_port) -> last_alert_epoch
_beacon_alerted: dict[tuple[str, str, int], float] = {}

_exfil_state_lock = threading.Lock()
# (src_ip, dst_ip) -> last_alert_epoch
_exfil_alerted: dict[tuple[str, str], float] = {}

_SEVERITY_ORDER_SQL = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 ELSE 3 END"
)


def _detect_from_capture_loop() -> None:
    """Scan capture-agent events for suspicious patterns and match IDS alerts against indexed rules."""
    _refresh_self_ips()
    logger.info("Capture detection loop started")

    while _CAPTURE_DETECT_RUNNING.is_set():
        try:
            _detect_port_scans()
            _detect_ssh_brute_force()
            _detect_syn_flood()
            _detect_c2_beacons()
            _detect_data_exfil()
            _detect_rule_matches()
            _match_alerts_to_rules()
            _sync_threat_intel()
        except Exception as exc:
            logger.warning("Capture detection error: %s", exc)

        time.sleep(10)


def _sync_threat_intel() -> None:
    """Periodically refresh threat-intel feeds (abuse.ch Feodo/URLhaus + custom).

    sync_feeds is internally throttled by SOC_TI_SYNC_SEC (default 6h); this
    call just gives it a heartbeat every detection pass. Enrich-index rules
    only fire when the indicator store has data, so a dead feed silently
    disables that detection surface — surface failures in the log.
    """
    try:
        from app_shared import threat_intel as _ti

        stats = _ti.sync_feeds()
        if stats:
            logger.info("Threat-intel feed sync: %s", stats)
    except Exception as exc:
        logger.warning("Threat-intel sync failed: %s", exc)


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
            # Count only SYN probes: a rejected connection makes the TARGET
            # send an RST back, and counting replies as probes made the host
            # look like the scanner (it "probed" every client's ephemeral
            # port) — the response engine then blocked the host itself.
            if not _is_syn(ev):
                continue
            if src_ip in _self_ips:
                continue  # never let the console attack itself
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
    _emit_capture_alert(
        "Port scan", "T1046", severity,
        "Port scan reconnaissance (T1046)",
        f"{port_count} distinct TCP ports probed by {src_ip} within "
        f"{_SCAN_WINDOW_SEC}s ({burst} within a {_SCAN_BURST_SEC}s burst; "
        f"packet capture).",
        src_ip,
    )


def _is_syn(packet_ev: dict) -> bool:
    """True when the event is a TCP packet with only the SYN flag set (0x02)."""
    proto = (packet_ev.get("protocol", "") or packet_ev.get("network_transport", "") or "").upper()
    if proto not in ("TCP", "TCP6"):
        return False
    flags = packet_ev.get("tcp_flags")
    if flags is None:
        return False
    try:
        return (int(flags) & 0x12) == 0x02  # SYN set, ACK clear
    except (TypeError, ValueError):
        return False


def _emit_capture_alert(
    kind: str, technique_id: str, severity: str, title: str, message: str,
    src_ip: str, dst_ip: str = "",
) -> None:
    """Shared alert emission for capture-based detections."""
    ts = datetime.now(timezone.utc).isoformat()
    tech = [technique_id]
    store_event(
        "soc-internal", "soc-detection",
        engine="soc-internal", title=title, message=message,
        severity=severity, rule_id=f"CAPTURE-{technique_id}",
        source_ip=src_ip, destination_ip=dst_ip, technique_ids=tech, timestamp=ts,
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
        source_ip=src_ip, destination_ip=dst_ip,
        technique_ids=tech,
        response_preview=preview,
        timestamp=ts,
    )
    logger.info("%s detected from %s -> alert CAPTURE-%s", kind, src_ip, technique_id)


def _detect_ssh_brute_force() -> None:
    """Detect SSH credential brute-force from capture-agent TCP SYNs.

    Any SYN to port 22 counts as an authentication attempt (a real login
    completes once; stuffing scripts retry dozens of times). Alert when a
    source exceeds _BRUTE_THRESHOLD attempts inside _BRUTE_WINDOW_SEC,
    rate-limited per source by _BRUTE_COOLDOWN_SEC.
    """
    window_start_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=_BRUTE_WINDOW_SEC)
    ).isoformat()
    events = query_events(sources=["capture"], start=window_start_iso, limit=_SCAN_READ_LIMIT)
    if not events:
        return

    now = time.time()
    cutoff = now - _BRUTE_WINDOW_SEC
    per_source: dict[str, list[float]] = {}
    for ev in events:
        ev_ts = _parse_event_ts(ev.get("timestamp"))
        if ev_ts < cutoff:
            continue
        if not _is_syn(ev):
            continue
        dst_port = ev.get("destination_port") or 0
        if dst_port != 22:
            continue
        src_ip = ev.get("source_ip", "") or ""
        dst_ip = ev.get("destination_ip", "") or ""
        if not src_ip or src_ip == "0.0.0.0":
            continue
        if _SCAN_SUPPRESS_LOOPBACK and src_ip.startswith("127.") and dst_ip.startswith("127."):
            continue
        per_source.setdefault(src_ip, []).append(ev_ts)

    with _brute_state_lock:
        for src_ip, attempts in per_source.items():
            last_alert, _ = _brute_windows.get(src_ip, (0.0, []))
            fresh = [ts for ts in attempts if ts >= cutoff]
            if len(fresh) >= _BRUTE_THRESHOLD and now - last_alert >= _BRUTE_COOLDOWN_SEC:
                _emit_capture_alert(
                    "SSH brute-force", "T1110", "high",
                    "SSH credential brute-force (T1110)",
                    f"{len(fresh)} SSH connection attempts from {src_ip} within "
                    f"{_BRUTE_WINDOW_SEC}s (threshold {_BRUTE_THRESHOLD}; packet capture).",
                    src_ip,
                )
                _brute_windows[src_ip] = (now, fresh)
            else:
                _brute_windows[src_ip] = (last_alert, fresh)


def _detect_syn_flood() -> None:
    """Detect SYN floods: a half-open SYN storm against a single port.

    More than _FLOOD_THRESHOLD bare SYNs from one source to one dst port
    inside _FLOOD_WINDOW_SEC, with no SYN-ACKs back (half-open), is a DoS
    signature rather than service traffic. DoS is availability impact (T1498).
    """
    window_start_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=_FLOOD_WINDOW_SEC)
    ).isoformat()
    events = query_events(sources=["capture"], start=window_start_iso, limit=_SCAN_READ_LIMIT)
    if not events:
        return

    now = time.time()
    cutoff = now - _FLOOD_WINDOW_SEC
    syn_counts: dict[tuple[str, int], list[float]] = {}
    synack_seen: set[tuple[str, int]] = set()
    dst_ips: dict[tuple[str, int], str] = {}
    for ev in events:
        ev_ts = _parse_event_ts(ev.get("timestamp"))
        if ev_ts < cutoff:
            continue
        proto = (ev.get("protocol", "") or ev.get("network_transport", "") or "").upper()
        if proto not in ("TCP", "TCP6"):
            continue
        flags = ev.get("tcp_flags")
        try:
            flag_val = int(flags) if flags is not None else None
        except (TypeError, ValueError):
            flag_val = None
        src_ip = ev.get("source_ip", "") or ""
        dst_ip = ev.get("destination_ip", "") or ""
        dst_port = ev.get("destination_port") or 0
        if not src_ip or not dst_port:
            continue
        if _SCAN_SUPPRESS_LOOPBACK and src_ip.startswith("127.") and dst_ip.startswith("127."):
            continue
        if flag_val is not None and (flag_val & 0x12) == 0x12:
            synack_seen.add((src_ip, dst_port))  # handshake progressing: not half-open
            continue
        if _is_syn(ev):
            key = (src_ip, dst_port)
            syn_counts.setdefault(key, []).append(ev_ts)
            if dst_ip:
                dst_ips[key] = dst_ip

    with _flood_state_lock:
        for (src_ip, dst_port), syns in syn_counts.items():
            if (src_ip, dst_port) in synack_seen:
                continue  # connections are completing: legitimate load
            last_alert, _ = _flood_windows.get((src_ip, dst_port), (0.0, []))
            fresh = [ts for ts in syns if ts >= cutoff]
            if len(fresh) >= _FLOOD_THRESHOLD and now - last_alert >= _FLOOD_COOLDOWN_SEC:
                dst_ip = dst_ips.get((src_ip, dst_port), "")
                _emit_capture_alert(
                    "SYN flood", "T1498", "critical",
                    "SYN flood denial-of-service (T1498)",
                    f"{len(fresh)} half-open SYNs from {src_ip} to port {dst_port} within "
                    f"{_FLOOD_WINDOW_SEC}s with no completed handshakes (threshold "
                    f"{_FLOOD_THRESHOLD}; packet capture).",
                    src_ip, dst_ip,
                )
                _flood_windows[(src_ip, dst_port)] = (now, fresh)
            else:
                _flood_windows[(src_ip, dst_port)] = (last_alert, fresh)


def _flow_events(window_sec: int) -> list[dict]:
    """Capture events inside the window, TCP-only, loopback-to-loopback dropped.

    Shared by the beacon and exfil detectors: both analyze per-flow behavior,
    and both must ignore local service chatter.
    """
    window_start_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=window_sec)
    ).isoformat()
    events = query_events(sources=["capture"], start=window_start_iso, limit=_SCAN_READ_LIMIT)
    out: list[dict] = []
    for ev in events:
        proto = (ev.get("protocol", "") or ev.get("network_transport", "") or "").upper()
        if proto not in ("TCP", "TCP6"):
            continue
        src_ip = ev.get("source_ip", "") or ""
        dst_ip = ev.get("destination_ip", "") or ""
        if not src_ip or src_ip == "0.0.0.0" or not ev.get("destination_port"):
            continue
        if _SCAN_SUPPRESS_LOOPBACK and src_ip.startswith("127.") and dst_ip.startswith("127."):
            continue
        out.append(ev)
    return out


def _jitter_ratio(intervals: list[float]) -> float:
    """Coefficient of variation of inter-connection intervals (0 = metronome)."""
    if len(intervals) < 2:
        return 1.0
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 1.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    return (variance ** 0.5) / mean


def _detect_c2_beacons() -> None:
    """Detect C2 beaconing: regular, repeated connection attempts to one endpoint.

    Groups bare SYNs by flow (src, dst, dst_port). A flow with at least
    _BEACON_MIN_CONNECTIONS inside _BEACON_WINDOW_SEC whose inter-connection
    intervals show near-metronome regularity (jitter ratio <= _BEACON_MAX_JITTER)
    is an implant checking in on a schedule — random traffic does not keep time.
    Stateless per pass (the full window is re-read); per-flow cooldown rates
    the alert. MITRE T1071 (Application Layer Protocol).
    """
    now = time.time()
    cutoff = now - _BEACON_WINDOW_SEC
    flows: dict[tuple[str, str, int], list[float]] = {}
    for ev in _flow_events(_BEACON_WINDOW_SEC):
        ev_ts = _parse_event_ts(ev.get("timestamp"))
        if ev_ts < cutoff:
            continue
        if not _is_syn(ev):
            continue
        key = (ev.get("source_ip", ""), ev.get("destination_ip", ""), ev.get("destination_port") or 0)
        flows.setdefault(key, []).append(ev_ts)

    with _beacon_state_lock:
        for (src_ip, dst_ip, dst_port), stamps in flows.items():
            stamps = sorted(stamps)
            intervals = [b - a for a, b in zip(stamps, stamps[1:])]
            if len(stamps) < _BEACON_MIN_CONNECTIONS or not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if not (_BEACON_MIN_INTERVAL_SEC <= mean_interval <= _BEACON_MAX_INTERVAL_SEC):
                continue
            jitter = _jitter_ratio(intervals)
            if jitter > _BEACON_MAX_JITTER:
                continue
            if now - _beacon_alerted.get((src_ip, dst_ip, dst_port), 0.0) < _BEACON_COOLDOWN_SEC:
                continue
            _emit_capture_alert(
                "C2 beaconing", "T1071", "high",
                "C2 beaconing to external endpoint (T1071)",
                f"{len(stamps)} regular connection attempts from {src_ip} to "
                f"{dst_ip}:{dst_port} within {_BEACON_WINDOW_SEC}s "
                f"(mean interval {mean_interval:.1f}s, jitter {jitter:.2f} — "
                f"near-fixed check-in schedule; packet capture).",
                src_ip, dst_ip,
            )
            _beacon_alerted[(src_ip, dst_ip, dst_port)] = now
        # Cooldown entries age out with the window.
        expired = [k for k, ts in _beacon_alerted.items() if now - ts > _BEACON_COOLDOWN_SEC * 2]
        for k in expired:
            _beacon_alerted.pop(k, None)


def _frame_len(ev: dict) -> int:
    """Wire size of a captured packet (agent ships frame_len; older events may omit it)."""
    val = ev.get("frame_len")
    if val is None:
        raw = ev.get("raw")
        if isinstance(raw, dict):
            val = raw.get("frame_len")
    try:
        return int(val or 0)
    except (TypeError, ValueError):
        return 0


def _detect_data_exfil() -> None:
    """Detect bulk outbound data transfer: staging-then-upload volume signature.

    Sums captured wire bytes per (source, destination) flow inside
    _EXFIL_WINDOW_SEC using an SQL GROUP BY over the numeric frame_len
    column — a 150 MB transfer is 100k+ packets, far past any event-read
    limit, so volume must be aggregated in the database, not in Python.
    One source pushing more than _EXFIL_BYTES_THRESHOLD to a single endpoint
    is exfiltration (T1041) or a staging upload; normal request traffic is
    kilobytes, not megabytes. Loopback pairs are skipped here (the SQL path
    has no access to the suppression flag); per-pair cooldown rate-limits.
    """
    now = time.time()
    window_start_iso = (
        datetime.now(timezone.utc) - timedelta(seconds=_EXFIL_WINDOW_SEC)
    ).isoformat()
    try:
        flows = exfil_volumes(start=window_start_iso)
    except Exception as exc:
        logger.warning("Exfil volume aggregation failed: %s", exc)
        return

    with _exfil_state_lock:
        for (src_ip, dst_ip), flow in flows.items():
            if _SCAN_SUPPRESS_LOOPBACK and src_ip.startswith("127.") and dst_ip.startswith("127."):
                continue
            total_bytes = flow["bytes"]
            if total_bytes < _EXFIL_BYTES_THRESHOLD:
                continue
            if now - _exfil_alerted.get((src_ip, dst_ip), 0.0) < _EXFIL_COOLDOWN_SEC:
                continue
            dst_port = flow.get("port", 0)
            mb = total_bytes / (1024 * 1024)
            _emit_capture_alert(
                "Data exfiltration", "T1041", "critical",
                "Bulk outbound data transfer (T1041)",
                f"{mb:.1f} MB transferred from {src_ip} to {dst_ip}:{dst_port} "
                f"within {_EXFIL_WINDOW_SEC}s (threshold "
                f"{_EXFIL_BYTES_THRESHOLD // (1024 * 1024)} MB; packet capture).",
                src_ip, dst_ip,
            )
            _exfil_alerted[(src_ip, dst_ip)] = now
        expired = [k for k, ts in _exfil_alerted.items() if now - ts > _EXFIL_COOLDOWN_SEC * 2]
        for k in expired:
            _exfil_alerted.pop(k, None)


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


# --- direct rule-engine phase (every indexed rule evaluated on events) ----
_RULE_ENGINE_WATERMARK_KEY = "capture_detection.rule_engine_watermark"
_RULE_ENGINE_BATCH = _env_int("SOC_RULE_ENGINE_BATCH", 200)
_RULE_ENGINE_MAX_ALERTS_PER_PASS = _env_int("SOC_RULE_ENGINE_MAX_ALERTS", 25)
_RULE_ENGINE_RELOAD_SEC = _env_int("SOC_RULE_ENGINE_RELOAD_SEC", 300)
_RULE_ENGINE_ALERT_COOLDOWN = _env_int("SOC_RULE_ENGINE_COOLDOWN_SEC", 900)  # per rule_id

_rule_engine_lock = threading.Lock()
_rule_engine_catalog = None
_rule_engine_catalog_loaded_at = 0.0
_rule_engine_alerted: dict[str, float] = {}


def _get_rule_catalog():
    """Compile the full catalog once, reload every _RULE_ENGINE_RELOAD_SEC."""
    global _rule_engine_catalog, _rule_engine_catalog_loaded_at
    now = time.time()
    with _rule_engine_lock:
        if _rule_engine_catalog is None or (now - _rule_engine_catalog_loaded_at) > _RULE_ENGINE_RELOAD_SEC:
            try:
                from app_shared.rule_engine import load_catalog_from_store
                _rule_engine_catalog = load_catalog_from_store()
                _rule_engine_catalog_loaded_at = now
                logger.info(
                    "Rule engine compiled: %d matchers (%s); skipped: %s",
                    len(_rule_engine_catalog.matchers),
                    ", ".join(f"{k} {v}" for k, v in sorted(_rule_engine_catalog.by_engine.items())),
                    ", ".join(f"{k} {v}" for k, v in sorted(_rule_engine_catalog.skip_by_engine.items())) or "none",
                )
            except Exception as exc:
                logger.warning("Rule engine compilation failed: %s", exc)
                _rule_engine_catalog = None if _rule_engine_catalog is None else _rule_engine_catalog
        return _rule_engine_catalog


def _detect_rule_matches() -> None:
    """Evaluate every compiled platform rule against the newest events.

    This is the piece that makes the 7k-rule catalog an engine instead of a
    library: an incoming event satisfying ANY indexed rule's logic fires
    that rule_id as an alert, with AI-triage + response preview attached by
    the existing response pipeline. Watermarked exactly like the other
    phases; per-rule cooldown keeps one noisy rule from flooding.
    """
    catalog = _get_rule_catalog()
    if catalog is None or not catalog.matchers:
        return

    watermark = str(get_kv(_RULE_ENGINE_WATERMARK_KEY, "") or "")
    docs = query_events(sources=["capture"], start=watermark or None, limit=_RULE_ENGINE_BATCH)
    if not docs:
        return
    if watermark:
        docs = [d for d in docs if str(d.get("timestamp", "")) > watermark]
    if not docs:
        return
    # Oldest-first so the watermark can only move forward over fully
    # processed events; newest batch tail resumes next pass.
    docs = sorted(docs, key=lambda d: str(d.get("timestamp", "")))

    max_ts = watermark
    fired = 0
    now = time.time()

    try:
        hits = catalog.evaluate(docs)
        for ev in docs:
            ts = str(ev.get("timestamp", ""))
            if ts > max_ts:
                max_ts = ts

        # Deduplicate: one alert per (rule_id, source_ip) per cooldown window.
        seen_pairs: set[tuple[str, str]] = set()
        for hit in hits:
            rule_id = hit["rule_id"]
            src = (hit["event"].get("source_ip") or "") or ""
            pair = (rule_id, src)
            if pair in seen_pairs:
                continue
            last = _rule_engine_alerted.get(rule_id, 0.0)
            if now - last < _RULE_ENGINE_ALERT_COOLDOWN:
                seen_pairs.add(pair)
                continue
            if fired >= _RULE_ENGINE_MAX_ALERTS_PER_PASS:
                break
            seen_pairs.add(pair)

            ev = hit["event"]
            source_ip = ev.get("source_ip", "") or ""
            dest_ip = ev.get("destination_ip", "") or ""
            dst_port = ev.get("destination_port", "") or ""
            host_name = ev.get("host_name", "") or ""
            transport = ev.get("network_transport", "") or ev.get("protocol", "") or ""
            techs = hit["technique_ids"] or []
            severity = hit["severity"] if hit["severity"] in ("critical", "high", "medium", "low") else "medium"
            title = f"{hit['title'] or rule_id} [rule engine]"
            message = (
                f"Rule {rule_id} ({hit['engine']}) matched a captured event: "
                f"{transport} {source_ip} -> {dest_ip}:{dst_port}. {hit['description'][:220]}"
            )

            store_event(
                "soc-internal", "soc-detection",
                engine="rule-engine",
                title=title,
                message=message,
                severity=severity,
                rule_id=rule_id,
                source_ip=source_ip,
                destination_ip=dest_ip,
                technique_ids=techs,
            )

            action = choose_action(techs)
            detail = action_detail(action)
            preview = {
                "title": detail["title"],
                "summary": detail["summary"],
                "preview_command": render_command_preview(
                    action,
                    {"source_ip": source_ip, "destination_ip": dest_ip, "rule_id": rule_id,
                     "technique_id": techs[0] if techs else "", "host_name": host_name},
                ),
                "success_criteria": f"{source_ip or dest_ip or 'target'} is present in the runtime blocklist.",
            }
            store_alert(
                "rule-engine", severity, title,
                message=message,
                rule_id=rule_id,
                source_ip=source_ip,
                destination_ip=dest_ip,
                technique_ids=techs,
                response_preview=preview,
            )
            _rule_engine_alerted[rule_id] = now
            fired += 1
            logger.info("Rule engine: %s (%s) fired on %s -> %s:%s",
                        rule_id, hit["engine"], source_ip or "?", dest_ip or "?", dst_port)

        if max_ts and max_ts != watermark:
            set_kv(_RULE_ENGINE_WATERMARK_KEY, max_ts)
    except Exception as exc:
        logger.warning("Rule engine evaluation error: %s", exc)


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

    db_path = state_path("soceyes_events.sqlite")
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

                # soc-internal source: enrichment output is never re-ingested.
                store_event(
                    "soc-internal", "soc-detection",
                    engine="soc-internal",
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
    logger.info("Capture detection loop started (scans, brute force, floods, beacons, exfil, rule engine)")


def stop_capture_detection() -> None:
    """Stop the capture event detection loop."""
    _CAPTURE_DETECT_RUNNING.clear()
    logger.info("Capture detection loop stopped")
