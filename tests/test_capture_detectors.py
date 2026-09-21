"""Tests for capture-based attack detectors (brute-force, SYN flood, C2 beacon, exfil).

Locks in the behaviors verified live against real container-borne attacks:
- SSH brute-force: >= threshold SYNs to port 22 in window -> high alert
- SYN flood: >= threshold half-open SYNs to one port, no handshakes -> critical
- Completed handshakes (SYN-ACK observed) suppress the flood alert
- C2 beaconing: regular-interval SYNs to one endpoint -> high alert (T1071)
- Data exfil: bulk outbound bytes to one destination -> critical alert (T1041)
"""
from __future__ import annotations

import datetime as dt
from unittest.mock import patch

import pytest

from backend.app.services import capture_detection as cd


def _syn(src: str, dst: str, port: int, seconds_ago: int, **extra) -> dict:
    ts = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds_ago)).isoformat()
    ev = {
        "source": "capture", "index_name": "soc-agent-capture",
        "source_ip": src, "destination_ip": dst, "destination_port": port,
        "protocol": "tcp", "network_transport": "tcp",
        "tcp_flags": 0x02, "timestamp": ts,
    }
    ev.update(extra)
    return ev


@pytest.fixture()
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    cd._brute_windows.clear()
    cd._flood_windows.clear()
    cd._scan_windows.clear()
    cd._beacon_alerted.clear()
    cd._exfil_alerted.clear()
    yield


def test_ssh_brute_force_alerts(fresh_state):
    events = [_syn("198.51.100.10", "172.17.0.1", 22, 30 - i) for i in range(20)]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_ssh_brute_force()
    emit.assert_called_once()
    args = emit.call_args[0]
    assert args[0] == "SSH brute-force"
    assert args[1] == "T1110"
    assert args[2] == "high"
    assert "198.51.100.10" in args[4]


def test_ssh_single_attempt_no_alert(fresh_state):
    events = [_syn("198.51.100.11", "172.17.0.1", 22, 5) for _ in range(3)]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_ssh_brute_force()
    emit.assert_not_called()


def test_syn_flood_alerts_critical(fresh_state):
    events = [_syn("203.0.113.66", "172.17.0.1", 9443, 5) for _ in range(120)]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_syn_flood()
    emit.assert_called_once()
    args = emit.call_args[0]
    assert args[0] == "SYN flood"
    assert args[1] == "T1498"
    assert args[2] == "critical"


def test_completed_handshake_suppresses_flood(fresh_state):
    events = [_syn("203.0.113.70", "172.17.0.1", 8443, 5) for _ in range(120)]
    # Server responses observed: handshakes are completing, this is load not a flood
    for ev in events:
        ev["tcp_flags"] = 0x12  # SYN-ACK from the responder direction
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_syn_flood()
    emit.assert_not_called()


def test_is_syn_flag_parsing(fresh_state):
    assert cd._is_syn({"protocol": "tcp", "tcp_flags": 0x02}) is True
    assert cd._is_syn({"protocol": "tcp", "tcp_flags": 0x12}) is False  # SYN-ACK
    assert cd._is_syn({"protocol": "tcp", "tcp_flags": 0x10}) is False  # pure ACK
    assert cd._is_syn({"protocol": "udp", "tcp_flags": 0x02}) is False
    assert cd._is_syn({"protocol": "tcp"}) is False  # no flags field


# --- C2 beaconing -----------------------------------------------------------


def test_c2_beacon_regular_interval_alerts(fresh_state):
    # 10 check-ins at exactly 60s apart: metronome regular.
    events = [_syn("198.51.100.40", "203.0.113.9", 443, 600 - i * 60) for i in range(10)]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_c2_beacons()
    emit.assert_called_once()
    args = emit.call_args[0]
    assert args[0] == "C2 beaconing"
    assert args[1] == "T1071"
    assert args[2] == "high"
    assert "198.51.100.40" in args[4] and "203.0.113.9" in args[4]


def test_c2_irregular_human_traffic_no_alert(fresh_state):
    # Same connection count, jittered intervals: human/web-like, no alert.
    gaps = [17, 121, 43, 211, 29, 167, 53, 137, 71]
    stamps, t = [], 0
    for g in gaps:
        stamps.append(t)
        t += g
    events = [_syn("198.51.100.41", "203.0.113.10", 443, 600 - int(s)) for s in stamps]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_c2_beacons()
    emit.assert_not_called()


def test_c2_completed_connections_no_alert(fresh_state):
    # Handshakes completing (SYN-ACK back): scheduled service, not an implant.
    events = [_syn("198.51.100.42", "203.0.113.11", 443, 600 - i * 60, tcp_flags=0x12) for i in range(10)]
    with patch.object(cd, "query_events", return_value=events), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_c2_beacons()
    emit.assert_not_called()


# --- data exfiltration ------------------------------------------------------


def _big_packet(src: str, dst: str, port: int, seconds_ago: int, nbytes: int) -> dict:
    return _syn(src, dst, port, seconds_ago, tcp_flags=0x18, frame_len=nbytes)


def test_data_exfil_bulk_transfer_alerts_critical(fresh_state):
    # SQL aggregation returns one flow at 150 MB: crosses the 100 MB threshold.
    flows = {("10.9.9.9", "203.0.113.50"): {"bytes": 150_000_000, "port": 8443}}
    with patch.object(cd, "exfil_volumes", return_value=flows), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_data_exfil()
    emit.assert_called_once()
    args = emit.call_args[0]
    assert args[0] == "Data exfiltration"
    assert args[1] == "T1041"
    assert args[2] == "critical"
    assert "10.9.9.9" in args[4] and "203.0.113.50" in args[4]


def test_data_exfil_small_transfer_no_alert(fresh_state):
    # 5 MB flow: normal request/response scale, no alert.
    flows = {("10.9.9.10", "203.0.113.51"): {"bytes": 5_000_000, "port": 8443}}
    with patch.object(cd, "exfil_volumes", return_value=flows), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_data_exfil()
    emit.assert_not_called()


def test_data_exfil_scattered_destinations_no_alert(fresh_state):
    # 150 MB split across many destinations: no single flow crosses threshold.
    flows = {("10.9.9.11", f"203.0.113.{60 + i}"): {"bytes": 15_000_000, "port": 443} for i in range(10)}
    with patch.object(cd, "exfil_volumes", return_value=flows), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_data_exfil()
    emit.assert_not_called()


def test_data_exfil_loopback_suppressed(fresh_state):
    # Localhost-to-localhost bulk copy is a local transfer, not exfiltration.
    flows = {("127.0.0.1", "127.0.0.1"): {"bytes": 500_000_000, "port": 9000}}
    with patch.object(cd, "exfil_volumes", return_value=flows), \
         patch.object(cd, "_emit_capture_alert") as emit:
        cd._detect_data_exfil()
    emit.assert_not_called()


def test_frame_len_reads_raw_fallback(fresh_state):
    assert cd._frame_len({"frame_len": 1500}) == 1500
    assert cd._frame_len({"raw": {"frame_len": "900"}}) == 900
    assert cd._frame_len({}) == 0
    assert cd._frame_len({"frame_len": "garbage"}) == 0
