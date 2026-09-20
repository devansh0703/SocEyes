"""Tests for capture-based attack detectors (brute-force, SYN flood).

Locks in the behaviors verified live against real container-borne attacks:
- SSH brute-force: >= threshold SYNs to port 22 in window -> high alert
- SYN flood: >= threshold half-open SYNs to one port, no handshakes -> critical
- Completed handshakes (SYN-ACK observed) suppress the flood alert
"""
from __future__ import annotations

import datetime as dt
from unittest.mock import patch

import pytest

from backend.app.services import capture_detection as cd


def _syn(src: str, dst: str, port: int, seconds_ago: int) -> dict:
    ts = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds_ago)).isoformat()
    return {
        "source": "capture", "index_name": "fda-agent-capture",
        "source_ip": src, "destination_ip": dst, "destination_port": port,
        "protocol": "tcp", "network_transport": "tcp",
        "tcp_flags": 0x02, "timestamp": ts,
    }


@pytest.fixture()
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setenv("FDA_STATE_DIR", str(tmp_path))
    cd._brute_windows.clear()
    cd._flood_windows.clear()
    cd._scan_windows.clear()
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
