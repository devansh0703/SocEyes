"""Unified data layer: Elasticsearch when available, SQLite fallback.

This is the single store module for the whole codebase (the former
``app_shared.sqlite_store`` duplicate was removed). At import time the module
pings the configured Elasticsearch cluster once. If the ping succeeds every
read/write operation is dispatched to Elasticsearch first; if the ES call
raises an exception the operation transparently falls back to the SQLite
implementation. When the ping fails the module runs entirely in SQLite mode
with no ES requests at all (standalone mode).

Run-scoped operations (``start_run``/``stop_run``/``current_run``/``save_run``/
``run_history``/``set_kv``/``get_kv``) are local-only and always hit SQLite
regardless of ES availability — runs are a runtime concept that does not live
in Elasticsearch.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from collections import Counter, defaultdict  # re-exported for backward compatibility
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app_shared.text_utils import clean_text, normalize_severity, now_utc  # re-exported for backward compatibility

logger = logging.getLogger("fda.unified_store")

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
_es_available: bool | None = None
_es_check_lock = threading.Lock()
_es_last_check: float = 0
_ES_CHECK_INTERVAL = 30  # seconds between ES pings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ping_es(timeout: float = 2.0) -> bool:
    """Return ``True`` if Elasticsearch is reachable."""
    try:
        from app_shared.es_client import ELASTICSEARCH_URL, get_es_client

        session = get_es_client()
        r = session.get(f"{ELASTICSEARCH_URL}/", timeout=timeout)
        return r.status_code in (200, 401)  # 401 means ES is up but auth required
    except Exception:
        return False


def es_available() -> bool:
    """Check (and cache) whether Elasticsearch is reachable."""
    global _es_available, _es_last_check

    now = time.monotonic()
    with _es_check_lock:
        if _es_available is not None and (now - _es_last_check) < _ES_CHECK_INTERVAL:
            return _es_available
        _es_available = _ping_es()
        _es_last_check = now
        return _es_available


def reset_es_cache() -> None:
    """Force the next call to :func:`es_available` to re-ping."""
    global _es_available, _es_last_check
    with _es_check_lock:
        _es_available = None
        _es_last_check = 0


# ---------------------------------------------------------------------------
# SQLite-backed tables (always initialised, used as fallback or primary)
# ---------------------------------------------------------------------------

_lock = threading.RLock()
_sqlite_conn: sqlite3.Connection | None = None


def _default_db() -> Path:
    """Resolve the events DB path at call time from the configured state root.

    Resolving per call (instead of at import time) keeps ``FDA_STATE_DIR``
    honored by processes that set it late, and keeps every deployment's data
    inside the directory the operator actually configured.
    """
    from app_shared.state_paths import state_path

    return state_path("fda_events.sqlite")


def init_db(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (or create) the SQLite database and ensure tables exist."""
    global _sqlite_conn
    if db_path is None:
        db_path = _default_db()
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    from app_shared.db_maintenance import apply_footprint_pragmas, start_wal_maintenance
    apply_footprint_pragmas(conn)
    start_wal_maintenance(str(db_path))
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id        TEXT PRIMARY KEY,
            source    TEXT NOT NULL,
            index_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            severity  TEXT,
            engine    TEXT,
            title     TEXT,
            message   TEXT,
            rule_id   TEXT,
            host_name TEXT,
            user_name TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            network_transport TEXT,
            suricata_event_type TEXT,
            process_name TEXT,
            process_command_line TEXT,
            technique_ids TEXT,
            run_id    TEXT,
            raw       TEXT,
            created_at TEXT NOT NULL,
            frame_len INTEGER,
            payload_len INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source);
        CREATE INDEX IF NOT EXISTS idx_events_run     ON events(run_id);
        CREATE INDEX IF NOT EXISTS idx_events_sev     ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_rule    ON events(rule_id);
        CREATE INDEX IF NOT EXISTS idx_events_src_ts  ON events(source, timestamp);

        CREATE TABLE IF NOT EXISTS alerts (
            id        TEXT PRIMARY KEY,
            engine    TEXT NOT NULL,
            severity  TEXT,
            title     TEXT,
            message   TEXT,
            rule_id   TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            timestamp TEXT NOT NULL,
            technique_ids TEXT,
            response_preview TEXT,
            run_id    TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_engine ON alerts(engine);

        CREATE TABLE IF NOT EXISTS rules (
            rule_id   TEXT PRIMARY KEY,
            engine    TEXT NOT NULL,
            title     TEXT,
            description TEXT,
            severity  TEXT,
            technique_ids TEXT,
            mitre_ids   TEXT,
            file_path   TEXT,
            raw         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_rules_engine ON rules(engine);

        CREATE TABLE IF NOT EXISTS runs (
            run_id    TEXT PRIMARY KEY,
            name      TEXT,
            note      TEXT,
            active    INTEGER DEFAULT 0,
            started_at TEXT,
            stopped_at TEXT,
            saved      INTEGER DEFAULT 0,
            saved_at   TEXT,
            duration_seconds INTEGER,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS state_kv (
            key       TEXT PRIMARY KEY,
            value     TEXT
        );
        """
    )
    # Lightweight migrations: agent wire-size columns added after first ship.
    _cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    for _new_col in ("frame_len", "payload_len"):
        if _new_col not in _cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {_new_col} INTEGER")
    conn.commit()
    with _lock:
        _sqlite_conn = conn
    return conn


def get_conn() -> sqlite3.Connection:
    """Return the SQLite connection (for use by other modules)."""
    if _sqlite_conn is None:
        return init_db()
    return _sqlite_conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _int_or_none(value) -> int | None:
    """Coerce to int for the numeric columns; None (NULL) when absent/garbage."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _compress_raw(raw_json: str) -> bytes:
    """Compress raw JSON payload with zstd for storage efficiency.

    Falls back to UTF-8 bytes if zstd is not available.
    """
    try:
        import zstandard as zstd
        cctx = zstd.ZstdCompressor(level=3)
        return cctx.compress(raw_json.encode("utf-8"))
    except Exception:
        # Fallback: return uncompressed UTF-8 bytes
        return raw_json.encode("utf-8")


def _decompress_raw(data: bytes | str) -> str:
    """Decompress a raw payload that was compressed with _compress_raw.

    If data is already a string (uncompressed), returns it directly.
    """
    if isinstance(data, str):
        return data
    try:
        import zstandard as zstd
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data).decode("utf-8")
    except Exception:
        # Fallback: assume uncompressed UTF-8
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)


def _decode_raw_text(val: bytes | str | None) -> str:
    """Decode a stored raw payload back to JSON text.

    SQLite stores base64(zstd(json)); legacy rows may hold plain JSON text.
    """
    if val is None:
        return "{}"
    if isinstance(val, bytes):
        return _decompress_raw(val)
    s = val.strip()
    if s.startswith("{") or s.startswith("["):
        return s  # legacy plain JSON
    try:
        import base64
        raw_bytes = base64.b64decode(s, validate=True)
    except Exception:
        return s  # not base64; return as-is
    if not raw_bytes:
        return s
    try:
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(raw_bytes).decode("utf-8")
    except Exception:
        # base64 of plain UTF-8 (zstd unavailable at write time)
        return raw_bytes.decode("utf-8", errors="replace")


def _parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


# ---------------------------------------------------------------------------
# Event ingest
# ---------------------------------------------------------------------------

def store_event(
    source: str,
    index_name: str,
    title: str = "",
    message: str = "",
    severity: str = "medium",
    severity_level: int | None = None,
    engine: str = "",
    rule_id: str = "",
    host_name: str = "",
    user_name: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    destination_port: int | None = None,
    network_transport: str = "",
    suricata_event_type: str = "",
    process_name: str = "",
    process_command_line: str = "",
    technique_ids: list[str] | None = None,
    run_id: str | None = None,
    timestamp: str | None = None,
    raw: dict[str, Any] | None = None,
    frame_len: int | None = None,
    payload_len: int | None = None,
) -> str:
    """Insert a single event into ES (if available), otherwise SQLite."""
    import json as _json
    from app_shared.text_utils import normalize_severity

    event_id = str(uuid4())
    ts = timestamp or _now_iso()
    sev = normalize_severity(severity)
    sev_label = sev.get("label", "medium") if isinstance(sev, dict) else str(sev)
    technique_json = _json.dumps(technique_ids or [])

    # Build the ES document
    es_doc = {
        "source": source,
        "index_name": index_name,
        "timestamp": ts,
        "@timestamp": ts,
        "severity": sev_label,
        "engine": engine,
        "title": title,
        "message": message,
        "rule_id": rule_id,
        "host_name": host_name,
        "user_name": user_name,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "network_transport": network_transport,
        "suricata_event_type": suricata_event_type,
        "event_type": suricata_event_type,
        "process_name": process_name,
        "process_command_line": process_command_line,
        "technique_ids": technique_ids or [],
        "run_id": run_id or "",
        "raw": _json.dumps(raw or {}),
        "source_id": event_id,
    }
    if source == "suricata":
        es_doc["event"] = {"original": message}
        es_doc["network"] = {"transport": network_transport}
        es_doc["source"] = {"ip": source_ip}
        es_doc["destination"] = {"ip": destination_ip, "port": destination_port}
        es_doc["suricata"] = {"eve": {"event_type": suricata_event_type}}
    elif source == "wazuh":
        es_doc["full_log"] = message
        es_doc["rule"] = {"description": title}
        es_doc["agent"] = {"name": host_name}
        es_doc["decoder"] = {"name": "wazuh"}
    elif source == "elastic":
        es_doc["event"] = {"original": message}
        es_doc["kibana"] = {"alert": {"rule": {"rule_id": rule_id, "name": title}}}
    elif source == "response":
        es_doc["response"] = {"action_title": title, "summary": message}
        es_doc["labels"] = {"run_id": run_id or ""}

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            target_index = index_name.rstrip("*").rstrip(".")
            payload = _json.dumps(es_doc)
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/{target_index}/_doc/{event_id}",
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 201):
                logger.debug("ES store_event ok: %s", event_id)
            else:
                logger.debug("ES store_event %s -> SQLite", r.status_code)
        except Exception as exc:
            logger.debug("ES store_event failed (%s); falling back to SQLite", exc)

    # Always write to SQLite too (fallback / local copy)
    # Compress raw payload with zstd for storage efficiency
    raw_json = _json.dumps(raw or {})
    raw_compressed = _compress_raw(raw_json)
    # Store as base64-encoded TEXT for schema compatibility
    import base64
    raw_b64 = base64.b64encode(raw_compressed).decode("ascii")

    with _lock:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO events (id, source, index_name, timestamp, severity,
                engine, title, message, rule_id, host_name, user_name,
                source_ip, destination_ip, destination_port, network_transport,
                suricata_event_type, process_name, process_command_line,
                technique_ids, run_id, raw, created_at, frame_len, payload_len)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, source, index_name, ts, sev_label, engine, title, message,
                rule_id, host_name, user_name, source_ip, destination_ip,
                destination_port, network_transport, suricata_event_type,
                process_name, process_command_line, technique_json, run_id,
                raw_b64, _now_iso(), _int_or_none(frame_len), _int_or_none(payload_len),
            ),
        )
        conn.commit()
    return event_id


def store_events_batch(events: list[dict[str, Any]]) -> list[str]:
    """Batch insert multiple events in a single transaction.

    Uses BEGIN IMMEDIATE + executemany for high-throughput ingestion.
    Each event dict has the same fields as store_event().
    Returns list of event IDs in order.
    """
    import json as _json
    from app_shared.text_utils import normalize_severity

    if not events:
        return []

    ids = []
    rows = []
    now = _now_iso()

    for ev in events:
        eid = str(uuid4())
        ts = ev.get("timestamp") or now
        sev = normalize_severity(ev.get("severity", "medium"))
        sev_label = sev.get("label", "medium") if isinstance(sev, dict) else str(sev)
        tech_json = _json.dumps(ev.get("technique_ids") or [])
        # Preserve agent-supplied top-level fields the fixed schema has no
        # column for (TCP flags, wire sizes, packet payload snapshot) inside
        # raw so they survive. The payload ships base64 from the agent.
        _raw_obj = dict(ev.get("raw") or {})
        for _k in ("tcp_flags", "frame_len", "payload_len", "payload", "source_port"):
            if ev.get(_k) is not None:
                _raw_obj[_k] = ev[_k]
        ev_frame_len = ev.get("frame_len")
        ev_payload_len = ev.get("payload_len")
        raw_json = _json.dumps(_raw_obj)
        raw_compressed = _compress_raw(raw_json)
        import base64
        raw_b64 = base64.b64encode(raw_compressed).decode("ascii")

        rows.append((
            eid,
            ev.get("source", ""),
            ev.get("index_name", ""),
            ts,
            sev_label,
            ev.get("engine", ""),
            ev.get("title", ""),
            ev.get("message", ""),
            ev.get("rule_id", ""),
            ev.get("host_name", ""),
            ev.get("user_name", ""),
            ev.get("source_ip", ""),
            ev.get("destination_ip", ""),
            ev.get("destination_port"),
            ev.get("network_transport", ""),
            ev.get("suricata_event_type", ""),
            ev.get("process_name", ""),
            ev.get("process_command_line", ""),
            tech_json,
            ev.get("run_id"),
            raw_b64,
            now,
            _int_or_none(ev.get("frame_len")),
            _int_or_none(ev.get("payload_len")),
        ))
        ids.append(eid)
    with _lock:
        conn = get_conn()
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany(
            """
            INSERT INTO events (id, source, index_name, timestamp, severity,
                engine, title, message, rule_id, host_name, user_name,
                source_ip, destination_ip, destination_port, network_transport,
                suricata_event_type, process_name, process_command_line,
                technique_ids, run_id, raw, created_at, frame_len, payload_len)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()

    return ids


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def store_alert(
    engine: str,
    severity: str,
    title: str,
    message: str = "",
    rule_id: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    technique_ids: list[str] | None = None,
    response_preview: dict[str, Any] | None = None,
    timestamp: str | None = None,
    run_id: str | None = None,
) -> str:
    """Insert a correlated alert."""
    import json as _json
    from app_shared.text_utils import normalize_severity

    alert_id = str(uuid4())
    ts = timestamp or _now_iso()
    technique_json = _json.dumps(technique_ids or [])
    preview_json = _json.dumps(response_preview or {})
    sev_label = normalize_severity(severity)
    sev_label = sev_label.get("label", "medium") if isinstance(sev_label, dict) else str(sev_label)

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            es_doc = {
                "engine": engine,
                "severity": sev_label,
                "title": title,
                "message": message,
                "rule_id": rule_id,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "timestamp": ts,
                "@timestamp": ts,
                "technique_ids": technique_ids or [],
                "response_preview": preview_json,
                "run_id": run_id or "",
                "labels": {"run_id": run_id or ""},
            }
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/security-response-*/_doc/{alert_id}",
                data=_json.dumps(es_doc).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 201):
                logger.debug("ES store_alert ok: %s", alert_id)
            else:
                logger.debug("ES store_alert %s -> SQLite", r.status_code)
        except Exception as exc:
            logger.debug("ES store_alert failed (%s); falling back to SQLite", exc)

    with _lock:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO alerts (id, engine, severity, title, message, rule_id,
                source_ip, destination_ip, timestamp, technique_ids,
                response_preview, run_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id, engine, sev_label, title, message,
                rule_id, source_ip, destination_ip, ts, technique_json,
                preview_json, run_id, _now_iso(),
            ),
        )
        conn.commit()
    return alert_id


# ---------------------------------------------------------------------------
# Querying helpers (ES-first, SQLite fallback)
# ---------------------------------------------------------------------------

_SOURCE_INDEX_MAP = {
    "suricata": "fda-suricata.eve-*",
    "wazuh": "wazuh-alerts-*",
    "elastic": ".alerts-security.alerts-*",
    "response": "security-response-*",
    "run": "fda-runs-*",
    "capture": "fda-agent-capture",
}


def _source_indices(sources: list[str] | None) -> list[str]:
    if not sources:
        return list(_SOURCE_INDEX_MAP.values())
    return [_SOURCE_INDEX_MAP.get(s, s) for s in sources]


def _resolve_relative_time(value: str) -> str:
    """Resolve Elasticsearch-style relative times (``now-5h``, ``now-15m``) to ISO.

    The frontend time filter sends ES-style expressions. Elasticsearch can read
    them directly, but the SQLite fallback stores plain ISO timestamps and
    would otherwise compare against the literal string ``now-5h`` — silently
    matching nothing. Resolve those here so both backends see the same window.
    """
    import re as _re

    if not isinstance(value, str):
        return value
    m = _re.fullmatch(r"now(?:-([\d]+)([smhd]))?", value.strip())
    if not m:
        return value
    delta = timedelta(0)
    if m.group(1):
        unit_secs = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        delta = timedelta(seconds=int(m.group(1)) * unit_secs)
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_where(
    start: str | None,
    end: str | None,
    run_id: str | None,
    indices: list[str] | None,
    orig_sources: list[str] | None = None,
) -> tuple[str, list]:
    """Build the shared WHERE clause.

    Source filtering matches EITHER the logical ``source`` column (what the
    producer declared, e.g. the capture agent writes index_name=*
    capture-packets with source=capture) OR the mapped index_name — writers
    are free to use either convention.
    """
    clauses: list[str] = ["1=1"]
    args: list = []
    if start:
        clauses.append("timestamp >= ?")
        args.append(_resolve_relative_time(start))
    if end:
        clauses.append("timestamp <= ?")
        args.append(_resolve_relative_time(end))
    if run_id:
        clauses.append("run_id = ?")
        args.append(run_id)
    if indices or orig_sources:
        source_clauses: list[str] = []
        if orig_sources:
            placeholders = ", ".join("?" * len(orig_sources))
            source_clauses.append(f"source IN ({placeholders})")
            args.extend(orig_sources)
        if indices:
            placeholders = ", ".join("?" * len(indices))
            source_clauses.append(f"index_name IN ({placeholders})")
            args.extend(indices)
        clauses.append("(" + " OR ".join(source_clauses) + ")")
    return " AND ".join(clauses), args


def query_events(
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
    limit: int = 200,
    query: str = "",
) -> list[dict[str, Any]]:
    """Return raw events.  ES first, SQLite fallback."""
    indices = _source_indices(sources) if sources else None  # None = all indices

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            from app_shared.text_utils import clean_text, normalize_severity, deep_get

            index_str = ",".join(indices) if indices else ",".join(_SOURCE_INDEX_MAP.values())
            must: list[dict[str, Any]] = []

            # Time range
            range_filter: dict[str, Any] = {}
            if start:
                range_filter["gte"] = start
            if end:
                range_filter["lte"] = end
            if range_filter:
                must.append({"range": {"@timestamp": range_filter}})

            # Run filter
            if run_id:
                must.append({
                    "bool": {
                        "should": [
                            {"term": {"labels.run_id.keyword": run_id}},
                            {"term": {"labels.run_id": run_id}},
                            {"term": {"run_id.keyword": run_id}},
                            {"term": {"run_id": run_id}},
                        ],
                        "minimum_should_match": 1,
                    }
                })

            # Text query
            if query.strip():
                must.append({
                    "multi_match": {
                        "query": query,
                        "type": "best_fields",
                        "fields": [
                            "message^5", "full_log^5", "event_original^3",
                            "process.command_line^4", "process_name^4",
                            "title^3", "rule_id^2", "search_text^6",
                        ],
                    }
                })

            payload = {
                "size": limit,
                "_source": True,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must}},
            }

            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/{index_str}/_search",
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                events = []
                for hit in data.get("hits", {}).get("hits", []):
                    src = hit.get("_source", {})
                    severity = normalize_severity(src.get("severity", "medium"))
                    events.append({
                        "id": hit.get("_id", ""),
                        "source": src.get("source", ""),
                        "index_name": src.get("index_name", hit.get("_index", "")),
                        "timestamp": src.get("@timestamp") or src.get("timestamp", ""),
                        "severity": severity.get("label", "medium") if isinstance(severity, dict) else str(severity),
                        "engine": src.get("engine", ""),
                        "title": clean_text(src.get("title", "")),
                        "message": clean_text(src.get("message", "")),
                        "rule_id": src.get("rule_id", ""),
                        "host_name": clean_text(src.get("host_name", deep_get(src, ["host", "name"]))),
                        "user_name": clean_text(src.get("user_name", deep_get(src, ["user", "name"]))),
                        "source_ip": src.get("source_ip", deep_get(src, ["source", "ip"])),
                        "destination_ip": src.get("destination_ip", deep_get(src, ["destination", "ip"])),
                        "destination_port": src.get("destination_port", deep_get(src, ["destination", "port"], 0)),
                        "network_transport": src.get("network_transport", deep_get(src, ["network", "transport"])),
                        "suricata_event_type": src.get("suricata_event_type", src.get("event_type", deep_get(src, ["suricata", "eve", "event_type"]))),
                        "process_name": clean_text(src.get("process_name", deep_get(src, ["process", "name"]))),
                        "process_command_line": clean_text(src.get("process_command_line", deep_get(src, ["process", "command_line"]))),
                        "technique_ids": src.get("technique_ids", []),
                        "run_id": clean_text(src.get("run_id", (src.get("labels") or {}).get("run_id", ""))),
                        "raw": src.get("raw", {}),
                        "created_at": src.get("created_at", ""),
                    })
                return events
        except Exception as exc:
            logger.debug("ES query_events failed (%s); falling back to SQLite", exc)

    # SQLite fallback
    where, args = _build_where(start, end, run_id, indices, sources)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    with _lock:
        conn = get_conn()
        rows = conn.execute(sql, args).fetchall()
    events = []
    for row in rows:
        import json as _json
        doc: dict[str, Any] = {}
        for key in row.keys():
            val = row[key]
            if key == "technique_ids" and val:
                try:
                    val = _json.loads(val)
                except (ValueError, TypeError):
                    val = []
            elif key == "raw" and val:
                try:
                    val = _json.loads(_decode_raw_text(val))
                except (ValueError, TypeError):
                    val = {}
            doc[key] = val
        if query:
            text = " ".join(
                str(doc.get(k, "")) for k in ("title", "message", "rule_id", "process_name", "source_ip")
            ).lower()
            if query.lower() not in text:
                continue
        # Flatten agent TCP flags + packet sizes: stored inside raw JSON by
        # the capture agent, surfaced top-level so detectors can filter
        # SYN-only probes and sum wire volume.
        if not doc.get("tcp_flags") or not doc.get("frame_len"):
            raw = doc.get("raw")
            if isinstance(raw, dict):
                for size_key in ("tcp_flags", "frame_len", "payload_len"):
                    if not doc.get(size_key) and raw.get(size_key) is not None:
                        doc[size_key] = raw.get(size_key)
        events.append(doc)
    return events


def exfil_volumes(
    start: str,
    end: str | None = None,
) -> dict[tuple[str, str], dict]:
    """Aggregate captured wire bytes per (source, destination) flow via SQL.

    Exfil detection needs TRUE volume totals — a 150 MB transfer is 100k+",
    packets, far past the event-read limit, so Python-side summing of the
    newest N events undercounts. SQLite does the whole-window SUM in one
    indexed range scan. Returns {(src, dst): {"bytes": n, "port": p}}.
    """
    conn = get_conn()
    if end:
        rows = conn.execute(
            "SELECT source_ip, destination_ip, SUM(COALESCE(frame_len, 0)) AS total, "
            "MAX(destination_port) AS port "
            "FROM events WHERE source = 'capture' AND timestamp >= ? AND timestamp <= ? "
            "AND frame_len IS NOT NULL "
            "GROUP BY source_ip, destination_ip",
            (start, end),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT source_ip, destination_ip, SUM(COALESCE(frame_len, 0)) AS total, "
            "MAX(destination_port) AS port "
            "FROM events WHERE source = 'capture' AND timestamp >= ? "
            "AND frame_len IS NOT NULL "
            "GROUP BY source_ip, destination_ip",
            (start,),
        ).fetchall()
    out: dict[tuple[str, str], dict] = {}
    for row in rows:
        src, dst, total, port = row[0], row[1], row[2] or 0, row[3] or 0
        if not src or not dst:
            continue
        out[(src, dst)] = {"bytes": int(total), "port": int(port)}
    return out


def count_events(
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
) -> int:
    """Count events.  ES first, SQLite fallback."""
    indices = _source_indices(sources) if sources else None  # None = all indices

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client

            index_str = ",".join(indices) if indices else ",".join(_SOURCE_INDEX_MAP.values())
            must: list[dict[str, Any]] = []
            range_filter: dict[str, Any] = {}
            if start:
                range_filter["gte"] = start
            if end:
                range_filter["lte"] = end
            if range_filter:
                must.append({"range": {"@timestamp": range_filter}})
            if run_id:
                must.append({
                    "bool": {
                        "should": [
                            {"term": {"labels.run_id.keyword": run_id}},
                            {"term": {"labels.run_id": run_id}},
                            {"term": {"run_id.keyword": run_id}},
                            {"term": {"run_id": run_id}},
                        ],
                        "minimum_should_match": 1,
                    }
                })

            payload = {"query": {"bool": {"must": must}}}
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/{index_str}/_count",
                json=payload,
                timeout=10,
            )
            if r.status_code == 200:
                return int(r.json().get("count", 0))
        except Exception as exc:
            logger.debug("ES count_events failed (%s); falling back to SQLite", exc)

    where, args = _build_where(start, end, run_id, indices, sources)
    with _lock:
        conn = get_conn()
        row = conn.execute(f"SELECT COUNT(*) as c FROM events WHERE {where}", args).fetchone()
    return row["c"]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def update_alert_preview(alert_id: str, preview: dict[str, Any]) -> bool:
    """Merge ``preview`` into an alert's response_preview (e.g. AI triage verdict)."""
    import json as _json

    with _lock:
        conn = get_conn()
        row = conn.execute(
            "SELECT response_preview FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if not row:
            return False
        try:
            merged = _json.loads(row["response_preview"] or "{}")
        except (ValueError, TypeError):
            merged = {}
        merged.update(preview)
        conn.execute(
            "UPDATE alerts SET response_preview = ? WHERE id = ?",
            (_json.dumps(merged, default=str), alert_id),
        )
        conn.commit()
    return True


def search_alerts(
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return correlated alerts.  ES first, SQLite fallback."""
    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            from app_shared.text_utils import clean_text, normalize_severity

            must: list[dict[str, Any]] = []
            range_filter: dict[str, Any] = {}
            if start:
                range_filter["gte"] = start
            if end:
                range_filter["lte"] = end
            if range_filter:
                must.append({"range": {"@timestamp": range_filter}})

            payload = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must}},
            }

            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/security-response-*/_search",
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                results = []
                for hit in data.get("hits", {}).get("hits", []):
                    src = hit.get("_source", {})
                    severity = normalize_severity(src.get("severity", "medium"))
                    item = {
                        "id": hit.get("_id", ""),
                        "engine": src.get("engine", "correlated"),
                        "severity": severity.get("label", "medium") if isinstance(severity, dict) else str(severity),
                        "title": clean_text(src.get("title", "")),
                        "message": clean_text(src.get("message", "")),
                        "rule_id": src.get("rule_id", ""),
                        "source_ip": src.get("source_ip", ""),
                        "destination_ip": src.get("destination_ip", ""),
                        "timestamp": src.get("@timestamp") or src.get("timestamp", ""),
                        "technique_ids": src.get("technique_ids", []),
                        "response_preview": src.get("response_preview", {}),
                        "run_id": clean_text(src.get("run_id", (src.get("labels") or {}).get("run_id", ""))),
                        "created_at": src.get("created_at", ""),
                    }
                    if run_id and item.get("run_id") != run_id:
                        continue
                    if isinstance(item.get("response_preview"), str):
                        import json as _json
                        try:
                            item["response_preview"] = _json.loads(item["response_preview"])
                        except Exception:
                            item["response_preview"] = {}
                    results.append(item)
                results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                return results[:limit]
        except Exception as exc:
            logger.debug("ES search_alerts failed (%s); falling back to SQLite", exc)

    # SQLite fallback
    clauses: list[str] = ["1=1"]
    a: list = []
    if start:
        clauses.append("timestamp >= ?"); a.append(_resolve_relative_time(start))
    if end:
        clauses.append("timestamp <= ?"); a.append(_resolve_relative_time(end))
    if run_id:
        clauses.append("run_id = ?"); a.append(run_id)
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE {' AND '.join(clauses)} ORDER BY timestamp DESC LIMIT ?",
            a + [limit],
        ).fetchall()
    results = []
    for row in rows:
        import json as _json
        doc = dict(row)
        if doc.get("technique_ids"):
            try:
                doc["technique_ids"] = _json.loads(doc["technique_ids"])
            except (ValueError, TypeError):
                doc["technique_ids"] = []
        if doc.get("response_preview"):
            try:
                doc["response_preview"] = _json.loads(doc["response_preview"])
            except (ValueError, TypeError):
                doc["response_preview"] = {}
        results.append(doc)
    return results


def get_latest_alerts(limit: int = 12) -> list[dict[str, Any]]:
    """Return the N most recent correlated alerts."""
    results = search_alerts(limit=limit)
    for r in results:
        r["id"] = r.get("id") or r.get("run_id")
    return results


# ---------------------------------------------------------------------------
# Analytics (replace ES aggregations with SQLite equivalents)
# ---------------------------------------------------------------------------

def get_analytics_summary(
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Compute dashboard aggregate stats.  ES first, SQLite fallback."""
    indices = _source_indices(sources) if sources else None  # None = all indices

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            from collections import Counter

            index_str = ",".join(indices) if indices else ",".join(_SOURCE_INDEX_MAP.values())
            range_filter: dict[str, Any] = {}
            if start:
                range_filter["gte"] = start
            if end:
                range_filter["lte"] = end
            if not range_filter:
                range_filter["gte"] = "now-24h"
            range_q = {"range": {"@timestamp": range_filter}}

            # Timeline aggregation
            timeline_payload = {
                "size": 0,
                "query": range_q,
                "aggs": {
                    "timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "5m",
                            "min_doc_count": 0,
                        }
                    }
                },
            }
            suricata_payload = {
                "size": 0,
                "query": range_q,
                "aggs": {
                    "protocols": {"terms": {"field": "network.transport", "size": 6}},
                    "event_types": {"terms": {"field": "event_type", "size": 6}},
                    "sources": {"terms": {"field": "source.ip", "size": 6}},
                    "destinations": {"terms": {"field": "destination.ip", "size": 6}},
                    "ports": {"terms": {"field": "destination.port", "size": 8}},
                    "indices": {"terms": {"field": "_index", "size": 8}},
                },
            }

            session = get_es_client()

            # Total counts
            r = session.post(f"{ELASTICSEARCH_URL}/{index_str}/_count", json={"query": range_q}, timeout=10)
            total_events = int(r.json().get("count", 0)) if r.status_code == 200 else 0

            r = session.post(f"{ELASTICSEARCH_URL}/security-response-*/_count", json={"query": range_q}, timeout=10)
            total_alerts = int(r.json().get("count", 0)) if r.status_code == 200 else 0

            # Timeline
            timeline: list[dict] = []
            try:
                r = session.post(f"{ELASTICSEARCH_URL}/{index_str}/_search", json=timeline_payload, timeout=15)
                if r.status_code == 200:
                    timeline = [
                        {"time": b.get("key_as_string"), "count": b.get("doc_count", 0)}
                        for b in (((r.json().get("aggregations") or {}).get("timeline") or {}).get("buckets") or [])
                    ]
            except Exception:
                pass

            # Suricata aggregations
            suricata: dict[str, Any] = {}
            try:
                r = session.post(f"{ELASTICSEARCH_URL}/fda-suricata.eve-*/_search", json=suricata_payload, timeout=15)
                if r.status_code == 200:
                    suricata = r.json()
            except Exception:
                pass

            sev_aggs = suricata.get("aggregations") or {}
            analytics = {
                "timeline": timeline,
                "severity_distribution": [],
                "engine_distribution": [],
                "suricata_protocols": [
                    {"label": b.get("key") or "unknown", "value": b.get("doc_count", 0)}
                    for b in ((sev_aggs.get("protocols") or {}).get("buckets") or [])
                ],
                "suricata_event_types": [
                    {"label": b.get("key") or "unknown", "value": b.get("doc_count", 0)}
                    for b in ((sev_aggs.get("event_types") or {}).get("buckets") or [])
                ],
                "top_sources": [
                    {"label": b.get("key") or "unknown", "value": b.get("doc_count", 0)}
                    for b in ((sev_aggs.get("sources") or {}).get("buckets") or [])
                ],
                "top_destinations": [
                    {"label": b.get("key") or "unknown", "value": b.get("doc_count", 0)}
                    for b in ((sev_aggs.get("destinations") or {}).get("buckets") or [])
                ],
                "source_indices": [
                    {"label": b.get("key") or "unknown", "value": b.get("doc_count", 0)}
                    for b in ((sev_aggs.get("indices") or {}).get("buckets") or [])
                ],
                "top_ports": [],
                "agent_run_mix": [],
                "top_usernames": [],
                "network_transports": [],
            }

            return {
                "rules_total": 0,
                "logs_total": total_events,
                "elastic_alerts_total": total_alerts,
                "wazuh_alerts_total": total_alerts,
                "suricata_events_total": total_events,
                "response_actions_total": 0,
                "latest_alerts": [],
                "zeroclaw": {"available": False, "summary": "elasticsearch mode"},
                "analytics": analytics,
            }
        except Exception as exc:
            logger.debug("ES get_analytics_summary failed (%s); falling back to SQLite", exc)

    # SQLite fallback
    where, args = _build_where(start, end, run_id, indices, sources)
    from collections import Counter

    with _lock:
        conn = get_conn()
        total_events = conn.execute(f"SELECT COUNT(*) as c FROM events WHERE {where}", args).fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts", []).fetchone()["c"]

        timeline = []
        ts_col = "timestamp"
        try:
            rows = conn.execute(
                f"""
                SELECT strftime('%Y-%m-%dT%H:00:00Z', {ts_col}) as bucket, COUNT(*) as count
                FROM events WHERE {where} GROUP BY bucket ORDER BY bucket
                """,
                args,
            ).fetchall()
            timeline = [{"time": r["bucket"], "count": r["count"]} for r in rows]
        except Exception:
            pass

        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM events WHERE source IN ('suricata','wazuh','elastic') AND 1=1 GROUP BY severity ORDER BY count DESC"
        ).fetchall()
        sev_alerts = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC"
        ).fetchall()

        all_sev = Counter()
        for r in sev_rows:
            all_sev[r["severity"]] += r["count"]
        for r in sev_alerts:
            all_sev[r["severity"]] += r["count"]

        severity_dist = [{"label": s, "value": c} for s, c in all_sev.most_common()]

        engine_rows = conn.execute(
            "SELECT engine, COUNT(*) as count FROM events WHERE engine IS NOT NULL GROUP BY engine ORDER BY count DESC"
        ).fetchall()
        engine_dist = [{"label": r["engine"], "value": r["count"]} for r in engine_rows]

        top_sources = conn.execute(
            "SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 6",
        ).fetchall()
        top_sources_list = [{"label": r["source_ip"], "value": r["count"]} for r in top_sources]

        top_dests = conn.execute(
            "SELECT destination_ip, COUNT(*) as count FROM events WHERE destination_ip IS NOT NULL AND destination_ip != '' GROUP BY destination_ip ORDER BY count DESC LIMIT 6",
        ).fetchall()
        top_destinations = [{"label": r["destination_ip"], "value": r["count"]} for r in top_dests]

        idx_rows = conn.execute(
            f"SELECT index_name AS label, COUNT(*) as count FROM events WHERE {where} GROUP BY index_name ORDER BY count DESC LIMIT 8",
            args,
        ).fetchall()
        source_indices = [{"label": r["label"], "value": r["count"]} for r in idx_rows]

        event_types = conn.execute(
            "SELECT suricata_event_type, COUNT(*) as count FROM events WHERE source='suricata' AND suricata_event_type IS NOT NULL GROUP BY suricata_event_type ORDER BY count DESC LIMIT 8"
        ).fetchall()
        suricata_types = [{"label": r["suricata_event_type"], "value": r["count"]} for r in event_types]

        protos = conn.execute(
            """SELECT network_transport as proto, COUNT(*) as count FROM events
               WHERE source='suricata' AND network_transport IS NOT NULL GROUP BY network_transport ORDER BY count DESC LIMIT 6"""
        ).fetchall()
        suricata_protos = [{"label": r["proto"], "value": r["count"]} for r in protos]

        top_ports = conn.execute(
            "SELECT destination_port AS port, COUNT(*) AS count FROM events WHERE destination_port IS NOT NULL GROUP BY destination_port ORDER BY count DESC LIMIT 8"
        ).fetchall()
        top_ports_list = [{"label": str(r["port"]), "value": r["count"]} for r in top_ports]

        agent_run_mix = conn.execute(
            "SELECT engine AS label, COUNT(*) AS value FROM events WHERE source='response' AND engine IS NOT NULL GROUP BY engine ORDER BY value DESC LIMIT 8"
        ).fetchall()
        agent_run_mix_list = [{"label": r["label"], "value": r["value"]} for r in agent_run_mix]

        user_rows = conn.execute(
            "SELECT user_name AS label, COUNT(*) AS value FROM events WHERE user_name IS NOT NULL AND user_name != '' GROUP BY user_name ORDER BY value DESC LIMIT 8"
        ).fetchall()
        top_usernames = [{"label": r["label"], "value": r["value"]} for r in user_rows]

        transport_rows = conn.execute(
            "SELECT network_transport AS label, COUNT(*) AS value FROM events WHERE network_transport IS NOT NULL GROUP BY network_transport ORDER BY value DESC LIMIT 8"
        ).fetchall()
        network_transports = [{"label": r["label"], "value": r["value"]} for r in transport_rows]

        rules_total = conn.execute("SELECT COUNT(*) as c FROM rules").fetchone()["c"]
        response_actions_total = conn.execute("SELECT COUNT(*) as c FROM events WHERE source='response'").fetchone()["c"]

    return {
        "rules_total": rules_total,
        "logs_total": total_events,
        "elastic_alerts_total": total_alerts,
        "wazuh_alerts_total": total_alerts,
        "suricata_events_total": total_events,
        "response_actions_total": response_actions_total,
        "latest_alerts": [],
        "zeroclaw": {"available": False, "summary": "standalone mode"},
        "analytics": {
            "timeline": timeline,
            "severity_distribution": severity_dist,
            "engine_distribution": engine_dist,
            "suricata_protocols": suricata_protos,
            "suricata_event_types": suricata_types,
            "top_sources": top_sources_list,
            "top_destinations": top_destinations,
            "top_ports": top_ports_list,
            "agent_run_mix": agent_run_mix_list,
            "top_usernames": top_usernames,
            "network_transports": network_transports,
            "source_indices": source_indices,
        },
    }


# ---------------------------------------------------------------------------
# Run management (SQLite only — runs are a runtime concept)
# ---------------------------------------------------------------------------

def start_run(name: str | None = None, note: str | None = None) -> dict[str, Any]:
    run_id = str(uuid4())[:8]
    now = _now_iso()
    with _lock:
        conn = get_conn()
        conn.execute("UPDATE runs SET active=0, stopped_at=? WHERE active=1", (now,))
        conn.execute(
            "INSERT INTO runs (run_id, name, note, active, started_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (run_id, name or "", note or "", now, now),
        )
        conn.commit()
    return {"active": True, "run_id": run_id, "started_at": now, "name": name, "note": note}


def stop_run() -> dict[str, Any]:
    now = _now_iso()
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT run_id, started_at FROM runs WHERE active=1 ORDER BY started_at DESC LIMIT 1").fetchone()
        if not row:
            return {"active": False, "run_id": None}
        duration = (datetime.now(timezone.utc) - _parse_iso(row["started_at"])).total_seconds()
        conn.execute("UPDATE runs SET active=0, stopped_at=? WHERE active=1", (now,))
        conn.commit()
    return {"active": False, "run_id": row["run_id"], "stopped_at": now, "duration_seconds": duration}


def current_run() -> dict[str, Any]:
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT * FROM runs WHERE active=1 ORDER BY started_at DESC LIMIT 1").fetchone()
    if not row:
        return {"active": False}
    return dict(row)


def save_run(name: str, note: str | None = None) -> dict[str, Any]:
    now = _now_iso()
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT run_id, started_at FROM runs WHERE active=1 ORDER BY started_at DESC LIMIT 1").fetchone()
        if not row:
            return {"active": False}
        conn.execute("UPDATE runs SET saved=1, saved_at=?, stopped_at=?, active=0 WHERE run_id=?", (now, now, row["run_id"]))
        conn.commit()
    return {"active": False, "run_id": row["run_id"], "saved_at": now, "name": name}


def run_history(limit: int = 20) -> list[dict[str, Any]]:
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Rules catalog
# ---------------------------------------------------------------------------

def index_rule(rule_doc: dict[str, Any]) -> None:
    """Upsert a rule into both ES rule-catalog and SQLite rules table."""
    import json as _json
    from app_shared.text_utils import normalize_severity

    rule_id = rule_doc.get("rule_id") or rule_doc.get("id", "")
    if not rule_id:
        return

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            es_doc = {
                "rule_id": rule_id,
                "engine": rule_doc.get("engine", ""),
                "title": rule_doc.get("title", ""),
                "description": rule_doc.get("description", ""),
                "severity": rule_doc.get("severity", "medium"),
                "technique_ids": rule_doc.get("technique_ids", []),
                "mitre_ids": rule_doc.get("mitre_ids", []),
                "path": rule_doc.get("file_path", ""),
                "search_text": " ".join([
                    rule_doc.get("title", ""),
                    rule_doc.get("description", ""),
                    rule_doc.get("query", ""),
                ]),
                "raw": _json.dumps(rule_doc, default=str),
            }
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/rule-catalog/_doc/{rule_id}",
                data=_json.dumps(es_doc).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code in (200, 201):
                logger.debug("ES index_rule ok: %s", rule_id)
            else:
                logger.debug("ES index_rule %s -> SQLite", r.status_code)
        except Exception as exc:
            logger.debug("ES index_rule failed (%s); falling back to SQLite", exc)

    with _lock:
        conn = get_conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO rules (rule_id, engine, title, description, severity,
                technique_ids, mitre_ids, file_path, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id,
                rule_doc.get("engine", ""),
                rule_doc.get("title", ""),
                rule_doc.get("description", ""),
                (lambda s: s.get("label", "medium") if isinstance(s, dict) else str(s))(normalize_severity(rule_doc.get("severity", "medium"))),
                _json.dumps(rule_doc.get("technique_ids", []) or []),
                _json.dumps(rule_doc.get("mitre_ids", []) or []),
                rule_doc.get("file_path", ""),
                _json.dumps(rule_doc, default=str),
            ),
        )
        conn.commit()


def search_rules(q: str, limit: int = 10, engines: list[str] | None = None) -> list[dict[str, Any]]:
    """Search rules.  ES first, SQLite fallback."""
    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client

            filters: list[dict[str, Any]] = []
            if engines:
                filters.append({"terms": {"engine": engines}})

            payload = {
                "size": limit,
                "query": {
                    "bool": {
                        "must": {
                            "multi_match": {
                                "query": q,
                                "type": "best_fields",
                                "fields": [
                                    "title^5", "description^4", "query^3",
                                    "search_text^6", "tags^2", "product^2",
                                    "service^2", "category^2", "path^2",
                                ],
                            }
                        },
                        "filter": filters,
                    }
                },
            }
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/rule-catalog/_search",
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                results = []
                for hit in data.get("hits", {}).get("hits", []):
                    src = hit.get("_source", {})
                    results.append({
                        "score": float(hit.get("_score") or 0),
                        **src,
                        "mitre_ids": src.get("mitre_ids", []),
                    })
                return results
        except Exception as exc:
            logger.debug("ES search_rules failed (%s); falling back to SQLite", exc)

    # SQLite fallback
    import json as _json
    patterns = [f"%{q}%"] * 3
    sql = "SELECT raw FROM rules WHERE (title LIKE ? OR rule_id LIKE ? OR description LIKE ?)"
    args: list = list(patterns)
    if engines:
        placeholders = ", ".join("?" * len(engines))
        sql += f" AND engine IN ({placeholders})"
        args.extend(engines)
    sql += " ORDER BY title LIMIT ?"
    args.append(limit)
    with _lock:
        conn = get_conn()
        rows = conn.execute(sql, args).fetchall()
    results = []
    for row in rows:
        try:
            raw_str = _decompress_raw(row["raw"])
            doc = _json.loads(raw_str)
            results.append(doc)
        except (ValueError, TypeError):
            results.append({"raw": row["raw"]})
    return results


def find_rule(rule_id: str) -> dict[str, Any] | None:
    """Find a single rule by ID.  ES first, SQLite fallback."""
    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            candidate_ids = [rule_id]
            if rule_id.startswith("sigma-"):
                candidate_ids.append(rule_id.removeprefix("sigma-"))
            for candidate in candidate_ids:
                payload = {"size": 1, "query": {"term": {"rule_id": candidate}}}
                session = get_es_client()
                r = session.post(
                    f"{ELASTICSEARCH_URL}/rule-catalog/_search",
                    json=payload,
                    timeout=10,
                )
                if r.status_code == 200:
                    hits = r.json().get("hits", {}).get("hits", [])
                    if hits:
                        src = hits[0].get("_source", {})
                        return {
                            "score": float(hits[0].get("_score") or 0),
                            **src,
                            "mitre_ids": src.get("mitre_ids", []),
                        }
        except Exception as exc:
            logger.debug("ES find_rule failed (%s); falling back to SQLite", exc)

    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT raw FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if not row:
        return None
    import json as _json
    try:
        raw_str = _decompress_raw(row["raw"])
        return _json.loads(raw_str)
    except (ValueError, TypeError):
        return {"raw": row["raw"]}


# ---------------------------------------------------------------------------
# State KV
# ---------------------------------------------------------------------------

def set_kv(key: str, value: Any) -> None:
    import json as _json
    with _lock:
        conn = get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO state_kv (key, value) VALUES (?, ?)",
            (key, _json.dumps(value)),
        )
        conn.commit()


def get_kv(key: str, default: Any = None) -> Any:
    import json as _json
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT value FROM state_kv WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return _json.loads(row["value"])
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def prune_events(retention_hours: int = 24) -> dict[str, Any]:
    """Delete events older than *retention_hours*."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=retention_hours)).isoformat()

    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            session = get_es_client()
            for index in ["fda-suricata.eve-*", "wazuh-alerts-*", "security-response-*", ".alerts-security.alerts-*"]:
                payload = {
                    "query": {
                        "range": {"@timestamp": {"lt": cutoff}}
                    }
                }
                r = session.post(
                    f"{ELASTICSEARCH_URL}/{index}/_delete_by_query",
                    json=payload,
                    timeout=30,
                )
                if r.status_code == 200:
                    logger.debug("ES prune %s: deleted=%s", index, r.json().get("deleted", 0))
        except Exception as exc:
            logger.debug("ES prune_events failed (%s); falling back to SQLite", exc)

    with _lock:
        conn = get_conn()
        deleted_events = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,)).rowcount
        deleted_alerts = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,)).rowcount
        conn.commit()
        # Reclaim disk for the deleted pages. incremental_vacuum (with
        # auto_vacuum=INCREMENTAL) moves free pages to the end of the file and
        # truncates, without the full-database rewrite of plain VACUUM.
        pages_freed = 0
        try:
            mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
            if mode == 2:  # INCREMENTAL
                before = conn.execute("PRAGMA freelist_count").fetchone()[0]
                conn.execute("PRAGMA incremental_vacuum(512)")
                conn.commit()
                after = conn.execute("PRAGMA freelist_count").fetchone()[0]
                pages_freed = max(before - after, 0)
        except sqlite3.Error as exc:
            logger.debug("incremental_vacuum skipped: %s", exc)
    return {
        "cutoff": cutoff,
        "retention_hours": retention_hours,
        "events_removed": deleted_events,
        "alerts_removed": deleted_alerts,
        "pages_freed": pages_freed,
        "pruned": True,
    }


# ---------------------------------------------------------------------------
# ES-compatible aliases (used by orchestration_engine.py)
# ---------------------------------------------------------------------------

def es_count(index: str, query: dict[str, Any] | None = None) -> int:
    """ES-style count. Uses ES if available, SQLite fallback."""
    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/{index}/_count",
                json={"query": query or {"match_all": {}}},
                timeout=10,
            )
            if r.status_code == 200:
                return int(r.json().get("count", 0))
        except Exception as exc:
            logger.debug("ES es_count failed (%s); falling back to SQLite", exc)
    
    # Fallback to SQLite count_events
    return count_events(sources=[index])


def es_search(index: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """ES-style search. Uses ES if available, SQLite fallback."""
    if es_available():
        try:
            from app_shared.es_client import ELASTICSEARCH_URL, get_es_client
            session = get_es_client()
            r = session.post(
                f"{ELASTICSEARCH_URL}/{index}/_search",
                json=payload,
                timeout=15,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                return [hit.get("_source", {}) for hit in hits]
        except Exception as exc:
            logger.debug("ES es_search failed (%s); falling back to SQLite", exc)
    
    # Fallback to SQLite query_events
    size = payload.get("size", 10)
    query = payload.get("query", {})
    run_id = None
    start = None
    end = None
    
    # Extract run_id from query
    if "bool" in query:
        for must in query["bool"].get("must", []):
            if "term" in must:
                for k, v in must["term"].items():
                    if "run_id" in k:
                        run_id = v
    
    # Extract time range
    for m in query.get("bool", {}).get("must", []):
        if "range" in m and "@timestamp" in m.get("range", {}):
            ts = m["range"]["@timestamp"]
            start = ts.get("gte")
            end = ts.get("lte")
    
    events = query_events(
        sources=[index],
        start=start,
        end=end,
        run_id=run_id,
        limit=size,
        query="",
    )
    return events
