"""SQLite-backed event store for the standalone (non-Docker) package.

Replaces Elasticsearch in single-binary mode.  Provides the same
high-level data shapes that ``services.py`` produced from ES queries,
so the API and frontend remain unchanged.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app_shared.text_utils import clean_text, normalize_severity, now_utc

_lock = threading.RLock()
_DEFAULT_DB = Path(__file__).resolve().parent.parent / "state" / "fda_events.sqlite"
_conn: sqlite3.Connection | None = None


def init_db(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (or create) the SQLite database and ensure tables exist."""
    global _conn
    if db_path is None:
        db_path = _DEFAULT_DB
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    from app_shared.db_maintenance import apply_footprint_pragmas, start_wal_maintenance
    apply_footprint_pragmas(conn)
    start_wal_maintenance(str(db_path))
    # Raw events from all sources
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id        TEXT PRIMARY KEY,
            source    TEXT NOT NULL,              -- e.g. 'wazuh', 'suricata', 'elastic', 'response', 'run'
            index_name TEXT NOT NULL,            -- original ES index it came from
            timestamp TEXT NOT NULL,              -- ISO 8601
            severity  TEXT,                      -- 'low'|'medium'|'high'|'critical'
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
            technique_ids TEXT,                  -- JSON array
            run_id    TEXT,
            raw       TEXT,                      -- original document JSON
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source);
        CREATE INDEX IF NOT EXISTS idx_events_run     ON events(run_id);
        CREATE INDEX IF NOT EXISTS idx_events_sev     ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_rule    ON events(rule_id);

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
    conn.commit()
    with _lock:
        _conn = conn
    return conn


def get_conn() -> sqlite3.Connection:
    if _conn is None:
        return init_db()
    return _conn


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Event ingest (simulated Suricata / Wazuh / Elastic sources)
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
) -> str:
    """Insert a single event."""
    event_id = str(uuid4())
    ts = timestamp or _now_iso()
    sev = normalize_severity(severity)
    sev_label = sev.get("label", "medium") if isinstance(sev, dict) else str(sev)
    technique_json = json.dumps(technique_ids or [])
    raw_json = json.dumps(raw or {})

    with _lock:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO events (id, source, index_name, timestamp, severity,
                engine, title, message, rule_id, host_name, user_name,
                source_ip, destination_ip, destination_port, network_transport,
                suricata_event_type, process_name, process_command_line,
                technique_ids, run_id, raw, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, source, index_name, ts, sev_label, engine, title, message,
                rule_id, host_name, user_name, source_ip, destination_ip,
                destination_port, network_transport, suricata_event_type,
                process_name, process_command_line, technique_json, run_id,
                raw_json, _now_iso(),
            ),
        )
        conn.commit()
    return event_id


# ---------------------------------------------------------------------------
# Alerting — correlated alerts across all sources
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
    """Insert a correlated alert and return its ID."""
    alert_id = str(uuid4())
    ts = timestamp or _now_iso()
    technique_json = json.dumps(technique_ids or [])
    preview_json = json.dumps(response_preview or {})
    sev_label = normalize_severity(severity)
    sev_label = sev_label.get("label", "medium") if isinstance(sev_label, dict) else str(sev_label)

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
# Querying helpers
# ---------------------------------------------------------------------------

_SOURCE_INDEX_MAP = {
    "suricata": "fda-suricata.eve-*",
    "wazuh": "wazuh-alerts-*",
    "elastic": ".alerts-security.alerts-*",
    "response": "security-response-*",
    "run": "fda-runs-*",
}


def _source_indices(sources: list[str] | None) -> list[str]:
    if not sources:
        return list(_SOURCE_INDEX_MAP.values())
    return [_SOURCE_INDEX_MAP.get(s, s) for s in sources]


def _build_where(start: str | None, end: str | None, run_id: str | None, sources: list[str] | None) -> tuple[str, list]:
    clauses: list[str] = ["1=1"]
    args: list = []
    if start:
        clauses.append("timestamp >= ?")
        args.append(start)
    if end:
        clauses.append("timestamp <= ?")
        args.append(end)
    if run_id:
        clauses.append("run_id = ?")
        args.append(run_id)
    if sources:
        placeholders = ", ".join("?" * len(sources))
        clauses.append(f"index_name IN ({placeholders})")
        args.extend(s for s in sources)
    return " AND ".join(clauses), args


def query_events(
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
    limit: int = 200,
    query: str = "",
) -> list[dict[str, Any]]:
    """Return raw events, optionally filtered by query string."""
    indices = _source_indices(sources)
    where, args = _build_where(start, end, run_id, indices)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    with _lock:
        conn = get_conn()
        rows = conn.execute(sql, args).fetchall()
    events = []
    for row in rows:
        doc: dict[str, Any] = {}
        for key in row.keys():
            val = row[key]
            if key in ("technique_ids", "raw") and val:
                try:
                    val = json.loads(val)
                except (ValueError, TypeError):
                    val = [] if key == "technique_ids" else {}
            doc[key] = val
        # Simple text query filter
        if query:
            text = " ".join(
                str(doc.get(k, "")) for k in ("title", "message", "rule_id", "process_name", "source_ip")
            ).lower()
            if query.lower() not in text:
                continue
        events.append(doc)
    return events


def count_events(
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
) -> int:
    indices = _source_indices(sources)
    where, args = _build_where(start, end, run_id, indices)
    with _lock:
        conn = get_conn()
        row = conn.execute(f"SELECT COUNT(*) as c FROM events WHERE {where}", args).fetchone()
    return row["c"]


def search_alerts(
    start: str | None = None,
    end: str | None = None,
    run_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    where, args = _build_where(start, end, run_id, None)
    # Use alerts table directly
    clauses: list[str] = ["1=1"]
    a: list = []
    if start:
        clauses.append("timestamp >= ?"); a.append(start)
    if end:
        clauses.append("timestamp <= ?"); a.append(end)
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
        doc = dict(row)
        if doc.get("technique_ids"):
            try:
                doc["technique_ids"] = json.loads(doc["technique_ids"])
            except (ValueError, TypeError):
                doc["technique_ids"] = []
        if doc.get("response_preview"):
            try:
                doc["response_preview"] = json.loads(doc["response_preview"])
            except (ValueError, TypeError):
                doc["response_preview"] = {}
        results.append(doc)
    return results


def get_latest_alerts(limit: int = 12) -> list[dict[str, Any]]:
    """Return the N most recent correlated alerts with their response_preview."""
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    results = []
    for row in rows:
        doc = dict(row)
        doc["id"] = doc.get("id") or row["run_id"]
        for field in ("technique_ids", "response_preview"):
            if doc.get(field):
                try:
                    doc[field] = json.loads(doc[field])
                except (ValueError, TypeError):
                    doc[field] = [] if field == "technique_ids" else {}
        results.append(doc)
    return results


# ---------------------------------------------------------------------------
# Analytics (replace ES aggregations)
# ---------------------------------------------------------------------------

def get_analytics_summary(sources: list[str] | None = None, start: str | None = None, end: str | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Compute dashboard aggregate stats from SQLite."""
    indices = _source_indices(sources)
    where, args = _build_where(start, end, run_id, indices)

    with _lock:
        conn = get_conn()
        # Total counts
        total_events = conn.execute(f"SELECT COUNT(*) as c FROM events WHERE {where}", args).fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts", []).fetchone()["c"]

        # Timeline (by hour)
        timeline: list[dict] = []
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

        # Severity distribution
        sev_rows = conn.execute(
            """
            SELECT severity, COUNT(*) as count FROM events WHERE source IN ('suricata','wazuh','elastic')
            AND 1=1 GROUP BY severity ORDER BY count DESC
            """
        ).fetchall()
        # Also include alerts
        sev_alerts = conn.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC"
        ).fetchall()

        all_sev = Counter()
        for r in sev_rows:
            all_sev[r["severity"]] += r["count"]
        for r in sev_alerts:
            all_sev[r["severity"]] += r["count"]

        severity_dist = [{"label": s, "value": c} for s, c in all_sev.most_common()]

        # Engine distribution
        engine_rows = conn.execute(
            "SELECT engine, COUNT(*) as count FROM events WHERE engine IS NOT NULL GROUP BY engine ORDER BY count DESC"
        ).fetchall()
        engine_dist = [{"label": r["engine"], "value": r["count"]} for r in engine_rows]

        # Top sources
        top_sources = conn.execute(
            f"SELECT source_ip, COUNT(*) as count FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 6",
        ).fetchall()
        top_sources_list = [{"label": r["source_ip"], "value": r["count"]} for r in top_sources]

        # Top destinations
        top_dests = conn.execute(
            "SELECT destination_ip, COUNT(*) as count FROM events WHERE destination_ip IS NOT NULL AND destination_ip != '' GROUP BY destination_ip ORDER BY count DESC LIMIT 6",
        ).fetchall()
        top_destinations = [{"label": r["destination_ip"], "value": r["count"]} for r in top_dests]

        # Suricata event types
        event_types = conn.execute(
            "SELECT suricata_event_type, COUNT(*) as count FROM events WHERE source='suricata' AND suricata_event_type IS NOT NULL GROUP BY suricata_event_type ORDER BY count DESC LIMIT 8"
        ).fetchall()
        suricata_types = [{"label": r["suricata_event_type"], "value": r["count"]} for r in event_types]

        # Suricata protocols
        protos = conn.execute(
            """SELECT network_transport as proto, COUNT(*) as count FROM events
               WHERE source='suricata' AND network_transport IS NOT NULL GROUP BY network_transport ORDER BY count DESC LIMIT 6"""
        ).fetchall()
        suricata_protos = [{"label": r["proto"], "value": r["count"]} for r in protos]

    return {
        "rules_total": conn.execute("SELECT COUNT(*) as c FROM rules").fetchone()["c"],
        "logs_total": total_events,
        "elastic_alerts_total": total_alerts,
        "wazuh_alerts_total": total_alerts,
        "suricata_events_total": total_events,
        "response_actions_total": conn.execute("SELECT COUNT(*) as c FROM events WHERE source='response'").fetchone()["c"],
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
        },
    }


# ---------------------------------------------------------------------------
# Run management (replaces demo-run state files with SQLite)
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
# Rules catalog (loaded from YAML/JSON files, indexed for search)
# ---------------------------------------------------------------------------

def index_rule(rule_doc: dict[str, Any]) -> None:
    """Upsert a rule into the SQLite rules table."""
    rule_id = rule_doc.get("rule_id") or rule_doc.get("id", "")
    if not rule_id:
        return
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
                json.dumps(rule_doc.get("technique_ids", []) or []),
                json.dumps(rule_doc.get("mitre_ids", []) or []),
                rule_doc.get("file_path", ""),
                json.dumps(rule_doc),
            ),
        )
        conn.commit()


def search_rules(q: str, limit: int = 10, engines: list[str] | None = None) -> list[dict[str, Any]]:
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
            doc = json.loads(row["raw"])
            results.append(doc)
        except (ValueError, TypeError):
            results.append({"raw": row["raw"]})
    return results


def find_rule(rule_id: str) -> dict[str, Any] | None:
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT raw FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if not row:
        # Fall back to file-based lookup
        return None
    try:
        return json.loads(row["raw"])
    except (ValueError, TypeError):
        return {"raw": row["raw"]}


# ---------------------------------------------------------------------------
# State KV (simple key-value for runtime settings)
# ---------------------------------------------------------------------------

def set_kv(key: str, value: Any) -> None:
    with _lock:
        conn = get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO state_kv (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        conn.commit()


def get_kv(key: str, default: Any = None) -> Any:
    with _lock:
        conn = get_conn()
        row = conn.execute("SELECT value FROM state_kv WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row["value"])
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def prune_events(retention_hours: int = 24) -> dict[str, Any]:
    """Delete events older than *retention_hours* from the rolling window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=retention_hours)).isoformat()
    with _lock:
        conn = get_conn()
        deleted_events = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,)).rowcount
        deleted_alerts = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,)).rowcount
        conn.commit()
    return {"cutoff": cutoff, "retention_hours": retention_hours, "events_removed": deleted_events, "alerts_removed": deleted_alerts, "pruned": True}
