"use client";

import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";

type RunState = {
  active: boolean;
  run_id?: string;
  name?: string;
  note?: string;
  started_at?: string;
  stopped_at?: string;
  saved?: boolean;
  saved_at?: string;
};

export default function RunsPage() {
  const [current, setCurrent] = useState<RunState | null>(null);
  const [history, setHistory] = useState<RunState[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setLoading(true);
      const [cur, past] = await Promise.all([
        apiFetch<RunState>("/api/runs/current").catch(() => ({} as RunState)),
        apiFetch<{ items: RunState[] }>("/api/runs/history?limit=40"),
      ]);
      setCurrent(cur);
      setHistory(past.items || []);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to load runs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setActionInProgress("start");
    try {
      await apiFetch("/api/runs/start", {
        method: "POST",
        body: JSON.stringify({ name: "Manual run", note: "" }),
      });
      await refresh();
    } catch (err: any) {
      setError(err.message || "Failed to start run");
    } finally {
      setActionInProgress(null);
    }
  };

  const handleStop = async () => {
    setActionInProgress("stop");
    try {
      await apiFetch("/api/runs/stop", { method: "POST" });
      await refresh();
    } catch (err: any) {
      setError(err.message || "Failed to stop run");
    } finally {
      setActionInProgress(null);
    }
  };

  const handleSave = async () => {
    setActionInProgress("save");
    try {
      await apiFetch("/api/runs/save", {
        method: "POST",
        body: JSON.stringify({ name: current?.name || "Saved run", note: current?.note || "" }),
      });
      await refresh();
    } catch (err: any) {
      setError(err.message || "Failed to save run");
    } finally {
      setActionInProgress(null);
    }
  };

  const formatTime = (ts?: string) => {
    if (!ts) return "—";
    return new Date(ts).toLocaleString();
  };

  const runDuration = (run: RunState) => {
    if (!run.started_at) return "—";
    const start = new Date(run.started_at);
    const end = run.stopped_at ? new Date(run.stopped_at) : new Date();
    const ms = end.getTime() - start.getTime();
    if (ms < 1000) return "< 1s";
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}m ${r}s`;
  };

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Runs</div>
          <h1 className="page-title small">Detection validation runs</h1>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {current?.active ? (
            <>
              <span className="chip accent">Active: {current.name || current.run_id}</span>
              <button className="btn btn-soft" onClick={handleSave} disabled={actionInProgress === "save"}>
                {actionInProgress === "save" ? "Saving…" : "Save run"}
              </button>
              <button className="btn btn-error" onClick={handleStop} disabled={actionInProgress === "stop"}>
                {actionInProgress === "stop" ? "Stopping…" : "Stop run"}
              </button>
            </>
          ) : (
            <button className="btn btn-accent" onClick={handleStart} disabled={actionInProgress === "start"}>
              {actionInProgress === "start" ? "Starting…" : "+ Start run"}
            </button>
          )}
        </div>
      </section>

      {error && <div className="panel" style={{ padding: 16, color: "#60a5fa" }}>{error}</div>}

      <div className="panel">
        <div className="section-head">
          <div>
            <div className="eyebrow">Run history</div>
            <h2 style={{ marginBottom: 6 }}>{history.length} runs recorded</h2>
          </div>
        </div>
        {loading && <p className="subtle">Loading runs…</p>}
        {!loading && history.length === 0 && <p className="subtle">No runs yet. Start one to begin.</p>}
        <table className="data-table">
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Name</th>
              <th>Status</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Saved</th>
            </tr>
          </thead>
          <tbody>
            {history.map((run) => (
              <tr key={run.run_id || "unknown"}>
                <td>{(run.run_id || "").slice(0, 8)}</td>
                <td>{run.name || "—"}</td>
                <td>
                  <span className={`chip ${run.active ? "accent" : "neutral"}`}>
                    {run.active ? "active" : "stopped"}
                  </span>
                </td>
                <td>{formatTime(run.started_at)}</td>
                <td>{runDuration(run)}</td>
                <td>{run.saved ? "✓" : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
