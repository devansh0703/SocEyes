"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { Bell, Bot, History, LayoutDashboard, PlaySquare, Radar, ScrollText, ShieldCheck } from "lucide-react";

import { apiFetch } from "../lib/api";
import { readCached, writeCached } from "../lib/client-cache";
import { useGlobalViewState } from "../lib/view-state";

const items = [
  { href: "/", label: "Mission", icon: Radar },
  { href: "/dashboard", label: "Command Center", icon: LayoutDashboard },
  { href: "/logs", label: "Logs", icon: ScrollText },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/runs", label: "Runs", icon: History },
  { href: "/playbooks", label: "Playbooks", icon: PlaySquare },
  { href: "/responses", label: "Responses", icon: ShieldCheck },
  { href: "/agents", label: "Agents", icon: Bot },
];

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

function splitDateTime(value: string): { date: string; time: string } {
  if (!value) {
    return { date: "", time: "" };
  }
  const [date, time = ""] = value.split("T");
  return { date, time: time.slice(0, 5) };
}

function combineDateTime(date: string, time: string): string {
  if (!date) {
    return "";
  }
  return `${date}T${time || "00:00"}`;
}

export function Nav() {
  const pathname = usePathname();
  const [viewState, setViewState] = useGlobalViewState();
  const [runState, setRunState] = useState<RunState>(() => readCached<RunState>("fda-cache:run-current") || { active: false });
  const [history, setHistory] = useState<RunState[]>(() => readCached<RunState[]>("fda-cache:run-history") || []);
  const autoStartInFlight = useRef(false);
  const lastAutoStartAttemptMs = useRef(0);
  const [fromDate, setFromDate] = useState("");
  const [fromTime, setFromTime] = useState("");
  const [toDate, setToDate] = useState("");
  const [toTime, setToTime] = useState("");

  useEffect(() => {
    const from = splitDateTime(viewState.start);
    const to = splitDateTime(viewState.end);
    setFromDate(from.date);
    setFromTime(from.time);
    setToDate(to.date);
    setToTime(to.time);
  }, [viewState.start, viewState.end]);

  async function refreshRuns(options?: { autoStartIfIdle?: boolean }) {
    const [current, past] = await Promise.all([
      apiFetch<RunState>("/api/runs/current"),
      apiFetch<{ items: RunState[] }>("/api/runs/history?limit=40"),
    ]);
    if (options?.autoStartIfIdle && !current.active) {
      const now = Date.now();
      if (!autoStartInFlight.current && now - lastAutoStartAttemptMs.current > 10000) {
        autoStartInFlight.current = true;
        lastAutoStartAttemptMs.current = now;
        try {
          await apiFetch<RunState>("/api/runs/start", {
            method: "POST",
            body: JSON.stringify({ name: "Auto live session", note: "Automatically started on app open" }),
          });
        } finally {
          autoStartInFlight.current = false;
        }
        const [startedCurrent, startedPast] = await Promise.all([
          apiFetch<RunState>("/api/runs/current"),
          apiFetch<{ items: RunState[] }>("/api/runs/history?limit=40"),
        ]);
        setRunState(startedCurrent);
        setHistory(startedPast.items);
        writeCached("fda-cache:run-current", startedCurrent);
        writeCached("fda-cache:run-history", startedPast.items);
        return;
      }
    }
    setRunState(current);
    setHistory(past.items);
    writeCached("fda-cache:run-current", current);
    writeCached("fda-cache:run-history", past.items);
  }

  useEffect(() => {
    refreshRuns({ autoStartIfIdle: true }).catch(() => {});
    const interval = setInterval(() => refreshRuns({ autoStartIfIdle: true }).catch(() => {}), 5000);
    return () => clearInterval(interval);
  }, []);

  const runOptions = useMemo(() => {
    const map = new Map<string, RunState>();
    if (runState.active && runState.run_id) {
      map.set(runState.run_id, runState);
    }
    history.forEach((item) => {
      if (item.run_id) {
        map.set(item.run_id, item);
      }
    });
    return Array.from(map.values());
  }, [runState, history]);

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-mark" />
        <div>
          <div className="sidebar-title">FDA Cyber Control</div>
          <div className="sidebar-subtitle">Elastic, Wazuh, Suricata, ZeroClaw Hands</div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {items.map((item) => {
          const Icon = item.icon;
          const active = pathname === item.href;
          return (
            <Link key={item.href} href={item.href} className={`sidebar-link ${active ? "active" : ""}`}>
              <Icon size={18} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="sidebar-control panel-soft">
        <div className="sidebar-control-title">Date and time filter</div>
        <label className="sidebar-label">
          From date
          <input
            type="date"
            value={fromDate}
            onChange={(event) => {
              const date = event.target.value;
              setFromDate(date);
              setViewState({ ...viewState, preset: "", start: combineDateTime(date, fromTime), end: combineDateTime(toDate, toTime) });
            }}
          />
        </label>
        <label className="sidebar-label">
          From time
          <input
            type="time"
            value={fromTime}
            onChange={(event) => {
              const time = event.target.value;
              setFromTime(time);
              setViewState({ ...viewState, preset: "", start: combineDateTime(fromDate, time), end: combineDateTime(toDate, toTime) });
            }}
          />
        </label>
        <label className="sidebar-label">
          To date
          <input
            type="date"
            value={toDate}
            onChange={(event) => {
              const date = event.target.value;
              setToDate(date);
              setViewState({ ...viewState, preset: "", start: combineDateTime(fromDate, fromTime), end: combineDateTime(date, toTime) });
            }}
          />
        </label>
        <label className="sidebar-label">
          To time
          <input
            type="time"
            value={toTime}
            onChange={(event) => {
              const time = event.target.value;
              setToTime(time);
              setViewState({ ...viewState, preset: "", start: combineDateTime(fromDate, fromTime), end: combineDateTime(toDate, time) });
            }}
          />
        </label>
      </div>

      <div className="sidebar-control panel-soft">
        <div className="sidebar-control-title">Run context</div>
        <div className="sidebar-run-state">{runState.active ? `Active: ${runState.name || runState.run_id}` : "No active run"}</div>
        <p className="sidebar-subtitle">Live session auto-starts when the app opens.</p>
        <label className="sidebar-label">
          Selected run
          <select
            value={viewState.selectedRunId}
            onChange={(event) => setViewState({ ...viewState, selectedRunId: event.target.value })}
          >
            <option value="">All runs</option>
            {runOptions.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {run.run_id} {run.saved ? "(saved)" : ""}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="sidebar-foot">
        <div className="chip accent">Realtime</div>
        <p>Human-readable rules, playbooks, agent steps, and response previews.</p>
      </div>
    </aside>
  );
}
