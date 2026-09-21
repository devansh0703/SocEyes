"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type Health = {
  status?: string;
  simulation?: boolean;
  zeroclaw?: boolean;
  elasticsearch?: boolean;
};

type RuntimePolicy = {
  auto_execute?: boolean;
  engines?: Record<string, boolean>;
};

type EventStatus = {
  event_receiver_running?: boolean;
  event_queue_size?: number;
};

/** Top status bar: the flight-deck annunciation strip.
 *  Live capture telemetry + enforcement mode + clock. Polls the three
 *  lightweight health endpoints on a slow loop; failures show a red
 *  DOWN state instead of hiding the bar. */
export function TopBar() {
  const [health, setHealth] = useState<Health | null>(null);
  const [events, setEvents] = useState<EventStatus | null>(null);
  const [policy, setPolicy] = useState<RuntimePolicy | null>(null);
  const [captured, setCaptured] = useState<number | null>(null);
  const [clock, setClock] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      const [h, e, p] = await Promise.all([
        apiFetch<Health>("/api/health").catch(() => null),
        apiFetch<EventStatus>("/api/events/status").catch(() => null),
        apiFetch<RuntimePolicy>("/api/response/policy").catch(() => null),
      ]);
      if (!active) return;
      setHealth(h);
      setEvents(e);
      setPolicy(p);
    };
    const captureCount = async () => {
      const d = await apiFetch<{ analytics?: { source_indices?: Array<{ label: string; value: number }> } }>("/api/dashboard").catch(() => null);
      if (!active || !d) return;
      const total = (d.analytics?.source_indices || []).reduce((acc, s) => acc + (s.value || 0), 0);
      setCaptured(total);
    };
    load();
    captureCount();
    const tick = setInterval(() => setClock(new Date().toLocaleTimeString([], { hour12: false })), 1000);
    const poll = setInterval(() => { load(); captureCount(); }, 5000);
    return () => {
      active = false;
      clearInterval(tick);
      clearInterval(poll);
    };
  }, []);

  const engineCount = health?.elasticsearch ? 4 : 3;
  const receiverUp = events?.event_receiver_running !== false;
  const enforcementMode = policy?.auto_execute ? "AUTO-RESPONSE ARMED" : "MANUAL MODE";

  return (
    <header className="topbar">
      <div className="topbar-brand">
        <div className="topbar-mark" />
        <span>SOCEYES</span>
      </div>

      <div className="topbar-telemetry">
        <span className="tele-item">
          <span className={`pulse-dot ${receiverUp ? "" : "down"}`} />
          capture
          <span className="tele-value">
            {captured === null ? "…" : captured.toLocaleString()}
          </span>
          pkts
        </span>
        <span className="tele-item">
          queue
          <span className="tele-value">{events?.event_queue_size ?? "…"}</span>
        </span>
        <span className="tele-item">
          engines
          <span className="tele-value">{engineCount}</span>
        </span>
        <span className="tele-item">
          orchestrator
          <span className={`tele-value ${health?.zeroclaw ? "" : "down"}`}>
            {health?.zeroclaw ? "running" : "down"}
          </span>
        </span>
      </div>

      <div className="topbar-right">
        <span className={`status-pill ${policy?.auto_execute ? "armed" : ""}`}>
          {enforcementMode}
        </span>
        <span className="topbar-clock">{clock || "—"}</span>
      </div>
    </header>
  );
}
