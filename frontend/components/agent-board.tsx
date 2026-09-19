"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type HandRun = {
  hand_name: string;
  run_id: string;
  status: { status: string; error?: string };
  findings: string[];
  steps: Array<{ title: string; detail: string; status: string; timestamp?: string }>;
  metrics: Record<string, string | number>;
  duration_ms?: number;
};

type ZeroClawStatus = {
  available: boolean;
  status?: string;
  summary: string;
  lines?: string[];
  daemon?: {
    reachable?: boolean;
    url?: string;
    status?: string;
    paired?: boolean;
    pairing_required?: boolean;
    uptime_seconds?: number;
    scheduler_status?: string;
    gateway_status?: string;
  };
};

type AgentsPayload = {
  hands: HandRun[];
  zeroclaw?: ZeroClawStatus;
};

export function AgentBoard({ embedded }: { embedded?: AgentsPayload }) {
  const [payload, setPayload] = useState<AgentsPayload>(embedded || { hands: [] });
  const [selected, setSelected] = useState<HandRun | null>(embedded?.hands[0] || null);
  const [history, setHistory] = useState<HandRun[]>([]);

  useEffect(() => {
    if (embedded?.hands.length) {
      setPayload(embedded);
      setSelected((current) => current || embedded.hands[0]);
      return;
    }
    let active = true;
    const load = async () => {
      const live = await apiFetch<AgentsPayload>("/api/agents/live");
      if (!active) {
        return;
      }
      setPayload(live);
      setSelected((current) => current || live.hands[0] || null);
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [embedded]);

  useEffect(() => {
    if (!selected) {
      return;
    }
    apiFetch<{ items: HandRun[] }>(`/api/agents/${selected.hand_name}/history?limit=12`)
      .then((next) => setHistory(next.items))
      .catch(() => {});
  }, [selected]);

  return (
    <div className="panel padded">
      <div className="panel-head">
        <div>
          <span className="kicker">ZeroClaw orchestration</span>
          <h2>Agents, validation, bandwidth, and runtime detail</h2>
        </div>
      </div>
      <div className="agent-layout">
        <div className="agent-list">
          {payload.hands.map((hand) => (
            <button key={hand.hand_name} className={`agent-card ${selected?.hand_name === hand.hand_name ? "selected" : ""}`} onClick={() => setSelected(hand)}>
              <div className="agent-headline">
                <div className="agent-name">{hand.hand_name.replaceAll("_", " ")}</div>
                <div className={`agent-status ${hand.status.status}`}>{hand.status.status}</div>
              </div>
              <p>{hand.findings[0] || "Live orchestration check recorded."}</p>
            </button>
          ))}
        </div>
        <div className="agent-detail">
          {selected ? (
            <>
              <div className="detail-card">
                <div className="detail-header">
                  <h3>{selected.hand_name.replaceAll("_", " ")}</h3>
                  <span className="chip accent">{selected.duration_ms ? `${selected.duration_ms} ms` : "live"}</span>
                </div>
                <p>{selected.findings.join(" ")}</p>
              </div>
              <div className="detail-card">
                <h3>Orchestration steps</h3>
                <div className="terminal-window">
                  {selected.steps.map((step) => (
                    <div key={`${selected.run_id}-${step.title}-${step.detail}`} className="terminal-line">
                      $ [{step.status}] {step.title}: {step.detail}
                    </div>
                  ))}
                </div>
              </div>
              <div className="detail-card">
                <h3>Metrics</h3>
                <div className="metric-pills">
                  {Object.entries(selected.metrics).map(([key, value]) => (
                    <div key={key} className="metric-pill">
                      <span>{key.replaceAll("_", " ")}</span>
                      <strong>{String(value)}</strong>
                    </div>
                  ))}
                </div>
              </div>
              <div className="detail-card">
                <h3>Recent terminal sessions</h3>
                <div className="terminal-window">
                  {history.map((run) => (
                    <div key={run.run_id} className="terminal-line">
                      $ {run.run_id} {"->"} {run.status.status}
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="detail-card"><p>No agent selected.</p></div>
          )}
          <div className="detail-card">
            <h3>ZeroClaw runtime</h3>
            {payload.zeroclaw?.available ? (
              <div className="detail-stack tight">
                <p>{payload.zeroclaw.summary}</p>
                {payload.zeroclaw.daemon && payload.zeroclaw.daemon.reachable ? (
                  <div className="metric-pills">
                    <div className="metric-pill">
                      <span>gateway</span>
                      <strong>{payload.zeroclaw.daemon.gateway_status || payload.zeroclaw.daemon.status || "ok"}</strong>
                    </div>
                    <div className="metric-pill">
                      <span>scheduler</span>
                      <strong>{payload.zeroclaw.daemon.scheduler_status || "ok"}</strong>
                    </div>
                    <div className="metric-pill">
                      <span>pairing</span>
                      <strong>{payload.zeroclaw.daemon.pairing_required ? "required" : "ready"}</strong>
                    </div>
                    <div className="metric-pill">
                      <span>uptime</span>
                      <strong>{payload.zeroclaw.daemon.uptime_seconds || 0}s</strong>
                    </div>
                  </div>
                ) : null}
                <div className="history-list">
                  {(payload.zeroclaw.lines || []).map((line) => (
                    <div key={line} className="terminal-line">
                      $ {line}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p>{payload.zeroclaw?.summary || "ZeroClaw runtime is not available in this environment."}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
