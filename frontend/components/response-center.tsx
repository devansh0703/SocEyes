"use client";

import { useEffect, useState } from "react";

import { apiFetch, buildQuery } from "../lib/api";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";
import { ResponsePolicy } from "./response-policy";

type RuntimeControls = {
  blocked_ips: Array<{ ip?: string; updated_at?: string; reason?: string }>;
  rate_limits: Array<{ path?: string; source_ip?: string; requests_per_minute?: number; updated_at?: string }>;
  disabled_accounts: Array<{ username?: string; updated_at?: string; reason?: string }>;
  isolated_hosts: Array<{ ip?: string; updated_at?: string; reason?: string }>;
  quarantined_endpoints: Array<{ ip?: string; updated_at?: string; reason?: string }>;
};

type AlertItem = {
  engine: string;
  title: string;
  severity: string;
  severity_level?: string;
  warning_level?: string;
  timestamp: string;
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    success_criteria: string;
    warning_level?: string;
    should_honeypot?: boolean;
    severity?: { level?: string; score?: number; label?: string };
    technical_explanation?: string;
    nontechnical_explanation?: string;
  };
};

type HoneypotSession = {
  session_id: string;
  created_at: string;
  container_name: string;
  container_id: string;
  host_port: string;
  severity: string;
  source_ip: string;
  rule_id: string;
  technique_id: string;
  groq_analysis?: string;
  logs: string[];
};

function noJsonLikeText(text: string): string {
  const trimmed = (text || "").trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    return "";
  }
  return text;
}

export function ResponseCenter() {
  const [viewState] = useGlobalViewState();
  const [controls, setControls] = useState<RuntimeControls | null>(null);
  const [responseAlerts, setResponseAlerts] = useState<AlertItem[]>([]);
  const [honeypots, setHoneypots] = useState<HoneypotSession[]>([]);
  const [explanationMode, setExplanationMode] = useState<"technical" | "nontechnical">("technical");

  useEffect(() => {
    const load = async () => {
      const [runtime, alerts, hp] = await Promise.all([
        apiFetch<RuntimeControls>("/api/response/runtime"),
        apiFetch<{ items: AlertItem[] }>(`/api/alerts/live?${buildQuery({ ...resolveTimeWindow(viewState), run_id: viewState.selectedRunId, limit: 30 })}`),
        apiFetch<{ items: HoneypotSession[] }>("/api/honeypot/sessions?limit=8"),
      ]);
      setControls(runtime);
      setResponseAlerts((alerts.items || []).filter((item) => item.engine === "response" || item.response_preview?.preview_command));
      setHoneypots(hp.items || []);
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 4000);
    return () => clearInterval(interval);
  }, [viewState]);

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Response center</div>
          <h1 className="page-title small">Policy gates, live enforcement state, and operator-readable commands</h1>
        </div>
      </section>

      <section className="workspace-grid">
        <ResponsePolicy />
        <div className="panel padded">
          <div className="panel-head">
            <div>
              <span className="kicker">Runtime controls</span>
              <h2>Live enforcement state</h2>
            </div>
          </div>
          {controls ? (
            <div className="detail-stack">
              <div className="detail-card">
                <h3>Disabled accounts</h3>
                <div className="history-list">
                  {(controls.disabled_accounts || []).map((entry) => (
                    <div key={`${entry.username}-${entry.updated_at}`} className="history-item">
                      <strong>{entry.username || "account"}</strong>
                      <span>{entry.updated_at || entry.reason || "active"}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="detail-card">
                <h3>Blocked source addresses</h3>
                <div className="history-list">
                  {(controls.blocked_ips || []).map((entry) => (
                    <div key={`${entry.ip}-${entry.updated_at}`} className="history-item">
                      <strong>{entry.ip || "address"}</strong>
                      <span>{entry.updated_at || entry.reason || "active"}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="detail-card">
                <h3>Rate limits</h3>
                <div className="history-list">
                  {(controls.rate_limits || []).map((entry) => (
                    <div key={`${entry.path}-${entry.source_ip}-${entry.updated_at}`} className="history-item">
                      <strong>{entry.path || "path"}</strong>
                      <span>{entry.requests_per_minute || 0} req/min</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <p>Loading live enforcement state.</p>
          )}
        </div>
      </section>

      <section className="panel padded">
        <div className="panel-head">
          <div>
            <span className="kicker">Honeypot containers</span>
            <h2>Live created containers and captured logs</h2>
          </div>
        </div>
        <div className="feed-list">
          {honeypots.map((hp) => (
            <div key={hp.session_id} className="feed-card static">
              <div className="feed-meta">
                <span className="chip accent">{hp.container_name || "honeypot"}</span>
                <span>{hp.created_at ? new Date(hp.created_at).toLocaleString() : "n/a"}</span>
              </div>
              <div className="chip-row">
                <span className="chip">severity {hp.severity || "unknown"}</span>
                <span className="chip">port {hp.host_port || "n/a"}</span>
                <span className="chip">src {hp.source_ip || "n/a"}</span>
                <span className="chip">{hp.technique_id || hp.rule_id || "unmapped"}</span>
              </div>
              {hp.groq_analysis ? <p>{noJsonLikeText(hp.groq_analysis)}</p> : null}
              <div className="terminal-window">
                {(hp.logs || []).slice(-25).map((line, index) => (
                  <div key={`${hp.session_id}-${index}`} className="terminal-line">$ {line}</div>
                ))}
              </div>
            </div>
          ))}
          {!honeypots.length ? <div className="feed-card static">No honeypot containers yet. Critical alerts will create and stream sessions here.</div> : null}
        </div>
      </section>

      <section className="panel padded">
        <div className="panel-head">
          <div>
            <span className="kicker">Response previews</span>
            <h2>Commands and outcomes shown in operator-readable form</h2>
          </div>
          <div className="segmented" role="group" aria-label="Response explanation mode">
            <button className={`segment ${explanationMode === "technical" ? "active" : ""}`} onClick={() => setExplanationMode("technical")}>Technical</button>
            <button className={`segment ${explanationMode === "nontechnical" ? "active" : ""}`} onClick={() => setExplanationMode("nontechnical")}>Non-technical</button>
          </div>
        </div>
        <div className="feed-list">
          {responseAlerts.map((item) => (
            <div key={`${item.engine}-${item.title}-${item.timestamp}`} className="feed-card static">
              <div className="feed-meta">
                <span className="chip accent">{item.engine}</span>
                <span>{new Date(item.timestamp).toLocaleString()}</span>
              </div>
              <div className="chip-row">
                <span className="chip">warning {item.warning_level || item.severity_level || "unknown"}</span>
                <span className="chip">severity {item.response_preview.severity?.score ?? "n/a"}</span>
                {item.response_preview.should_honeypot ? <span className="chip accent">critical honeypot eligible</span> : null}
              </div>
              <strong>{item.title}</strong>
              <p>{noJsonLikeText(item.response_preview.summary)}</p>
              <p>
                {explanationMode === "technical"
                  ? noJsonLikeText(item.response_preview.technical_explanation || item.response_preview.summary)
                  : noJsonLikeText(item.response_preview.nontechnical_explanation || item.response_preview.summary)}
              </p>
              <div className="preview-command">{item.response_preview.preview_command}</div>
              <p>{item.response_preview.success_criteria}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
