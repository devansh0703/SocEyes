"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart, Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiFetch, buildQuery } from "../lib/api";
import { useCachedState, writeCached } from "../lib/client-cache";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";
import { DetailSections } from "./detail-sections";

type ChartDatum = { label?: string; time?: string; value?: number; count?: number };
type Section = { title: string; paragraphs?: string[]; bullets?: string[] };
type AlertItem = {
  id: string;
  engine: string;
  title: string;
  severity: string;
  severity_level?: string;
  timestamp: string;
  message: string;
  technique_ids: string[];
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    success_criteria: string;
    technical_explanation?: string;
    nontechnical_explanation?: string;
    playbook?: { sections: Section[] };
  };
};

type DashboardPayload = {
  rules_total: number;
  logs_total: number;
  elastic_alerts_total: number;
  wazuh_alerts_total: number;
  suricata_events_total: number;
  response_actions_total: number;
  latest_alerts: AlertItem[];
  zeroclaw: { available: boolean; summary: string; lines?: string[] };
  analytics: {
    timeline: Array<{ time: string; count: number }>;
    severity_distribution: ChartDatum[];
    engine_distribution: ChartDatum[];
    suricata_protocols: ChartDatum[];
    top_sources: ChartDatum[];
    top_destinations: ChartDatum[];
    agent_run_mix: ChartDatum[];
  };
  response_preview: AlertItem["response_preview"];
};

const chartPalette = ["#4f8ef7", "#7aa7f9", "#a5c3fb", "#cfe0fd", "#5c6577", "#2f66d8"];
const severityPalette: Record<string, string> = {
  critical: "#f0433c",
  high: "#f59e0b",
  medium: "#eab308",
  low: "#64748b",
  info: "#4f8ef7",
};
const severityClass: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function DashboardView() {
  const [viewState] = useGlobalViewState();
  const [data, setData] = useCachedState<DashboardPayload | null>("fda-cache:dashboard-view", null);
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const timeWindow = resolveTimeWindow(viewState);
        const query = buildQuery({ ...timeWindow, run_id: viewState.selectedRunId, limit: 120 });
        const payload = await apiFetch<DashboardPayload>(`/api/dashboard?${query}`);
        if (!active) {
          return;
        }
        setData(payload);
        setSelectedAlertId((current) => current || payload.latest_alerts[0]?.id || "");
        writeCached("fda-cache:dashboard-view", payload);
      } catch (loadError) {
        if (active) {
          setError(loadError instanceof Error ? loadError.message : "Failed to load command center");
        }
      }
    };
    load();
    const interval = setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [viewState]);

  if (!data) {
    return <div className="panel padded">{error || "Loading command center..."}</div>;
  }

  const selectedAlert = data.latest_alerts.find((item) => item.id === selectedAlertId) || data.latest_alerts[0] || null;
  const preview = selectedAlert?.response_preview || data.response_preview;

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Live command center <span className="live-badge">LIVE</span></div>
          <h1 className="page-title">Detection, timeline, and response context without hidden processing</h1>
          <p className="lead">Use exact date and time selectors in the sidebar to scope telemetry and responses.</p>
        </div>
      </section>

      <section className="feature-strip">
        <Link href="/logs" className="feature-box">
          <div>
            <h3>Logs and runs workspace</h3>
            <p>Consecutive-log grouping, run context, and entity timelines in one place.</p>
          </div>
        </Link>
        <Link href="/playbooks" className="feature-box">
          <div>
            <h3>SOAR playbooks</h3>
            <p>Technique-centric mapping with alert and rule context.</p>
          </div>
        </Link>
        <Link href="/responses" className="feature-box">
          <div>
            <h3>Response center</h3>
            <p>Groq-generated technical and non-technical response explanation with execution evidence.</p>
          </div>
        </Link>
      </section>

      <section className="stat-grid">
        <div className="stat-tile"><span>Rules indexed</span><strong>{data.rules_total.toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Logs in range</span><strong>{data.logs_total.toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Elastic alerts</span><strong>{data.elastic_alerts_total.toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Wazuh alerts</span><strong>{data.wazuh_alerts_total.toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Suricata events</span><strong>{data.suricata_events_total.toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Responses executed</span><strong>{data.response_actions_total.toLocaleString()}</strong></div>
      </section>

      <section className="dashboard-grid">
        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Volume timeline</span><h2>Signal density over time</h2></div></div>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={data.analytics.timeline}>
              <defs>
                <linearGradient id="timelineShade" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4f8ef7" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#4f8ef7" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#232b3d" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis stroke="#5c6577" tick={{ fill: "#8b94a7", fontSize: 12 }} />
              <Tooltip />
              <Area type="monotone" dataKey="count" stroke="#4f8ef7" fill="url(#timelineShade)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Severity mix</span><h2>Alert distribution</h2></div></div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={data.analytics.severity_distribution} dataKey="value" nameKey="label" innerRadius={52} outerRadius={82} paddingAngle={2} strokeWidth={0}>
                {data.analytics.severity_distribution.map((entry, index) => (
                  <Cell key={entry.label || index} fill={severityPalette[String(entry.label || "").toLowerCase()] || chartPalette[index % chartPalette.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="chip-row" style={{ justifyContent: "center", marginTop: 8 }}>
            {data.analytics.severity_distribution.map((entry) => {
              const key = String(entry.label || "").toLowerCase();
              return (
                <span key={entry.label || ""} className={`chip ${severityClass[key] || ""}`}>
                  {entry.label}: {entry.value}
                </span>
              );
            })}
          </div>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Engine patterns</span><h2>Coverage pulse</h2></div></div>
          <ResponsiveContainer width="100%" height={240}>
            <ComposedChart data={data.analytics.engine_distribution}>
              <CartesianGrid stroke="#232b3d" vertical={false} />
              <XAxis dataKey="label" stroke="#5c6577" tick={{ fill: "#8b94a7", fontSize: 12 }} />
              <YAxis stroke="#5c6577" tick={{ fill: "#8b94a7", fontSize: 12 }} />
              <Tooltip />
              <Area dataKey="value" fill="#4f8ef7" stroke="#4f8ef7" fillOpacity={0.16} strokeWidth={2} />
              <Line dataKey="value" stroke="#0b0e14" strokeWidth={2} dot={{ r: 3 }} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Network shape</span><h2>Source and destination profile</h2></div></div>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={data.analytics.top_sources.slice(0, 6).map((item, index) => ({
              label: item.label,
              source: item.value,
              destination: data.analytics.top_destinations[index]?.value || 0,
            }))}>
              <Tooltip />
              <Radar name="Sources" dataKey="source" stroke="#4f8ef7" fill="#4f8ef7" fillOpacity={0.22} />
              <Radar name="Destinations" dataKey="destination" stroke="#7aa7f9" fill="#7aa7f9" fillOpacity={0.14} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Live detections</span><h2>Alert stream</h2></div></div>
          <div className="feed-list">
            {data.latest_alerts.map((alert) => (
              <button key={alert.id} className={`feed-card ${selectedAlert?.id === alert.id ? "selected" : ""}`} onClick={() => setSelectedAlertId(alert.id)}>
                <div className="feed-meta">
                  <span className="chip accent">{alert.engine}</span>
                  <span>{new Date(alert.timestamp).toLocaleString()}</span>
                </div>
                <strong>{alert.title}</strong>
                <p>{alert.message}</p>
                <div className="chip-row">
                  <span className={`chip ${severityClass[alert.severity?.toLowerCase()] || ""}`}>{alert.severity}</span>
                  {alert.technique_ids.slice(0, 5).map((item) => <span key={item} className="tag">{item}</span>)}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Response context</span><h2>{selectedAlert?.title || "Latest response preview"}</h2></div></div>
          <p className="lead">{preview.summary}</p>
          <div className="detail-card">
            <h3>Technical explanation</h3>
            <p>{preview.technical_explanation || preview.summary}</p>
          </div>
          <div className="detail-card">
            <h3>Non-technical explanation</h3>
            <p>{preview.nontechnical_explanation || preview.summary}</p>
          </div>
          <div className="preview-stack">
            <div className="preview-card">
              <div className="preview-label">Planned command</div>
              <div className="preview-command">{preview.preview_command}</div>
            </div>
            <div className="preview-card">
              <div className="preview-label">Success criteria</div>
              <div>{preview.success_criteria}</div>
            </div>
          </div>
          <DetailSections sections={(preview.playbook?.sections || []).slice(0, 3)} />
        </div>
      </section>

      <section className="panel padded">
        <div className="panel-head"><div><span className="kicker">ZeroClaw runtime</span><h2>Processing visibility</h2></div></div>
        <div className="terminal-window">
          {(data.zeroclaw.lines || [data.zeroclaw.summary]).slice(0, 12).map((line) => (
            <div key={line} className="terminal-line">$ {line}</div>
          ))}
        </div>
      </section>
    </div>
  );
}
