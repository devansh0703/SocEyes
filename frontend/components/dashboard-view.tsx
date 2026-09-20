"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiFetch, buildQuery } from "../lib/api";
import { useCachedState, writeCached } from "../lib/client-cache";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";

type ChartDatum = { label?: string; time?: string; value?: number; count?: number };
type AlertItem = {
  id: string;
  engine: string;
  title: string;
  severity: string;
  timestamp: string;
  message: string;
  source_ip?: string;
  technique_ids: string[];
  response_preview?: {
    status?: string;
    recommended_action?: string;
    preview_command?: string;
    ai_triage?: { verdict?: string; confidence?: number; summary?: string; technical_details?: string };
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
    top_ports?: ChartDatum[];
  };
};

const chartPalette = ["#4d8dff", "#7aa3f9", "#a5c0fb", "#cfe0fd", "#5d6474", "#2e5fd0"];
const severityPalette: Record<string, string> = {
  critical: "#ff4d4f",
  high: "#ff9838",
  medium: "#e8c547",
  low: "#7d879c",
  info: "#4d8dff",
};
const severityClass: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

const tooltipStyle = {
  background: "#14161d",
  border: "1px solid #2a2f3b",
  borderRadius: 6,
  fontSize: 12,
  fontFamily: "JetBrains Mono",
};

/** One tile of the KPI strip: label, tabular value, sparkline. */
function KpiTile({ label, value, delta, data, color }: {
  label: string;
  value: number | string;
  delta?: string;
  data?: Array<{ v: number }>;
  color?: string;
}) {
  const stroke = color || "#4d8dff";
  return (
    <div className="kpi-tile">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{typeof value === "number" ? value.toLocaleString() : value}</span>
      {delta ? <span className="kpi-delta">{delta}</span> : null}
      {data && data.length > 1 ? (
        <ResponsiveContainer width="100%" height={26} className="kpi-spark">
          <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
            <YAxis hide domain={["dataMin", "dataMax"]} />
            <Area isAnimationActive={false} type="monotone" dataKey="v" stroke={stroke} strokeWidth={1.3} fill={stroke} fillOpacity={0.12} />
          </AreaChart>
        </ResponsiveContainer>
      ) : null}
    </div>
  );
}

export function DashboardView() {
  const [viewState] = useGlobalViewState();
  const [data, setData] = useCachedState<DashboardPayload | null>("fda-cache:dashboard-view", null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const timeWindow = resolveTimeWindow(viewState);
        const query = buildQuery({ ...timeWindow, run_id: viewState.selectedRunId, limit: 120 });
        const payload = await apiFetch<DashboardPayload>(`/api/dashboard?${query}`);
        if (!active) return;
        setData(payload);
        writeCached("fda-cache:dashboard-view", payload);
      } catch (loadError) {
        if (active) setError(loadError instanceof Error ? loadError.message : "Failed to load command center");
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [viewState]);

  if (!data) {
    return <div className="panel padded">{error || "Loading command center..."}</div>;
  }

  const a = data.analytics;
  const totalAlerts = data.elastic_alerts_total + data.wazuh_alerts_total;
  const criticalCount = a.severity_distribution.find((s) => String(s.label).toLowerCase() === "critical")?.value || 0;
  const highCount = a.severity_distribution.find((s) => String(s.label).toLowerCase() === "high")?.value || 0;
  const timelineSpark = a.timeline.map((t) => ({ v: t.count }));
  const half = Math.floor(a.timeline.length / 2);
  const sparkDelta = (series: Array<{ v: number }>) => {
    if (series.length < 4) return undefined;
    const first = series.slice(0, half).reduce((s, p) => s + p.v, 0);
    const second = series.slice(half).reduce((s, p) => s + p.v, 0);
    if (first === second) return "flat vs earlier";
    return second > first ? `↑ trending up` : `↓ easing off`;
  };

  const protoSpark = a.suricata_protocols.slice(0, 12).map((p, i, arr) => ({ v: arr[arr.length - 1 - i].value || 0 }));

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Command center <span className="live-badge">LIVE</span></div>
          <h1 className="page-title">Detection, timeline, and response context</h1>
          <p className="lead">Scope telemetry with the sidebar time filter. Everything below reads the same window.</p>
        </div>
      </section>

      {/* KPI strip */}
      <section className="kpi-strip">
        <KpiTile label="Detections" value={totalAlerts} data={timelineSpark} delta={sparkDelta(timelineSpark)} />
        <KpiTile label="Critical" value={criticalCount} data={timelineSpark} color="#ff4d4f" />
        <KpiTile label="High" value={highCount} data={timelineSpark} color="#ff9838" />
        <KpiTile label="Log events" value={data.logs_total} />
        <KpiTile label="Capture events" value={data.suricata_events_total} data={protoSpark} />
        <KpiTile label="Responses" value={data.response_actions_total} color="#3fd68f" />
      </section>

      <section className="dashboard-grid">
        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Volume timeline</span><h2>Signal density over time</h2></div></div>
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={a.timeline}>
              <defs>
                <linearGradient id="timelineShade" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4d8dff" stopOpacity={0.32} />
                  <stop offset="100%" stopColor="#4d8dff" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1e222b" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis width={34} stroke="#5d6474" tick={{ fill: "#949bab", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#949bab" }} />
              <Area isAnimationActive={false} type="monotone" dataKey="count" stroke="#4d8dff" fill="url(#timelineShade)" strokeWidth={1.6} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Severity mix</span><h2>Alert distribution</h2></div></div>
          <ResponsiveContainer width="100%" height={190}>
            <PieChart>
              <Pie isAnimationActive={false} data={a.severity_distribution} dataKey="value" nameKey="label" innerRadius={50} outerRadius={78} paddingAngle={2} strokeWidth={0}>
                {a.severity_distribution.map((entry, index) => (
                  <Cell key={entry.label || index} fill={severityPalette[String(entry.label || "").toLowerCase()] || chartPalette[index % chartPalette.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="chip-row" style={{ justifyContent: "center", marginTop: 6 }}>
            {a.severity_distribution.map((entry) => {
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
          <ResponsiveContainer width="100%" height={230}>
            <ComposedChart data={a.engine_distribution}>
              <CartesianGrid stroke="#1e222b" vertical={false} />
              <XAxis dataKey="label" stroke="#5d6474" tick={{ fill: "#949bab", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <YAxis width={34} stroke="#5d6474" tick={{ fill: "#949bab", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area isAnimationActive={false} dataKey="value" fill="#4d8dff" stroke="#4d8dff" fillOpacity={0.14} strokeWidth={1.6} />
              <Line isAnimationActive={false} dataKey="value" stroke="#949bab" strokeWidth={1.2} dot={{ r: 2, fill: "#949bab" }} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Network shape</span><h2>Top talkers</h2></div></div>
          <table className="data-table">
            <thead>
              <tr><th>Source</th><th style={{ textAlign: "right" }}>Events</th><th>Destination</th><th style={{ textAlign: "right" }}>Events</th></tr>
            </thead>
            <tbody>
              {Array.from({ length: Math.min(a.top_sources.length, a.top_destinations.length, 8) }).map((_, i) => (
                <tr key={i}>
                  <td className="cell-ip">{a.top_sources[i]?.label || "—"}</td>
                  <td style={{ textAlign: "right" }}>{(a.top_sources[i]?.value || 0).toLocaleString()}</td>
                  <td className="cell-ip">{a.top_destinations[i]?.label || "—"}</td>
                  <td style={{ textAlign: "right" }}>{(a.top_destinations[i]?.value || 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Dense alert table */}
      <section className="panel padded">
        <div className="panel-head">
          <div><span className="kicker">Live detections</span><h2>Alert stream</h2></div>
          <Link href="/incidents" className="button" style={{ padding: "5px 12px", fontSize: "0.75rem" }}>Work incidents</Link>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Engine</th>
                <th>Source</th>
                <th>MITRE</th>
                <th>AI verdict</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {data.latest_alerts.map((alert) => {
                const triage = alert.response_preview?.ai_triage;
                return (
                  <tr key={alert.id}>
                    <td className="cell-sev">
                      <span className={`chip ${severityClass[alert.severity?.toLowerCase()] || ""}`}>{alert.severity}</span>
                    </td>
                    <td>{alert.title}</td>
                    <td>{alert.engine}</td>
                    <td className="cell-ip">{alert.source_ip || "—"}</td>
                    <td>{alert.technique_ids.slice(0, 2).join(", ") || "—"}</td>
                    <td>
                      {triage?.verdict
                        ? <span className={triage.verdict === "true_positive" ? "helper-text danger" : "subtle"}>
                            {triage.verdict.replace("_", " ")}{triage.confidence ? ` ${Math.round(triage.confidence * 100)}%` : ""}
                          </span>
                        : <span className="static">pending</span>}
                    </td>
                    <td className="cell-time">{new Date(alert.timestamp).toLocaleTimeString([], { hour12: false })}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
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
