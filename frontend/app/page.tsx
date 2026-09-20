"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiFetch, buildQuery } from "../lib/api";
import { useCachedState, writeCached } from "../lib/client-cache";
import { IconSiren } from "../components/icons";

type Analytics = {
  timeline: Array<{ time: string; count: number }>;
  severity_distribution: Array<{ label: string; value: number }>;
  engine_distribution: Array<{ label: string; value: number }>;
  top_sources: Array<{ label: string; value: number }>;
};

type DashboardPayload = {
  rules_total: number;
  logs_total: number;
  elastic_alerts_total: number;
  wazuh_alerts_total: number;
  suricata_events_total: number;
  response_actions_total: number;
  latest_alerts: Array<{ id: string; severity?: string; title: string; timestamp: string; source_ip?: string }>;
  analytics: Analytics;
  agents?: { hands?: Array<unknown> };
};

type AlertItem = {
  id: string;
  title: string;
  severity: string;
  engine: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  rule_id: string;
  message: string;
  technique_ids: string[];
  response_preview?: { status?: string; recommended_action?: string; ai_triage?: { verdict?: string; confidence?: number; summary?: string } };
};

const sevClass: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.round(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m ago`;
  return `${Math.round(ms / 3_600_000)}h ago`;
}

export default function LandingPage() {
  const [dashboard, setDashboard] = useCachedState<DashboardPayload | null>("fda-cache:landing-dashboard", null);
  const [attention, setAttention] = useCachedState<AlertItem[]>("fda-cache:landing-attention", []);
  const [acting, setActing] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      const [d, alerts] = await Promise.all([
        apiFetch<DashboardPayload>("/api/dashboard"),
        apiFetch<{ items: AlertItem[] }>("/api/alerts/live?limit=40"),
      ]);
      if (!active) return;
      setDashboard(d);
      const open = (alerts.items || []).filter((a) => {
        const st = a.response_preview?.status;
        return (a.severity === "high" || a.severity === "critical") && st !== "executed";
      });
      setAttention(open.slice(0, 6));
      writeCached("fda-cache:landing-dashboard", d);
      writeCached("fda-cache:landing-attention", open.slice(0, 6));
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  const stats = useMemo(() => {
    if (!dashboard) return null;
    const sev = (label: string) =>
      dashboard.analytics.severity_distribution.find((s) => s.label === label)?.value || 0;
    return {
      critical: sev("critical"),
      high: sev("high"),
      medium: sev("medium"),
      low: sev("low"),
      detections: dashboard.elastic_alerts_total + dashboard.wazuh_alerts_total,
      responses: dashboard.response_actions_total,
      hands: dashboard.agents?.hands?.length || 18,
    };
  }, [dashboard]);

  const runAct = async (id: string, action: string, source_ip: string, destination_ip: string, rule_id: string, technique: string) => {
    setActing(id);
    try {
      await apiFetch("/api/response/execute", {
        method: "POST",
        body: JSON.stringify({
          actions: [action],
          payload: { alert_id: id, source_ip, destination_ip, rule_id, technique_id: technique },
        }),
      });
    } catch {
      // surfaced by refresh; the audit log records failures
    } finally {
      setActing("");
    }
  };

  if (!dashboard || !stats) {
    return <div className="panel padded">Loading mission telemetry...</div>;
  }

  const verdict = attention.length === 0
    ? { cls: "", label: "ALL CLEAR" }
    : stats.critical > 0
      ? { cls: "live", label: `${stats.critical} CRITICAL OPEN` }
      : { cls: "armed", label: `${attention.length} NEED ATTENTION` };

  return (
    <div className="page-stack">
      {/* System state sentence — the five-second read */}
      <section className="sys-state">
        <span className={`pulse-dot ${verdict.cls === "live" ? "down" : verdict.cls === "armed" ? "warn" : ""}`} />
        <div>
          <div className="sys-headline">
            {verdict.label === "ALL CLEAR"
              ? "All clear. Detection live, nothing burning."
              : `${verdict.label} — open incidents below.`}
          </div>
          <div className="sys-sub">
            {stats.detections.toLocaleString()} detections indexed · {dashboard.rules_total.toLocaleString()} rules armed ·{" "}
            {stats.hands} agent hands running · {stats.responses.toLocaleString()} responses executed
          </div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <Link href="/incidents" className="button button-primary">Open Incidents</Link>
          <Link href="/dashboard" className="button">Command Center</Link>
        </div>
      </section>

      <section className="workspace-grid">
        {/* 24h waveform */}
        <div className="panel padded chart-panel">
          <div className="panel-head">
            <div><span className="kicker">Last 24 hours</span><h2>Signal density</h2></div>
            <div className="chip-row">
              {(["critical", "high", "medium", "low"] as const).map((s) => (
                <span key={s} className={`chip ${sevClass[s]}`}>{s} {stats[s].toLocaleString()}</span>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={210}>
            <AreaChart data={dashboard.analytics.timeline}>
              <defs>
                <linearGradient id="waveShade" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4d8dff" stopOpacity={0.32} />
                  <stop offset="100%" stopColor="#4d8dff" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" hide />
              <YAxis width={32} stroke="#5d6474" tick={{ fill: "#949bab", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Tooltip
                contentStyle={{ background: "#14161d", border: "1px solid #2a2f3b", borderRadius: 6, fontSize: 12 }}
                labelStyle={{ color: "#949bab" }}
              />
              <Area isAnimationActive={false} type="monotone" dataKey="count" stroke="#4d8dff" strokeWidth={1.6} fill="url(#waveShade)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Fleet strip */}
        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Fleet</span><h2>Telemetry &amp; coverage</h2></div></div>
          <div className="metrics-grid">
            <div className="stat-tile"><span>Log events</span><strong>{dashboard.logs_total.toLocaleString()}</strong></div>
            <div className="stat-tile"><span>Suricata events</span><strong>{dashboard.suricata_events_total.toLocaleString()}</strong></div>
            <div className="stat-tile"><span>Engines live</span><strong>{Math.max(dashboard.analytics.engine_distribution.length, 1)}</strong></div>
            <div className="stat-tile"><span>Top source actors</span><strong>{dashboard.analytics.top_sources.length}</strong></div>
          </div>
          <p className="helper-text" style={{ marginTop: 12 }}>
            Capture, correlation, AI triage, and nftables enforcement run on this box. The status bar up top shows live packet flow; the sidebar groups the console by job.
          </p>
        </div>
      </section>

      {/* Attention queue — the decision surface */}
      <section className="panel padded">
        <div className="panel-head">
          <div>
            <span className="kicker">Needs attention</span>
            <h2>Open high &amp; critical incidents</h2>
          </div>
          <Link href="/incidents" className="button" style={{ padding: "5px 12px", fontSize: "0.75rem" }}>All incidents</Link>
        </div>
        {attention.length === 0 ? (
          <div className="empty-state" style={{ padding: "32px 20px" }}>
            <div className="empty-title">Nothing waiting on you</div>
            <div className="empty-message">High and critical incidents land here with one-click containment when they appear.</div>
          </div>
        ) : (
          <div className="data-table" style={{ display: "block", overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Incident</th>
                  <th>Source</th>
                  <th>MITRE</th>
                  <th>When</th>
                  <th>Act</th>
                </tr>
              </thead>
              <tbody>
                {attention.map((a) => (
                  <tr key={a.id}>
                    <td className="cell-sev"><span className={`chip ${sevClass[a.severity?.toLowerCase()] || ""}`}>{a.severity}</span></td>
                    <td>{a.title}</td>
                    <td className="cell-ip">{a.source_ip || "—"}</td>
                    <td>{a.technique_ids?.[0] || "—"}</td>
                    <td className="cell-time">{timeAgo(a.timestamp)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          className="action-btn block"
                          disabled={acting === a.id}
                          onClick={() => runAct(a.id, "block_source_ip", a.source_ip, a.destination_ip, a.rule_id, a.technique_ids?.[0] || "")}
                        >
                          Block
                        </button>
                        <button
                          className="action-btn observe"
                          disabled={acting === a.id}
                          onClick={() => runAct(a.id, "observe_only", a.source_ip, a.destination_ip, a.rule_id, a.technique_ids?.[0] || "")}
                        >
                          Observe
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
