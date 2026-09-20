"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { IconSiren, IconShield, IconWorkflow } from "../components/icons";

import { apiFetch } from "../lib/api";
import { useCachedState, writeCached } from "../lib/client-cache";

type DashboardPayload = {
  rules_total: number;
  logs_total: number;
  elastic_alerts_total: number;
  wazuh_alerts_total: number;
  suricata_events_total: number;
  response_actions_total: number;
  latest_alerts: Array<{ severity_level?: string; warning_level?: string }>;
  analytics: {
    timeline: Array<{ time: string; count: number }>;
    severity_distribution: Array<{ label: string; value: number }>;
    engine_distribution: Array<{ label: string; value: number }>;
    suricata_protocols: Array<{ label: string; value: number }>;
    top_sources: Array<{ label: string; value: number }>;
    top_destinations: Array<{ label: string; value: number }>;
    top_ports?: Array<{ label: string; value: number }>;
    source_indices?: Array<{ label: string; value: number }>;
    agent_run_mix: Array<{ label: string; value: number }>;
  };
  agents?: { hands?: Array<unknown> };
};

type HoneypotPayload = {
  items: Array<{ session_id: string; severity: string }>;
};

type RunHistoryPayload = {
  items: Array<{ run_id?: string; started_at?: string; saved?: boolean }>;
};

export default function LandingPage() {
  const [dashboard, setDashboard] = useCachedState<DashboardPayload | null>("fda-cache:landing-dashboard", null);
  const [honeypots, setHoneypots] = useCachedState<HoneypotPayload>("fda-cache:landing-honeypots", { items: [] });
  const [runs, setRuns] = useCachedState<RunHistoryPayload>("fda-cache:landing-runs", { items: [] });

  useEffect(() => {
    let active = true;
    const load = async () => {
      const [d, h, r] = await Promise.all([
        apiFetch<DashboardPayload>("/api/dashboard"),
        apiFetch<HoneypotPayload>("/api/honeypot/sessions?limit=50"),
        apiFetch<RunHistoryPayload>("/api/runs/history?limit=100"),
      ]);
      if (!active) {
        return;
      }
      setDashboard(d);
      setHoneypots(h);
      setRuns(r);
      writeCached("fda-cache:landing-dashboard", d);
      writeCached("fda-cache:landing-honeypots", h);
      writeCached("fda-cache:landing-runs", r);
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  const headlineStats = useMemo(() => {
    if (!dashboard) {
      return null;
    }
    const critical = dashboard.analytics.severity_distribution.find((item) => item.label === "critical")?.value || 0;
    const high = dashboard.analytics.severity_distribution.find((item) => item.label === "high")?.value || 0;
    const medium = dashboard.analytics.severity_distribution.find((item) => item.label === "medium")?.value || 0;
    const low = dashboard.analytics.severity_distribution.find((item) => item.label === "low")?.value || 0;
    return {
      detections: dashboard.elastic_alerts_total + dashboard.wazuh_alerts_total,
      events: dashboard.logs_total + dashboard.suricata_events_total,
      responses: dashboard.response_actions_total,
      honeypots: honeypots.items.length,
      attacksBySeverity: `critical ${critical} | high ${high} | medium ${medium} | low ${low}`,
    };
  }, [dashboard, honeypots.items.length]);

  if (!dashboard || !headlineStats) {
    return <div className="panel padded">Loading mission telemetry...</div>;
  }

  return (
    <div className="page-stack">
      <section className="hero-grid">
        <div className="hero-panel hero-copy">
          <div className="eyebrow">Mission control</div>
          <h1>Detect attacks. Decide with AI. Respond in one click.</h1>
          <p>
            Every alert from Elastic, Wazuh, Suricata, and packet capture is triaged
            by an AI analyst — verdict, confidence, and a recommended action — then
            held for one-click enforcement with a full audit trail.
          </p>
          <div className="hero-actions">
            <Link href="/dashboard" className="button button-primary">Open Command Center</Link>
            <Link href="/logs" className="button button-secondary">Open Logs + Runs</Link>
            <Link href="/responses" className="button button-secondary">Open Responses</Link>
          </div>
          <div className="detail-card">
            <h3>Active threats by severity</h3>
            <p>{headlineStats.attacksBySeverity}</p>
          </div>
        </div>
        <div className="hero-panel hero-metrics">
          <div className="metric-card"><span>Live detections</span><strong>{headlineStats.detections.toLocaleString()}</strong><small>Elastic + Wazuh alert volume</small></div>
          <div className="metric-card"><span>Total event flow</span><strong>{headlineStats.events.toLocaleString()}</strong><small>Logs + Suricata combined</small></div>
          <div className="metric-card"><span>Response executions</span><strong>{headlineStats.responses.toLocaleString()}</strong><small>Automated + manual response actions</small></div>
          <div className="metric-card"><span>Honeypot sessions</span><strong>{headlineStats.honeypots.toLocaleString()}</strong><small>Critical containment containers created</small></div>
          <div className="metric-card"><span>Rules indexed</span><strong>{(dashboard?.rules_total || 0).toLocaleString()}</strong><small>Detection corpus ready for mapping</small></div>
          <div className="metric-card"><span>Run history</span><strong>{runs.items.length.toLocaleString()}</strong><small>Saved and completed mission runs</small></div>
          <div className="metric-card"><span>Active telemetry sources</span><strong>{(dashboard?.analytics.source_indices?.length || 0).toLocaleString()}</strong><small>Distinct index contributors in range</small></div>
          <div className="metric-card"><span>Network source spread</span><strong>{(dashboard?.analytics.top_sources.length || 0).toLocaleString()}</strong><small>Top observed source actors</small></div>
          <div className="metric-card"><span>Network destination spread</span><strong>{(dashboard?.analytics.top_destinations.length || 0).toLocaleString()}</strong><small>Top targeted destinations</small></div>
          <div className="metric-card"><span>Protocol diversity</span><strong>{(dashboard?.analytics.suricata_protocols.length || 0).toLocaleString()}</strong><small>Transport/protocol profile depth</small></div>
          <div className="metric-card"><span>Attack timeline points</span><strong>{(dashboard?.analytics.timeline.length || 0).toLocaleString()}</strong><small>Waveform samples for graphing</small></div>
          <div className="metric-card"><span>Orchestration hands</span><strong>{(dashboard?.agents?.hands?.length || 0).toLocaleString()}</strong><small>Parallel agent execution channels</small></div>
        </div>
      </section>

      <section className="stat-grid">
        <div className="stat-tile"><span>Critical honeypot sessions</span><strong>{honeypots.items.filter((item) => item.severity === "critical").length}</strong></div>
        <div className="stat-tile"><span>Active engines</span><strong>{(dashboard?.analytics.engine_distribution.length || 0).toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Severity levels seen</span><strong>{(dashboard?.analytics.severity_distribution.length || 0).toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Top ports probed</span><strong>{(dashboard?.analytics.top_ports?.length || 0).toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Agent runs</span><strong>{(dashboard?.analytics.agent_run_mix.length || 0).toLocaleString()}</strong></div>
        <div className="stat-tile"><span>Alerts in view</span><strong>{(dashboard?.latest_alerts.length || 0).toLocaleString()}</strong></div>
      </section>

      <section className="panel feature-strip">
          <div className="feature-box">
            <IconShield size={20} />
            <div>
              <h3>Live session on open</h3>
              <p>The console starts capturing and streaming telemetry the moment it opens — no setup, no warm-up.</p>
            </div>
          </div>
        <div className="feature-box">
          <IconWorkflow size={20} />
          <div>
            <h3>MITRE-mapped playbooks</h3>
            <p>Every detection carries technique IDs that map to playbooks, response previews, and runtime controls.</p>
          </div>
        </div>
        <div className="feature-box">
          <IconSiren size={20} />
          <div>
            <h3>Critical containment</h3>
            <p>Critical responses spin up honeypot containers and surface captured sessions in the Response Center.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
