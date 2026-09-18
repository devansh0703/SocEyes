"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiFetch, buildQuery } from "../lib/api";
import { readCached, writeCached } from "../lib/client-cache";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";

type Section = { title: string; paragraphs?: string[]; bullets?: string[] };

type LogItem = {
  id: string;
  timestamp: string;
  message: string;
  source_index: string;
  host_name?: string;
  user_name?: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  network_transport: string;
  suricata_event_type: string;
  process_name?: string;
  process_command_line?: string;
  run_id?: string;
};

type GroupedLog = {
  group_id: string;
  count: number;
  start_time: string;
  end_time: string;
  latest: LogItem;
  ids: string[];
};

type RuleMatch = {
  rule_id: string;
  title: string;
  description: string;
  engine: string;
  sections: Section[];
  mitre_ids: string[];
  playbooks: Array<{ technique_id: string; sections: Section[] }>;
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    success_criteria: string;
  };
};

type TimelinePayload = {
  entity_type: string;
  entity_id: string;
  count: number;
  start_time: string;
  stop_time: string;
  events: Array<{ kind: string; timestamp: string; id: string; title: string; source_ip?: string; destination_ip?: string }>;
};

type LogDetailPayload = {
  log: LogItem;
  matches: RuleMatch[];
  timeline: TimelinePayload;
  ip_context: Record<string, { ip: string; timeline: TimelinePayload }>;
};

type RunState = {
  active: boolean;
  run_id?: string;
  name?: string;
  note?: string;
  started_at?: string;
  stopped_at?: string;
  saved?: boolean;
  saved_at?: string;
  duration_seconds?: number;
};

type Analytics = {
  timeline: Array<{ time: string; count: number }>;
  suricata_event_types: Array<{ label: string; value: number }>;
  suricata_protocols: Array<{ label: string; value: number }>;
  top_ports: Array<{ label: string; value: number }>;
  source_indices: Array<{ label: string; value: number }>;
};

export function LogExplorer() {
  const [viewState] = useGlobalViewState();
  const [groupedLogs, setGroupedLogs] = useState<GroupedLog[]>(() => readCached<GroupedLog[]>("fda-cache:logs-grouped") || []);
  const [analytics, setAnalytics] = useState<Analytics>(() => readCached<Analytics>("fda-cache:logs-analytics") || {
    timeline: [],
    suricata_event_types: [],
    suricata_protocols: [],
    top_ports: [],
    source_indices: [],
  });
  const [selectedGroupId, setSelectedGroupId] = useState("");
  const [detail, setDetail] = useState<LogDetailPayload | null>(null);
  const [runState, setRunState] = useState<RunState>(() => readCached<RunState>("fda-cache:run-current") || { active: false });
  const [history, setHistory] = useState<RunState[]>(() => readCached<RunState[]>("fda-cache:run-history") || []);
  const [runTimeline, setRunTimeline] = useState<TimelinePayload | null>(null);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);

  const selectedGroup = useMemo(
    () => groupedLogs.find((item) => item.group_id === selectedGroupId) || groupedLogs[0] || null,
    [groupedLogs, selectedGroupId],
  );

  useEffect(() => {
    let active = true;

    const appendTerminal = (line: string) => {
      setTerminalLines((current) => [line, ...current].slice(0, 18));
    };

    const load = async () => {
      const timeWindow = resolveTimeWindow(viewState);
      const query = buildQuery({ ...timeWindow, run_id: viewState.selectedRunId, limit: 160 });
      appendTerminal("refresh: loading grouped logs + analytics + run state");

      const [groups, charts, currentRun, runHistory] = await Promise.all([
        apiFetch<{ items: GroupedLog[] }>(`/api/logs/grouped?${query}`),
        apiFetch<Analytics>(`/api/logs/analytics?${buildQuery({ ...timeWindow, run_id: viewState.selectedRunId })}`),
        apiFetch<RunState>("/api/runs/current"),
        apiFetch<{ items: RunState[] }>("/api/runs/history?limit=30"),
      ]);

      if (!active) {
        return;
      }

      setGroupedLogs(groups.items || []);
      setSelectedGroupId((current) => current || groups.items[0]?.group_id || "");
      setAnalytics(charts);
      setRunState(currentRun);
      setHistory(runHistory.items || []);
      writeCached("fda-cache:logs-grouped", groups.items || []);
      writeCached("fda-cache:logs-analytics", charts);
      writeCached("fda-cache:run-current", currentRun);
      writeCached("fda-cache:run-history", runHistory.items || []);
      appendTerminal(`refresh: ${groups.items.length} grouped events loaded`);
    };

    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 3000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [viewState]);

  useEffect(() => {
    if (!selectedGroup?.latest?.id) {
      setDetail(null);
      return;
    }
    const timeWindow = resolveTimeWindow(viewState);
    const query = buildQuery({ ...timeWindow, run_id: viewState.selectedRunId });
    apiFetch<LogDetailPayload>(`/api/logs/${encodeURIComponent(selectedGroup.latest.id)}/detail?${query}`)
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [selectedGroup?.latest?.id, viewState]);

  useEffect(() => {
    if (!viewState.selectedRunId) {
      setRunTimeline(null);
      return;
    }
    const query = buildQuery({ ...resolveTimeWindow(viewState), run_id: viewState.selectedRunId, entity_type: "run", entity_id: viewState.selectedRunId, limit: 200 });
    apiFetch<TimelinePayload>(`/api/timeline?${query}`).then(setRunTimeline).catch(() => setRunTimeline(null));
  }, [viewState]);

  const playbookIds = useMemo(() => {
    if (!detail) {
      return [];
    }
    return Array.from(new Set(detail.matches.flatMap((rule) => rule.mitre_ids).filter(Boolean))).slice(0, 16);
  }, [detail]);

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Logs + runs workspace <span className="live-badge">LIVE</span></div>
          <h1 className="page-title small">Consecutive log groups, run context, and timeline drilldown for logs, rules, playbooks, and IPs</h1>
        </div>
      </section>

      <section className="dashboard-grid">
        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Timeline</span><h2>Signal wave</h2></div></div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={analytics.timeline}>
              <defs>
                <linearGradient id="logsTimelineFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2563eb" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#2563eb" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#3b82f6" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis stroke="#60a5fa" />
              <Tooltip />
              <Area dataKey="count" stroke="#2563eb" fill="url(#logsTimelineFill)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Event composition</span><h2>Type and transport mix</h2></div></div>
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={analytics.suricata_event_types.slice(0, 6).map((item, index) => ({
              label: item.label,
              events: item.value,
              protocols: analytics.suricata_protocols[index]?.value || 0,
            }))}>
              <CartesianGrid stroke="#3b82f6" vertical={false} />
              <XAxis dataKey="label" stroke="#60a5fa" />
              <YAxis stroke="#60a5fa" />
              <Tooltip />
              <Area dataKey="events" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
              <Line dataKey="protocols" stroke="#60a5fa" strokeWidth={2} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Ports</span><h2>Destination pressure</h2></div></div>
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={analytics.top_ports.slice(0, 10)}>
              <CartesianGrid stroke="#3b82f6" vertical={false} />
              <XAxis dataKey="label" stroke="#60a5fa" />
              <YAxis stroke="#60a5fa" />
              <Tooltip />
              <Area dataKey="value" stroke="#93c5fd" fill="#93c5fd" fillOpacity={0.16} />
              <Line dataKey="value" stroke="#0a0f29" dot={false} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="panel padded chart-panel">
          <div className="panel-head"><div><span className="kicker">Sources</span><h2>Index contribution</h2></div></div>
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={analytics.source_indices.slice(0, 8)}>
              <CartesianGrid stroke="#3b82f6" vertical={false} />
              <XAxis dataKey="label" stroke="#60a5fa" />
              <YAxis stroke="#60a5fa" />
              <Tooltip />
              <Area dataKey="value" stroke="#60a5fa" fill="#60a5fa" fillOpacity={0.18} />
              <Line dataKey="value" stroke="#0a0f29" dot={{ r: 2 }} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Grouped stream</span><h2>Consecutive event concatenation</h2></div></div>
          <div className="feed-list">
            {groupedLogs.map((group) => (
              <button key={group.group_id} className={`feed-card ${selectedGroup?.group_id === group.group_id ? "selected" : ""}`} onClick={() => setSelectedGroupId(group.group_id)}>
                <div className="feed-meta">
                  <span className="chip accent">{group.latest.source_index}</span>
                  <span>{new Date(group.end_time).toLocaleString()}</span>
                </div>
                <strong>{group.latest.message}</strong>
                <p>
                  {group.count} event{group.count > 1 ? "s" : ""} grouped, {new Date(group.start_time).toLocaleString()} {"->"} {new Date(group.end_time).toLocaleString()}
                </p>
                <div className="chip-row">
                  <span className="chip">src {group.latest.source_ip || "n/a"}</span>
                  <span className="chip">dst {group.latest.destination_ip || "n/a"}</span>
                  {group.latest.suricata_event_type ? <span className="chip">{group.latest.suricata_event_type}</span> : null}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="panel padded">
          <div className="panel-head"><div><span className="kicker">Runs + investigation</span><h2>Selected event context</h2></div></div>

          <div className="detail-card">
            <h3>Run status</h3>
            <p>{runState.active ? `${runState.name || runState.run_id} is active.` : "No active run."}</p>
            <div className="chip-row">
              {runState.run_id ? <span className="chip accent">{runState.run_id}</span> : <span className="chip">idle</span>}
              {runState.started_at ? <span className="chip">started {new Date(runState.started_at).toLocaleString()}</span> : null}
              {viewState.selectedRunId ? <span className="chip">selected {viewState.selectedRunId}</span> : null}
            </div>
          </div>

          <div className="detail-card">
            <h3>Saved run history</h3>
            <div className="history-list">
              {history.slice(0, 8).map((run) => (
                <div key={`${run.run_id}-${run.started_at}`} className="history-item">
                  <strong>{run.run_id}</strong>
                  <span>{run.saved ? "saved" : "completed"}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="terminal-window">
            {terminalLines.map((line, index) => (
              <div key={`${line}-${index}`} className="terminal-line">$ {line}</div>
            ))}
          </div>

          {detail ? (
            <>
              <div className="detail-card">
                <h3>Selected log detail</h3>
                <p>{detail.log.message}</p>
                <div className="chip-row">
                  <span className="chip accent">{detail.log.source_index}</span>
                  <span className="chip">start {new Date(selectedGroup?.start_time || detail.log.timestamp).toLocaleString()}</span>
                  <span className="chip">stop {new Date(selectedGroup?.end_time || detail.log.timestamp).toLocaleString()}</span>
                  {detail.log.host_name ? <span className="chip">host {detail.log.host_name}</span> : null}
                  {detail.log.user_name ? <span className="chip">user {detail.log.user_name}</span> : null}
                  {detail.log.run_id ? <span className="chip">run {detail.log.run_id}</span> : null}
                  {detail.log.network_transport ? <span className="chip">{detail.log.network_transport}</span> : null}
                  {detail.log.destination_port ? <span className="chip">port {detail.log.destination_port}</span> : null}
                </div>
              </div>

              <div className="detail-card">
                <h3>Rule mapping</h3>
                <div className="feed-list compact">
                  {detail.matches.map((rule) => (
                    <Link key={rule.rule_id} href={`/rules/${encodeURIComponent(rule.rule_id)}`} className="feed-card static">
                      <div className="feed-meta">
                        <span className="chip accent">{rule.engine}</span>
                        <span>{rule.rule_id}</span>
                      </div>
                      <strong>{rule.title}</strong>
                      <p>{rule.description}</p>
                    </Link>
                  ))}
                </div>
              </div>

              <div className="detail-card">
                <h3>SOAR and MITRE mapping</h3>
                <div className="chip-row">
                  {playbookIds.map((techniqueId) => (
                    <Link key={techniqueId} href={`/playbooks/${encodeURIComponent(techniqueId)}`} className="chip accent">
                      {techniqueId}
                    </Link>
                  ))}
                </div>
              </div>

              <div className="detail-card">
                <h3>Log timeline</h3>
                <p>{detail.timeline.count} timeline events in selected range.</p>
                <div className="chip-row">
                  <span className="chip">start {detail.timeline.start_time ? new Date(detail.timeline.start_time).toLocaleString() : "n/a"}</span>
                  <span className="chip">stop {detail.timeline.stop_time ? new Date(detail.timeline.stop_time).toLocaleString() : "n/a"}</span>
                </div>
              </div>

              {Object.values(detail.ip_context).map((context) => (
                <div key={context.ip} className="detail-card">
                  <h3>IP timeline: {context.ip}</h3>
                  <p>{context.timeline.count} events in selected range.</p>
                  <div className="chip-row">
                    <span className="chip">start {context.timeline.start_time ? new Date(context.timeline.start_time).toLocaleString() : "n/a"}</span>
                    <span className="chip">stop {context.timeline.stop_time ? new Date(context.timeline.stop_time).toLocaleString() : "n/a"}</span>
                  </div>
                </div>
              ))}
            </>
          ) : (
            <div className="detail-card"><p>Select a grouped event to inspect mapped rules, playbooks, and timeline context.</p></div>
          )}

          {runTimeline ? (
            <div className="detail-card">
              <h3>Selected run timeline</h3>
              <p>{runTimeline.count} mapped events.</p>
              <div className="chip-row">
                <span className="chip">start {runTimeline.start_time ? new Date(runTimeline.start_time).toLocaleString() : "n/a"}</span>
                <span className="chip">stop {runTimeline.stop_time ? new Date(runTimeline.stop_time).toLocaleString() : "n/a"}</span>
              </div>
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}
