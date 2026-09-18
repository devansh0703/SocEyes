"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiFetch, buildQuery } from "../lib/api";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";
import { DetailSections } from "./detail-sections";

type Section = { title: string; paragraphs?: string[]; bullets?: string[] };

type PlaybookPayload = {
  technique_id: string;
  path: string;
  available: boolean;
  sections: Section[];
};

type RuleMatch = {
  rule_id: string;
  title: string;
  engine: string;
  description: string;
};

type LogMatch = {
  id: string;
  timestamp: string;
  message: string;
  source_index: string;
  source_ip?: string;
  destination_ip?: string;
};

type TimelinePayload = {
  count: number;
  start_time: string;
  stop_time: string;
};

export function PlaybookDetail({ techniqueId }: { techniqueId: string }) {
  const [viewState] = useGlobalViewState();
  const [playbook, setPlaybook] = useState<PlaybookPayload | null>(null);
  const [timeline, setTimeline] = useState<TimelinePayload | null>(null);
  const [rules, setRules] = useState<RuleMatch[]>([]);
  const [logs, setLogs] = useState<LogMatch[]>([]);

  useEffect(() => {
    const windowQuery = resolveTimeWindow(viewState);
    apiFetch<PlaybookPayload>(`/api/playbooks/${encodeURIComponent(techniqueId)}`).then(setPlaybook).catch(() => setPlaybook(null));
    apiFetch<TimelinePayload>(`/api/timeline?${buildQuery({ ...windowQuery, run_id: viewState.selectedRunId, entity_type: "playbook", entity_id: techniqueId, limit: 240 })}`)
      .then(setTimeline)
      .catch(() => setTimeline(null));
    apiFetch<{ matches: RuleMatch[] }>(`/api/rules/search?${buildQuery({ q: techniqueId, limit: 20 })}`)
      .then((payload) => setRules(payload.matches || []))
      .catch(() => setRules([]));
    apiFetch<{ matches: LogMatch[] }>(`/api/logs/search?${buildQuery({ ...windowQuery, run_id: viewState.selectedRunId, q: techniqueId, limit: 24 })}`)
      .then((payload) => setLogs(payload.matches || []))
      .catch(() => setLogs([]));
  }, [techniqueId, viewState]);

  if (!playbook) {
    return <div className="panel padded">Loading playbook...</div>;
  }

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">SOAR playbook</div>
          <h1 className="page-title small">{playbook.technique_id}</h1>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel padded">
          <div className="detail-card">
            <h3>Playbook timeline</h3>
            <p>{timeline?.count || 0} mapping events in selected range.</p>
            <div className="chip-row">
              <span className="chip">start {timeline?.start_time ? new Date(timeline.start_time).toLocaleString() : "n/a"}</span>
              <span className="chip">stop {timeline?.stop_time ? new Date(timeline.stop_time).toLocaleString() : "n/a"}</span>
            </div>
          </div>
          <DetailSections sections={playbook.sections} />
        </div>

        <div className="panel padded">
          <div className="detail-card">
            <h3>Mapped rules</h3>
            <div className="feed-list compact">
              {rules.map((rule) => (
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
            <h3>Related logs</h3>
            <div className="feed-list compact">
              {logs.map((log) => (
                <Link key={log.id} href="/logs" className="feed-card static">
                  <div className="feed-meta">
                    <span className="chip accent">{log.source_index || "log"}</span>
                    <span>{log.timestamp ? new Date(log.timestamp).toLocaleString() : "n/a"}</span>
                  </div>
                  <strong>{log.message}</strong>
                  <p>src {log.source_ip || "n/a"} | dst {log.destination_ip || "n/a"}</p>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
