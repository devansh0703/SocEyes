"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiFetch, buildQuery } from "../lib/api";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";
import { DetailSections } from "./detail-sections";

type Section = { title: string; paragraphs?: string[]; bullets?: string[] };

type RulePayload = {
  rule_id: string;
  title: string;
  description: string;
  engine: string;
  path: string;
  sections: Section[];
  mitre_ids: string[];
  playbooks: Array<{ technique_id: string; sections: Section[] }>;
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    success_criteria: string;
    technical_explanation?: string;
    nontechnical_explanation?: string;
  };
};

type TimelinePayload = {
  count: number;
  start_time: string;
  stop_time: string;
};

type RuleEvidence = {
  logs: Array<{ id?: string; message?: string; timestamp?: string; source_index?: string; source_ip?: string; destination_ip?: string }>;
  alerts: Array<{ message?: string; "@timestamp"?: string; source?: { ip?: string }; destination?: { ip?: string } }>;
};

type ExecuteResponseResult = {
  preview?: {
    title?: string;
    technical_explanation?: string;
    nontechnical_explanation?: string;
  };
  verification?: {
    status?: string;
    remaining_alerts?: number;
  };
  honeypot?: {
    session_id?: string;
    log_path?: string;
    groq_analysis?: string;
    host_port?: string;
  };
};

export function RuleDetail({ ruleId }: { ruleId: string }) {
  const [viewState] = useGlobalViewState();
  const [rule, setRule] = useState<RulePayload | null>(null);
  const [timeline, setTimeline] = useState<TimelinePayload | null>(null);
  const [evidence, setEvidence] = useState<RuleEvidence>({ logs: [], alerts: [] });
  const [execution, setExecution] = useState("");

  useEffect(() => {
    const windowQuery = resolveTimeWindow(viewState);
    apiFetch<RulePayload>(`/api/rules/${encodeURIComponent(ruleId)}`).then(setRule).catch(() => setRule(null));
    apiFetch<TimelinePayload>(`/api/timeline?${buildQuery({ ...windowQuery, run_id: viewState.selectedRunId, entity_type: "rule", entity_id: ruleId, limit: 240 })}`).then(setTimeline).catch(() => setTimeline(null));
    apiFetch<RuleEvidence>(`/api/rules/${encodeURIComponent(ruleId)}/evidence?${buildQuery({ ...windowQuery, run_id: viewState.selectedRunId, limit: 20 })}`)
      .then(setEvidence)
      .catch(() => setEvidence({ logs: [], alerts: [] }));
  }, [ruleId, viewState]);

  async function executeResponse() {
    if (!rule) {
      return;
    }
    const result = await apiFetch<ExecuteResponseResult>("/api/response/execute", {
      method: "POST",
      body: JSON.stringify({
        engine: rule.engine,
        rule_id: rule.rule_id,
        technique_id: rule.mitre_ids[0] || "",
        message: `Manual response from rule dashboard: ${rule.title}`,
      }),
    });
    const verification = result.verification?.status || "unknown";
    const remaining = result.verification?.remaining_alerts ?? 0;
    const honeypotSuffix = result.honeypot?.session_id ? `, honeypot ${result.honeypot.session_id} on port ${result.honeypot.host_port || "n/a"}` : "";
    setExecution(`response ${verification}, remaining alerts ${remaining}${honeypotSuffix}`);
  }

  if (!rule) {
    return <div className="panel padded">Loading rule details...</div>;
  }

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Rule dashboard</div>
          <h1 className="page-title small">{rule.title}</h1>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="panel padded">
          <div className="chip-row">
            <span className="chip accent">{rule.engine}</span>
            <span className="chip">{rule.rule_id}</span>
            <span className="chip">{rule.path}</span>
          </div>
          <p>{rule.description}</p>
          <DetailSections sections={rule.sections.slice(0, 6)} />
          <div className="detail-card">
            <h3>Mapped playbooks</h3>
            <div className="chip-row">
              {rule.mitre_ids.map((technique) => (
                <Link key={technique} href={`/playbooks/${encodeURIComponent(technique)}`} className="chip accent">
                  {technique}
                </Link>
              ))}
            </div>
          </div>
        </div>

        <div className="panel padded">
          <div className="detail-card">
            <h3>Rule timeline</h3>
            <p>{timeline?.count || 0} alert events in selected range.</p>
            <div className="chip-row">
              <span className="chip">start {timeline?.start_time ? new Date(timeline.start_time).toLocaleString() : "n/a"}</span>
              <span className="chip">stop {timeline?.stop_time ? new Date(timeline.stop_time).toLocaleString() : "n/a"}</span>
            </div>
          </div>

          <div className="detail-card">
            <h3>Response execution</h3>
            <p>{rule.response_preview.technical_explanation || rule.response_preview.summary}</p>
            <div className="preview-command">{rule.response_preview.preview_command}</div>
            <p>{rule.response_preview.nontechnical_explanation || rule.response_preview.summary}</p>
            <button className="button button-primary" onClick={executeResponse}>Execute response</button>
            {execution ? <div className="helper-text success">{execution}</div> : null}
          </div>

          <div className="detail-card">
            <h3>Related logs and alerts</h3>
            <div className="feed-list compact">
              {evidence.logs.slice(0, 8).map((log, index) => (
                <Link key={`log-${index}-${log.id || "x"}`} href="/logs" className="feed-card static">
                  <div className="feed-meta">
                    <span className="chip accent">{log.source_index || "log"}</span>
                    <span>{log.timestamp ? new Date(log.timestamp).toLocaleString() : "n/a"}</span>
                  </div>
                  <strong>{log.message || "Mapped evidence log"}</strong>
                  <p>src {log.source_ip || "n/a"} | dst {log.destination_ip || "n/a"}</p>
                </Link>
              ))}
              {evidence.alerts.slice(0, 4).map((alert, index) => (
                <div key={`alert-${index}`} className="feed-card static">
                  <div className="feed-meta">
                    <span className="chip">alert</span>
                    <span>{alert["@timestamp"] ? new Date(alert["@timestamp"]).toLocaleString() : "n/a"}</span>
                  </div>
                  <strong>{alert.message || "Mapped alert evidence"}</strong>
                  <p>src {alert.source?.ip || "n/a"} | dst {alert.destination?.ip || "n/a"}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
