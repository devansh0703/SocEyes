"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";

import { apiFetch } from "../lib/api";
import { DetailSections } from "./detail-sections";

type RuleMatch = {
  rule_id: string;
  title: string;
  description: string;
  engine: string;
  path: string;
  sections: Array<{ title: string; paragraphs?: string[]; bullets?: string[] }>;
  mitre_ids: string[];
  playbooks: Array<{ technique_id: string; sections: Array<{ title: string; paragraphs?: string[]; bullets?: string[] }> }>;
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    success_criteria: string;
    technical_explanation?: string;
    nontechnical_explanation?: string;
  };
  positive_alert_count: number;
  positive_log_count: number;
  evidence: {
    alerts: Array<{ message?: string; "@timestamp"?: string; full_log?: string }>;
    logs: Array<{ message?: string; process_command_line?: string; timestamp?: string; source_index?: string }>;
  };
};

export function RuleQuery() {
  const [query, setQuery] = useState("Show me suspicious Linux privilege persistence and related logs");
  const [results, setResults] = useState<RuleMatch[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [executionNotice, setExecutionNotice] = useState("");

  const selected = useMemo(() => results.find((item) => item.rule_id === selectedId) || results[0] || null, [results, selectedId]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setExecutionNotice("");
    try {
      const payload = await apiFetch<{ matches: RuleMatch[] }>("/api/query/resolve", {
        method: "POST",
        body: JSON.stringify({ query, limit: 8 })
      });
      setResults(payload.matches);
      setSelectedId(payload.matches[0]?.rule_id || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }

  async function executeSelected() {
    if (!selected) {
      return;
    }
    const result = await apiFetch<{ response?: { action_title?: string }; preview?: { title?: string }; verification?: { status?: string; remaining_alerts?: number } }>("/api/response/execute", {
      method: "POST",
      body: JSON.stringify({
        engine: selected.engine,
        rule_id: selected.rule_id,
        technique_id: selected.mitre_ids[0] || "",
        message: `Manual response executed for ${selected.title}`
      })
    });
    const verification = result.verification?.status || "unknown";
    const remaining = result.verification?.remaining_alerts ?? 0;
    setExecutionNotice(`${result.response?.action_title || result.preview?.title || "Response executed"} | verification: ${verification} | remaining alerts: ${remaining}`);
  }

  return (
    <div className="page-stack">
      <div className="panel padded">
        <form onSubmit={submit}>
          <div className="panel-head">
            <div>
              <span className="kicker">Natural language</span>
              <h1 className="page-title small">Query to rule, log, MITRE, playbook, and response</h1>
            </div>
          </div>
          <textarea className="search-box" rows={4} value={query} onChange={(event) => setQuery(event.target.value)} />
          <div className="hero-actions">
            <button className="button button-primary" type="submit" disabled={loading}>
              {loading ? "Resolving..." : "Resolve query"}
            </button>
          </div>
        </form>
        {error ? <div className="helper-text danger">{error}</div> : null}
        {executionNotice ? <div className="helper-text success">{executionNotice}</div> : null}
      </div>

      <div className="workspace-grid">
        <div className="panel padded">
          <div className="panel-head">
            <div>
              <span className="kicker">Matched rules</span>
              <h2>Readable search results</h2>
            </div>
          </div>
          <div className="feed-list">
            {results.map((rule) => (
              <div key={rule.rule_id} className={`feed-card ${selected?.rule_id === rule.rule_id ? "selected" : ""}`}>
                <div className="feed-meta">
                  <span className="chip accent">{rule.engine}</span>
                  <span>{rule.rule_id}</span>
                </div>
                <strong>{rule.title}</strong>
                <p>{rule.description}</p>
                <div className="chip-row">
                  {rule.mitre_ids.map((item) => <span key={item} className="chip">{item}</span>)}
                </div>
                <div className="hero-actions">
                  <button className="button button-secondary" onClick={() => setSelectedId(rule.rule_id)}>Inspect</button>
                  <Link className="button button-primary" href={`/rules/${encodeURIComponent(rule.rule_id)}`}>Open rule dashboard</Link>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel padded">
          {selected ? (
            <>
              <div className="panel-head">
                <div>
                  <span className="kicker">Rule detail</span>
                  <h2>{selected.title}</h2>
                </div>
              </div>
              <div className="chip-row">
                <span className="chip accent">{selected.engine}</span>
                <span className="chip">{selected.rule_id}</span>
                <span className="chip">{selected.path}</span>
              </div>
              <div className="stat-inline-grid">
                <div className="mini-stat"><span>Positive alerts</span><strong>{selected.positive_alert_count}</strong></div>
                <div className="mini-stat"><span>Positive logs</span><strong>{selected.positive_log_count}</strong></div>
              </div>
              <DetailSections sections={selected.sections} />
              <div className="detail-card">
                <h3>Response preview</h3>
                <p>{selected.response_preview.summary}</p>
                <p>{selected.response_preview.technical_explanation || selected.response_preview.summary}</p>
                <p>{selected.response_preview.nontechnical_explanation || selected.response_preview.summary}</p>
                <div className="preview-command">{selected.response_preview.preview_command}</div>
                <p>{selected.response_preview.success_criteria}</p>
                <button className="button button-primary" onClick={executeSelected}>Execute response</button>
              </div>
              <div className="detail-card">
                <h3>Mapped playbooks</h3>
                {selected.playbooks.map((playbook) => (
                  <div key={playbook.technique_id} className="playbook-card">
                    <div className="chip accent">{playbook.technique_id}</div>
                    <DetailSections sections={playbook.sections.slice(0, 3)} />
                  </div>
                ))}
              </div>
              <div className="detail-card">
                <h3>Positive evidence</h3>
                <div className="feed-list compact">
                  {selected.evidence.logs.slice(0, 5).map((log, index) => (
                    <div key={`log-${index}`} className="feed-card static">
                      <strong>{log.source_index || "Mapped log"}</strong>
                      <p>{log.message || log.process_command_line || "Evidence"}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <p>No results yet.</p>
          )}
        </div>
      </div>
    </div>
  );
}
