"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type Policy = {
  auto_execute: boolean;
  allow_manual_execute: boolean;
  engines: {
    elastic: boolean;
    wazuh: boolean;
  };
};

type Preview = {
  title: string;
  summary: string;
  preview_command: string;
  success_criteria: string;
  technical_explanation?: string;
  nontechnical_explanation?: string;
  llm_generated?: boolean;
};

export function ResponsePolicy() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    apiFetch<Policy>("/api/response/policy").then(setPolicy).catch(() => {});
    apiFetch<Preview>("/api/response/preview", { method: "POST", body: JSON.stringify({ include_llm: true }) }).then(setPreview).catch(() => {});
  }, []);

  async function save(nextPolicy: Policy) {
    setPolicy(nextPolicy);
    setSaving(true);
    try {
      const updated = await apiFetch<Policy>("/api/response/policy", {
        method: "PUT",
        body: JSON.stringify(nextPolicy)
      });
      setPolicy(updated);
    } finally {
      setSaving(false);
    }
  }

  if (!policy) {
    return <div className="panel padded">Loading response policy…</div>;
  }

  return (
    <div className="panel padded">
      <div className="panel-head">
        <div>
          <span className="kicker">Response control</span>
          <h2>Policy gates and execution preview</h2>
        </div>
      </div>
      <div className="toggle-list">
        <label className="toggle-row">
          <span>Enable auto response</span>
          <input type="checkbox" checked={policy.auto_execute} onChange={(event) => save({ ...policy, auto_execute: event.target.checked })} />
        </label>
        <label className="toggle-row">
          <span>Allow manual execution</span>
          <input type="checkbox" checked={policy.allow_manual_execute} onChange={(event) => save({ ...policy, allow_manual_execute: event.target.checked })} />
        </label>
        <label className="toggle-row">
          <span>Elastic auto response</span>
          <input type="checkbox" checked={policy.engines.elastic} onChange={(event) => save({ ...policy, engines: { ...policy.engines, elastic: event.target.checked } })} />
        </label>
        <label className="toggle-row">
          <span>Wazuh auto response</span>
          <input type="checkbox" checked={policy.engines.wazuh} onChange={(event) => save({ ...policy, engines: { ...policy.engines, wazuh: event.target.checked } })} />
        </label>
      </div>
      {preview ? (
        <div className="preview-stack">
          <div className="preview-card">
            <div className="preview-label">Recommended action</div>
            <strong>{preview.title}</strong>
            <p>{preview.summary}</p>
            <p>{preview.technical_explanation || preview.summary}</p>
            <p>{preview.nontechnical_explanation || preview.summary}</p>
          </div>
          <div className="preview-card">
            <div className="preview-label">Execution command</div>
            <div className="preview-command">{preview.preview_command}</div>
          </div>
          <div className="preview-card">
            <div className="preview-label">Success criteria</div>
            <div>{preview.success_criteria}</div>
          </div>
        </div>
      ) : null}
      <div className="helper-text">{saving ? "Saving policy..." : preview?.llm_generated ? "Policy is synced and preview is Groq-generated." : "Policy is synced using live context-derived output."}</div>
    </div>
  );
}
