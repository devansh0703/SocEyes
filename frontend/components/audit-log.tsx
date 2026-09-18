"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type AuditEntry = {
  timestamp: string;
  type: "ai_decision" | "enforcement" | "rollback" | "observation";
  rule_id: string;
  source_ip: string;
  action: string;
  verdict?: string;
  severity?: string;
  summary?: string;
  ttl_seconds?: number;
  rolled_back?: boolean;
};

export function AuditLogView() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        // Fetch from audit log endpoint (reads from response log)
        const payload = await apiFetch<{ items: AuditEntry[] }>("/api/responses/audit/?limit=200");
        if (!active) return;
        setEntries(payload.items || []);
      } catch {
        // If no dedicated endpoint, derive from alerts + response actions
        try {
          const alerts = await apiFetch<{ items: any[] }>("/api/alerts/live/?limit=200");
          if (!active) return;
          const derived: AuditEntry[] = (alerts.items || []).map((a) => ({
            timestamp: a.timestamp,
            type: "ai_decision" as const,
            rule_id: a.rule_id || "",
            source_ip: a.source_ip || "",
            action: a.response_preview?.action || "observe_only",
            verdict: a.response_preview?.verdict,
            severity: a.severity,
            summary: a.response_preview?.nontechnical,
          }));
          setEntries(derived);
        } catch {
          if (!active) return;
        }
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 10000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  if (loading) return <div className="loading-skeleton">Loading audit log…</div>;
  if (!entries.length) {
    return (
      <div className="empty-state">
        <div className="empty-title">No decisions yet</div>
        <div className="empty-message">AI decisions and enforcement actions will appear here.</div>
      </div>
    );
  }

  return (
    <div className="audit-log">
      <div className="audit-header">
        <span>Type</span>
        <span>Action</span>
        <span>Source</span>
        <span>Verdict</span>
        <span>Time</span>
      </div>
      {entries.slice(0, 100).map((entry, idx) => (
        <div key={idx} className="audit-row">
          <span className={`audit-type type-${entry.type}`}>
            {entry.type.replace("_", " ")}
          </span>
          <span className="audit-action">{entry.action}</span>
          <span className="audit-source">{entry.source_ip || "—"}</span>
          <span className="audit-verdict">
            {entry.verdict ? entry.verdict.replace("_", " ") : "—"}
          </span>
          <span className="audit-time">
            {new Date(entry.timestamp).toLocaleString()}
          </span>
          {entry.rolled_back && <span className="audit-rollback">rolled back</span>}
        </div>
      ))}
    </div>
  );
}
