"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Incident = {
  id: string;
  title: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  rule_id: string;
  engine: string;
  technique_ids: string[];
  timestamp: string;
  verdict?: string;
  confidence?: number;
  summary?: string;
  recommended_action?: string;
};

const severityClasses: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
};

const severityIcons: Record<string, string> = {
  critical: "●",
  high: "▲",
  medium: "●",
  low: "○",
};

export function IncidentsView() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const payload = await apiFetch<{ items: Incident[] }>("/api/alerts/live?limit=50");
        if (!active) return;
        setIncidents(payload.items || []);
        if (payload.items?.length) setSelectedId(payload.items[0].id);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Failed to load incidents");
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 5000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  const selected = incidents.find((i) => i.id === selectedId);

  const handleAction = async (action: string) => {
    if (!selected) return;
    try {
      await apiFetch("/api/response/execute", {
        method: "POST",
        body: JSON.stringify({
          action,
          alert_id: selected.id,
          rule_id: selected.rule_id,
          source_ip: selected.source_ip,
          destination_ip: selected.destination_ip,
          technique_id: selected.technique_ids[0] || "",
        }),
      });
    } catch (err) {
      console.error("Action failed:", err);
    }
  };

  if (loading) return <div className="loading-skeleton">Loading incidents…</div>;
  if (error) return <div className="error-banner">{error}</div>;
  if (!incidents.length) {
    return (
      <div className="empty-state">
        <div className="empty-title">All clear</div>
        <div className="empty-message">No active incidents. The system is watching.</div>
      </div>
    );
  }

  return (
    <div className="incidents-layout">
      {/* Left: incident list */}
      <div className="incident-list">
        {incidents.map((inc) => (
          <button
            key={inc.id}
            className={`incident-card ${severityClasses[inc.severity?.toLowerCase()] || "sev-medium"} ${inc.id === selectedId ? "selected" : ""}`}
            onClick={() => setSelectedId(inc.id)}
          >
            <div className={`incident-severity ${severityClasses[inc.severity?.toLowerCase()] || "sev-medium"}`}>
              <span className="severity-icon">{severityIcons[inc.severity] || "●"}</span>
              <span className="severity-label">{inc.severity.toUpperCase()}</span>
            </div>
            <div className="incident-title">{inc.title}</div>
            <div className="incident-meta">{inc.source_ip} → {inc.destination_ip}</div>
          </button>
        ))}
      </div>

      {/* Right: selected incident detail */}
      {selected && (
        <div className="incident-detail">
          <div
            className={`detail-severity-badge ${severityClasses[selected.severity?.toLowerCase()] || "sev-medium"}`}
          >
            <span className="severity-icon">{severityIcons[selected.severity] || "●"}</span>
            {selected.severity.toUpperCase()}
          </div>

          <h2 className="detail-title">{selected.title}</h2>

          {selected.summary && (
            <div className="detail-summary">
              <div className="summary-label">AI Summary</div>
              <p>{selected.summary}</p>
            </div>
          )}

          {selected.verdict && (
            <div className="detail-verdict">
              <span className="verdict-label">Verdict:</span>{" "}
              <span className={`verdict-${selected.verdict}`}>
                {selected.verdict.replace("_", " ")}
              </span>
              {selected.confidence !== undefined && (
                <span className="confidence">
                  ({Math.round(selected.confidence * 100)}% confidence)
                </span>
              )}
            </div>
          )}

          <div className="detail-meta">
            <div><strong>Source IP:</strong> {selected.source_ip}</div>
            <div><strong>Destination IP:</strong> {selected.destination_ip}</div>
            <div><strong>Rule ID:</strong> {selected.rule_id}</div>
            <div><strong>Engine:</strong> {selected.engine}</div>
            <div><strong>MITRE:</strong> {selected.technique_ids.join(", ") || "—"}</div>
            <div><strong>Time:</strong> {new Date(selected.timestamp).toLocaleString()}</div>
          </div>

          {/* Action bar */}
          <div className="action-bar">
            <button
              className="action-btn enforce"
              onClick={() => handleAction("block_source_ip")}
            >
              Block IP
            </button>
            <button
              className="action-btn isolate"
              onClick={() => handleAction("isolate_host")}
            >
              Isolate Host
            </button>
            <button
              className="action-btn observe"
              onClick={() => handleAction("observe_only")}
            >
              Observe
            </button>
            <button
              className="action-btn dismiss"
              onClick={() => handleAction("dismiss")}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
