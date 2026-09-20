"use client";

import { useEffect, useState } from "react";

import { apiFetch } from "../lib/api";

type AlertItem = {
  engine: string;
  id: string;
  index: string;
  timestamp: string;
  title: string;
  severity: string;
  severity_level?: string;
  rule_id: string;
  message: string;
  technique_ids: string[];
};

export function LiveAlerts() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);

  useEffect(() => {
    let active = true;
    const load = async () => {
      const payload = await apiFetch<{ items: AlertItem[] }>("/api/alerts/live?limit=25");
      if (active) {
        setAlerts(payload.items);
      }
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 2000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="panel" style={{ padding: 20 }}>
      <div className="section-head">
        <div>
          <div className="eyebrow">Realtime detection flow <span className="live-badge">LIVE</span></div>
          <h2 style={{ marginBottom: 6 }}>Alerts, MITRE, and response state</h2>
        </div>
      </div>
      <div className="list">
        {alerts.map((item) => (
          <div key={`${item.engine}-${item.id}`} className="list-item">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 14 }}>
              <strong>{item.title}</strong>
              <span className="chip accent">{item.engine}</span>
            </div>
            <p className="subtle" style={{ margin: "8px 0" }}>
              {new Date(item.timestamp).toLocaleString()}
            </p>
            <p style={{ margin: "8px 0 12px" }}>{item.message || "Alert matched"}</p>
            <div className="chip-row">
              <span className={`chip sev-${(item.severity_level || item.severity || "low").toLowerCase()}`}>{item.severity_level || item.severity || "unknown"}</span>
              {item.rule_id ? <span className="tag">{item.rule_id}</span> : null}
              {item.technique_ids.map((techniqueId) => <span key={techniqueId} className="tag">{techniqueId}</span>)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
