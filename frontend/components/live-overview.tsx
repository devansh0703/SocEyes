"use client";

import { useEffect, useState } from "react";

import { API_URL, apiFetch } from "../lib/api";

type Overview = {
  rules_total: number;
  logs_total: number;
  elastic_alerts_total: number;
  wazuh_alerts_total: number;
  response_actions_total: number;
  response_policy: {
    auto_execute: boolean;
    engines: Record<string, boolean>;
  };
  latest_alerts: Array<{
    engine: string;
    id: string;
    title: string;
    severity: string;
    timestamp: string;
    technique_ids: string[];
  }>;
};

export function LiveOverview() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    let eventSource: EventSource | null = null;

    const load = async () => {
      try {
        const payload = await apiFetch<Overview>("/api/overview");
        if (active) {
          setData(payload);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Failed to load overview");
        }
      }
    };

    load();

    try {
      eventSource = new EventSource(`${API_URL}/api/stream/overview`);
      eventSource.onmessage = (event) => {
        if (!active) {
          return;
        }
        setData(JSON.parse(event.data));
      };
      eventSource.onerror = () => {
        eventSource?.close();
      };
    } catch {
      const interval = setInterval(load, 3000);
      return () => clearInterval(interval);
    }

    return () => {
      active = false;
      eventSource?.close();
    };
  }, []);

  if (error && !data) {
    return <div className="panel" style={{ padding: 20 }}>{error}</div>;
  }

  if (!data) {
    return <div className="panel" style={{ padding: 20 }}>Loading live overview…</div>;
  }

  return (
    <div className="content-grid">
      <div className="panel" style={{ padding: 20 }}>
        <div className="metrics-grid">
          <div className="metric">
            <div className="subtle">Rules Indexed</div>
            <strong>{data.rules_total.toLocaleString()}</strong>
          </div>
          <div className="metric">
            <div className="subtle">Logs Indexed</div>
            <strong>{data.logs_total.toLocaleString()}</strong>
          </div>
          <div className="metric">
            <div className="subtle">Response Actions</div>
            <strong>{data.response_actions_total.toLocaleString()}</strong>
          </div>
        </div>
        <div className="metrics-grid" style={{ marginTop: 16 }}>
          <div className="metric">
            <div className="subtle">Elastic Alerts</div>
            <strong>{data.elastic_alerts_total.toLocaleString()}</strong>
          </div>
          <div className="metric">
            <div className="subtle">Wazuh Alerts</div>
            <strong>{data.wazuh_alerts_total.toLocaleString()}</strong>
          </div>
          <div className="metric">
            <div className="subtle">Auto Response</div>
            <strong className={data.response_policy.auto_execute ? "success" : "warning"}>
              {data.response_policy.auto_execute ? "Enabled" : "Manual"}
            </strong>
          </div>
        </div>
      </div>
      <div className="panel" style={{ padding: 20 }}>
        <div className="section-head" style={{ marginBottom: 12 }}>
          <div>
            <div className="eyebrow">Realtime feed</div>
            <h2 style={{ marginBottom: 0 }}>Latest detections</h2>
          </div>
        </div>
        <div className="list">
          {data.latest_alerts.slice(0, 5).map((item) => (
            <div key={`${item.engine}-${item.id}`} className="list-item">
              <div style={{ display: "flex", justifyContent: "space-between", gap: 16 }}>
                <strong>{item.title}</strong>
                <span className="chip accent">{item.engine}</span>
              </div>
              <p className="subtle" style={{ margin: "8px 0" }}>
                {item.severity || "unknown severity"} · {new Date(item.timestamp).toLocaleString()}
              </p>
              <div className="chip-row">
                {item.technique_ids.map((techniqueId) => (
                  <span key={techniqueId} className="chip">{techniqueId}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
