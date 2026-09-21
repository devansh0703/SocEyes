"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type DetectionPack = {
  id: string;
  name: string;
  description: string;
  rules_count: number;
  category: string;
  tags: string[];
  author: string;
  version: string;
  updated_at: string;
};

type PackRule = {
  id: string;
  title: string;
  severity: string;
  engine: string;
  technique_ids: string[];
  description: string;
  enabled: boolean;
};

export function PackEditor() {
  const [packs, setPacks] = useState<DetectionPack[]>([]);
  const [selectedPack, setSelectedPack] = useState<DetectionPack | null>(null);
  const [rules, setRules] = useState<PackRule[]>([]);
  const [editingRule, setEditingRule] = useState<PackRule | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        // Load available detection packs (directories under detection-rules/rules/)
        const payload = await apiFetch<{ packs: DetectionPack[] }>("/api/packs");
        if (!active || !payload.packs?.length) return;
        setPacks(payload.packs);
        setSelectedPack((current) => current || payload.packs[0]);
      } catch {
        // Endpoint not yet built — show local directories as packs
        setPacks([
          { id: "network", name: "Network", description: "Network-based detections", rules_count: 0, category: "network", tags: ["suricata"], author: "soceyes", version: "1.0", updated_at: "" },
          { id: "linux", name: "Linux", description: "Linux host detections", rules_count: 0, category: "linux", tags: ["auditd"], author: "soceyes", version: "1.0", updated_at: "" },
          { id: "windows", name: "Windows", description: "Windows event detections", rules_count: 0, category: "windows", tags: ["sigma"], author: "soceyes", version: "1.0", updated_at: "" },
          { id: "ml", name: "ML Anomaly", description: "Machine-learning anomaly detections", rules_count: 0, category: "ml", tags: ["anomaly"], author: "soceyes", version: "1.0", updated_at: "" },
          { id: "threat_intel", name: "Threat Intel", description: "Threat intelligence feeds", rules_count: 0, category: "threat_intel", tags: ["ioc"], author: "soceyes", version: "1.0", updated_at: "" },
        ]);
      }
    };
    load();
    const interval = setInterval(load, 30000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  useEffect(() => {
    if (!selectedPack) return;
    let active = true;
    const loadRules = async () => {
      try {
        const payload = await apiFetch<{ rules: PackRule[] }>(`/api/packs/${selectedPack.id}/rules`);
        if (active) setRules(payload.rules || []);
      } catch {
        // Backend not ready — show empty
        if (active) setRules([]);
      }
    };
    loadRules();
  }, [selectedPack]);

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    setSaving(true);
    try {
      await apiFetch(`/api/packs/${selectedPack!.id}/rules/${ruleId}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      });
      setRules((rs) => rs.map((r) => (r.id === ruleId ? { ...r, enabled } : r)));
      setMessage(`Rule ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      setMessage(`Failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
    setSaving(false);
  };

  return (
    <div className="pack-editor">
      <div className="pack-list">
        <h3>Detection Packs</h3>
        {packs.map((pack) => (
          <button
            key={pack.id}
            className={`pack-item ${selectedPack?.id === pack.id ? "selected" : ""}`}
            onClick={() => setSelectedPack(pack)}
          >
            <div className="pack-name">{pack.name}</div>
            <div className="pack-meta">{pack.category} · {pack.tags.join(", ")}</div>
          </button>
        ))}
      </div>

      {selectedPack && (
        <div className="pack-detail">
          <div className="pack-header">
            <h2>{selectedPack.name}</h2>
            <p>{selectedPack.description}</p>
            <div className="pack-tags">{selectedPack.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
          </div>

          <div className="rules-list">
            <h3>Rules ({rules.length})</h3>
            {rules.map((rule) => (
              <div key={rule.id} className={`rule-row ${!rule.enabled ? "disabled" : ""}`}>
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={(e) => handleToggleRule(rule.id, e.target.checked)}
                  disabled={saving}
                />
                <div className="rule-info">
                  <div className="rule-title">{rule.title}</div>
                  <div className="rule-meta">
                    {rule.severity} · {rule.engine} · {rule.technique_ids.join(", ")}
                  </div>
                </div>
              </div>
            ))}
            {!rules.length && <div className="empty">No rules in this pack</div>}
          </div>
        </div>
      )}

      {message && <div className="pack-message">{message}</div>}
    </div>
  );
}
