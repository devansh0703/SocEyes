"use client";

import { useEffect, useMemo, useState } from "react";

import { apiFetch } from "../lib/api";
import { buildQuery } from "../lib/api";
import { resolveTimeWindow, useGlobalViewState } from "../lib/view-state";
import { DetailSections } from "./detail-sections";

type Section = { title: string; paragraphs?: string[]; bullets?: string[] };
type AlertItem = {
  technique_ids: string[];
  title: string;
  engine: string;
  response_preview: {
    title: string;
    summary: string;
    preview_command: string;
    playbook: { technique_id: string; sections: Section[] };
  };
};
type PlaybookDetail = {
  technique_id: string;
  path: string;
  available: boolean;
  sections: Section[];
};

export function PlaybookGallery() {
  const [viewState] = useGlobalViewState();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [details, setDetails] = useState<Record<string, PlaybookDetail>>({});

  useEffect(() => {
    let active = true;
    const load = async () => {
      const payload = await apiFetch<{ items: AlertItem[] }>(`/api/alerts/live?${buildQuery({ ...resolveTimeWindow(viewState), run_id: viewState.selectedRunId, limit: 30 })}`);
      if (!active) {
        return;
      }
      setAlerts(payload.items);
      const techniques = Array.from(new Set(payload.items.flatMap((item) => item.technique_ids).filter(Boolean)));
      setSelectedId((current) => current || techniques[0] || "");
      techniques.forEach((techniqueId) => {
        apiFetch<PlaybookDetail>(`/api/playbooks/${techniqueId}`).then((detail) => {
          if (!active) {
            return;
          }
          setDetails((current) => ({ ...current, [techniqueId]: detail }));
        }).catch(() => {});
      });
    };
    load().catch(() => {});
    const interval = setInterval(() => load().catch(() => {}), 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [viewState]);

  const techniques = useMemo(() => Array.from(new Set(alerts.flatMap((item) => item.technique_ids).filter(Boolean))), [alerts]);
  const selected = selectedId ? details[selectedId] : null;
  const relatedAlerts = alerts.filter((item) => item.technique_ids.includes(selectedId));

  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Playbooks</div>
          <h1 className="page-title small">MITRE playbooks with live detection context and executable response commands</h1>
        </div>
      </section>

      <section className="workspace-grid playbook-grid">
        <div className="panel padded">
          <div className="panel-head">
            <div>
              <span className="kicker">Technique feed</span>
              <h2>Playbooks currently present in live detections</h2>
            </div>
          </div>
          <div className="chip-row">
            <span className="chip accent">{techniques.length} techniques</span>
            <span className="chip">{alerts.length} linked detections</span>
          </div>
          <div className="feed-list">
            {techniques.map((techniqueId) => (
              <button key={techniqueId} className={`feed-card ${selectedId === techniqueId ? "selected" : ""}`} onClick={() => setSelectedId(techniqueId)}>
                <div className="feed-meta">
                  <span className="chip accent">{techniqueId}</span>
                  <span>{alerts.filter((item) => item.technique_ids.includes(techniqueId)).length} live detections</span>
                </div>
                <strong>{details[techniqueId]?.sections[0]?.title || "Loading playbook"}</strong>
                <p>{details[techniqueId]?.sections[0]?.bullets?.slice(0, 2).join(" ") || "Loading playbook detail."}</p>
              </button>
            ))}
          </div>
        </div>

        <div className="panel padded">
          {selected ? (
            <>
              <div className="panel-head">
                <div>
                  <span className="kicker">Selected playbook</span>
                  <h2>{selected.technique_id}</h2>
                </div>
              </div>
              <div className="detail-card">
                <h3>Playbook metadata</h3>
                <div className="chip-row">
                  <span className="chip accent">{selected.available ? "available" : "missing"}</span>
                  <span className="chip">{selected.sections.length} sections</span>
                  <span className="chip">{relatedAlerts.length} related detections</span>
                </div>
              </div>
              <DetailSections sections={selected.sections} />
              <div className="detail-card">
                <h3>Related live detections</h3>
                <div className="feed-list compact">
                  {alerts.filter((item) => item.technique_ids.includes(selected.technique_id)).map((item) => (
                    <div key={`${item.engine}-${item.title}-${item.technique_ids.join("-")}`} className="feed-card static">
                      <div className="feed-meta">
                        <span className="chip accent">{item.engine}</span>
                        <span>{item.response_preview.title}</span>
                      </div>
                      <strong>{item.title}</strong>
                      <p>{item.response_preview.summary}</p>
                      <div className="preview-command">{item.response_preview.preview_command}</div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="detail-card"><p>No playbook selected yet.</p></div>
          )}
        </div>
      </section>
    </div>
  );
}
