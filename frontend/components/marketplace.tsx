"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type MarketplacePack = {
  id: string;
  name: string;
  description: string;
  rules_count: number;
  category: string;
  tags: string[];
  author: string;
  version: string;
};

export function MarketplaceView() {
  const [packs, setPacks] = useState<MarketplacePack[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState("");

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const payload = await apiFetch<{ packs: MarketplacePack[] }>("/api/marketplace/packs");
        if (!active) return;
        setPacks(payload.packs || []);
      } catch {
        // Marketplace not yet deployed — show helpful message
        if (active) setPacks([]);
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
  }, []);

  const handleDownload = async (packId: string) => {
    setDownloading(packId);
    try {
      const res = await fetch(`/api/marketplace/packs/${packId}/download`);
      if (!res.ok) throw new Error(`Download failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${packId}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
    }
    setDownloading("");
  };

  if (loading) return <div className="loading-skeleton">Loading marketplace…</div>;
  if (!packs.length) {
    return (
      <div className="empty-state">
        <div className="empty-title">Marketplace coming soon</div>
        <div className="empty-message">
          Community detection packs will be available for download here.
          <br />
          In the meantime, browse local packs in the Detection Packs page.
        </div>
      </div>
    );
  }

  return (
    <div className="marketplace">
      <div className="marketplace-grid">
        {packs.map((pack) => (
          <div key={pack.id} className="marketplace-card">
            <h3 className="mp-name">{pack.name}</h3>
            <p className="mp-desc">{pack.description}</p>
            <div className="mp-meta">
              <span>{pack.rules_count} rules</span>
              <span>{pack.category}</span>
              <span>v{pack.version}</span>
            </div>
            <div className="mp-tags">{pack.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
            <div className="mp-footer">
              <span className="mp-author">by {pack.author}</span>
              <span className="mp-stats">v{pack.version}</span>
              <button
                className="mp-download-btn"
                onClick={() => handleDownload(pack.id)}
                disabled={downloading === pack.id}
              >
                {downloading === pack.id ? "Packaging…" : "Download"}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
