"use client";

import { useState } from "react";

import { apiFetch } from "../lib/api";
import { useGlobalViewState } from "../lib/view-state";

type ChatReference = {
  rule_id?: string;
  engine?: string;
  title?: string;
  id?: string;
  timestamp?: string;
  message?: string;
  source_index?: string;
};

type ChatResponse = {
  answer: string;
  next_actions: string[];
  llm_generated: boolean;
  references?: {
    rule_hits?: ChatReference[];
    log_hits?: ChatReference[];
  };
};

export function RuleExplorerFab() {
  const [viewState] = useGlobalViewState();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("What should I investigate right now?");
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<ChatResponse | null>(null);
  const [error, setError] = useState("");

  async function send() {
    setLoading(true);
    setError("");
    try {
      const payload = await apiFetch<ChatResponse>("/api/chat", {
        method: "POST",
        body: JSON.stringify({
          message: query,
          start: viewState.start || undefined,
          end: viewState.end || undefined,
          run_id: viewState.selectedRunId || undefined,
          detailed: true,
        }),
      });
      setResponse(payload);
    } catch (chatError) {
      setError(chatError instanceof Error ? chatError.message : "Chat request failed");
    } finally {
      setLoading(false);
    }
  }

  if (!open) {
    return (
      <button className="rules-fab" onClick={() => setOpen(true)}>
        Open Chat
      </button>
    );
  }

  return (
    <section className="rules-drawer" aria-label="Chat drawer">
      <div className="rules-drawer-head">
        <div>
          <div className="kicker">SOC chat</div>
          <h2>{loading ? "Thinking..." : "Investigation chat"}</h2>
        </div>
        <button className="button button-secondary" onClick={() => setOpen(false)}>Minimize</button>
      </div>
      <div className="rules-drawer-controls">
        <textarea className="search-box" rows={3} value={query} onChange={(event) => setQuery(event.target.value)} />
        <button className="button button-primary" onClick={send} disabled={loading}>
          {loading ? "Sending..." : "Send"}
        </button>
      </div>
      <div className="rules-drawer-results">
        {error ? <div className="feed-card static">{error}</div> : null}
        {response ? (
          <>
            <div className="feed-card static">
              <div className="feed-meta">
                <span className="chip accent">{response.llm_generated ? "groq" : "context"}</span>
                <span className="chip">detailed</span>
              </div>
              <strong>Answer</strong>
              <p>{response.answer}</p>
              <div className="chip-row">
                {response.next_actions.map((item) => <span key={item} className="chip">{item}</span>)}
              </div>
            </div>
            <div className="feed-card static">
              <strong>Evidence used</strong>
              <p>
                {(response.references?.rule_hits || []).length} rule hits, {(response.references?.log_hits || []).length} log hits.
              </p>
            </div>
          </>
        ) : (
          <div className="feed-card static">
            Ask for incident triage, attack path, or next response action.
          </div>
        )}
      </div>
    </section>
  );
}
