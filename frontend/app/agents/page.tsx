import { AgentBoard } from "../../components/agent-board";

export default function AgentsPage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Agents</div>
          <h1 className="page-title small">ZeroClaw-compatible orchestration hands and validation history</h1>
        </div>
      </section>
      <AgentBoard />
    </div>
  );
}
