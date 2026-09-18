import { IncidentsView } from "@/components/incidents-view";

export default function IncidentsPage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Incidents</div>
          <h1 className="page-title small">Active incidents with AI verdicts</h1>
        </div>
      </section>
      <IncidentsView />
    </div>
  );
}
