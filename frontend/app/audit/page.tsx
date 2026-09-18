import { AuditLogView } from "@/components/audit-log";

export default function AuditPage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Audit Log</div>
          <h1 className="page-title small">Every AI decision and enforcement action</h1>
        </div>
      </section>
      <AuditLogView />
    </div>
  );
}
