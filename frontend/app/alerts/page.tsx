import { LiveAlerts } from "@/components/live-alerts";

export default function AlertsPage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Alerts</div>
          <h1 className="page-title small">
            Live detection alerts from Elastic, Wazuh, and Suricata
          </h1>
        </div>
      </section>
      <LiveAlerts />
    </div>
  );
}
