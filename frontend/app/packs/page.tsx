import { PackEditor } from "@/components/pack-editor";

export default function PacksPage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Detection Packs</div>
          <h1 className="page-title small">Browse and edit detection rule packs</h1>
        </div>
      </section>
      <PackEditor />
    </div>
  );
}
