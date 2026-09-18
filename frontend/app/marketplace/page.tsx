import { MarketplaceView } from "@/components/marketplace";

export default function MarketplacePage() {
  return (
    <div className="page-stack">
      <section className="top-row">
        <div>
          <div className="eyebrow">Marketplace</div>
          <h1 className="page-title small">Download community detection packs</h1>
        </div>
      </section>
      <MarketplaceView />
    </div>
  );
}
