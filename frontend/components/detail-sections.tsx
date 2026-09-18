type DetailSection = {
  title: string;
  paragraphs?: string[];
  bullets?: string[];
};

function DetailBullet({ bullet }: { bullet: string }) {
  const parts = bullet.split(":");
  if (parts.length >= 2 && parts[0].length < 40) {
    const label = parts.shift() || "";
    const value = parts.join(":").trim();
    return (
      <li className="detail-list-item split">
        <strong>{label}</strong>
        <span>{value}</span>
      </li>
    );
  }
  return (
    <li className="detail-list-item">
      <span>{bullet}</span>
    </li>
  );
}

export function DetailSections({ sections }: { sections: DetailSection[] }) {
  return (
    <div className="detail-stack">
      {sections.map((section) => (
        <section key={section.title} className="detail-card">
          <h3>{section.title}</h3>
          {(section.paragraphs || []).map((paragraph) => (
            <p key={paragraph}>{paragraph}</p>
          ))}
          {(section.bullets || []).length ? (
            <ul className="detail-list">
              {(section.bullets || []).map((bullet) => (
                <DetailBullet key={bullet} bullet={bullet} />
              ))}
            </ul>
          ) : null}
        </section>
      ))}
    </div>
  );
}
