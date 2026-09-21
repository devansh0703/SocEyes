import Image from "next/image";

const STATS = [
  { num: "6,570+", lbl: "live matchers" },
  { num: "161", lbl: "MITRE techniques" },
  { num: "4", lbl: "rule engines" },
  { num: "<2s", lbl: "packet to alert" },
];

const PIPELINE = [
  {
    stage: "01 — CAPTURE",
    title: "Raw packets on the wire",
    body: "A Go agent reads AF_PACKET directly from the interface — no pcap middleman. Ethernet, IPv4, TCP, UDP and ICMP are decoded; 512-byte payload snapshots ship with every event.",
  },
  {
    stage: "02 — DETECT",
    title: "Every rule, every event",
    body: "The rule engine compiles your full catalog — Sigma, Elastic detection-rules, Wazuh XML and Panther Python — into matchers and evaluates each captured event against all of them.",
  },
  {
    stage: "03 — TRIAGE",
    title: "AI decides what matters",
    body: "Fired alerts go through LLM triage with a true/false-positive verdict and confidence score before any human or automation sees them.",
  },
  {
    stage: "04 — RESPOND",
    title: "Containment on the wire",
    body: "Confirmed hits trigger response playbooks. block_egress writes an nftables set entry, packets drop in-kernel, and TTL rollback restores connectivity automatically.",
  },
];

const FEATURES = [
  {
    title: "Behavioral network detectors",
    body: "Port scans (T1046), SSH brute force (T1110), SYN floods (T1498), C2 beaconing with jitter analysis (T1071) and volume-based data exfiltration (T1041) run continuously over the capture stream.",
  },
  {
    title: "Threat-intel enrichment",
    body: "Abuse.ch Feodo and URLhaus feeds sync into a local indicator store on a schedule you control. Events touching a known-bad IP or domain are enriched and the corresponding TI rules fire.",
  },
  {
    title: "A catalog that actually runs",
    body: "Most tools treat imported rules as documentation. SocEyes compiles them into executable matchers — a rule that can't evaluate against real events is skipped loudly, never silently.",
  },
  {
    title: "Self-hosted, one binary per role",
    body: "API + detection loop in one FastAPI process, capture agent as a static Go binary, embedded SQLite with Elasticsearch as an optional accelerator. No cluster required.",
  },
  {
    title: "Flight-deck console",
    body: "A dense operator UI: ECAM-style status bar, KPI strip with sparklines, timeline, severity donut, MITRE playbook view and live alert tables — all streaming from real data.",
  },
  {
    title: "Full audit trail",
    body: "Every detection, triage verdict, response action and rollback is recorded in the unified store with actor, rule citation and timestamp. Query it from the console or the API.",
  },
];

const ENGINES = [
  { name: "Sigma", compiled: "3,103 / 3,108", note: "Full detection grammar: selections, keywords, |contains|all, 1 of, not/and/or" },
  { name: "Elastic", compiled: "1,503 / 1,764", note: "KQL, EQL and Lucene parsed natively; ESQL and threat-match joins skipped" },
  { name: "Wazuh", compiled: "1,089 / 1,305", note: "match/regex from source XML, program_name and level filtering" },
  { name: "Panther", compiled: "867 / 1,024", note: "Real rule() Python executed in a restricted namespace" },
];

const STEPS = [
  {
    title: "Clone and install",
    body: "One command sets up the Python environment and builds the Go capture agent.",
    code: "git clone https://github.com/devansh/soceyes.git\ncd soceyes\n./soceyes install",
  },
  {
    title: "Start the stack",
    body: "The API boots with the detection loop, rule engine and response engine. First start indexes the full rule catalog.",
    code: "./soceyes start\n./soceyes status   # health, rule counts, detector state",
  },
  {
    title: "Point an agent at an interface",
    body: "Run the capture agent as root (AF_PACKET needs CAP_NET_RAW) on the interface you want watched.",
    code: "# e.g. watch container traffic\nsudo SOC_API_URL=http://127.0.0.1:8088 \\\n  SOC_AGENT_INTERFACE=docker0 ./bin/soceyes-agent",
  },
  {
    title: "Open the console",
    body: "The flight-deck UI runs on port 3000 and streams live from the API on 8088.",
    code: "cd frontend && npm install && npm run dev\n# http://localhost:3000",
  },
];

export default function Home() {
  return (
    <main>
      <nav className="nav">
        <div className="wrap nav-inner">
          <a className="brand" href="#top">
            <span className="brand-dot" />
            SocEyes
          </a>
          <div className="nav-links">
            <a href="#pipeline">How it works</a>
            <a href="#console">Console</a>
            <a href="#engines">Rule engines</a>
            <a href="#setup">Setup</a>
          </div>
          <a className="btn btn-primary" href="#setup" style={{ padding: "8px 16px", fontSize: 14 }}>
            Get started
          </a>
        </div>
      </nav>

      <header className="hero" id="top">
        <div className="wrap">
          <span className="hero-kicker">◉ DETECTION &amp; RESPONSE — SELF-HOSTED</span>
          <h1>
            Your rule catalog is not a detection engine.
            <br />
            <span className="accent">SocEyes makes it one.</span>
          </h1>
          <p className="lede">
            SocEyes captures raw packets off the wire, evaluates 6,500+ detection rules from
            Sigma, Elastic, Wazuh and Panther against live traffic, triages every hit with AI,
            and can contain confirmed threats in-kernel — from one self-hosted stack.
          </p>
          <div className="hero-cta">
            <a className="btn btn-primary" href="#setup">
              Deploy in five commands
            </a>
            <a className="btn" href="#pipeline">
              See how it works
            </a>
          </div>

          <div className="hero-stats">
            {STATS.map((s) => (
              <div className="stat" key={s.lbl}>
                <div className="num">{s.num}</div>
                <div className="lbl">{s.lbl}</div>
              </div>
            ))}
          </div>
        </div>
      </header>

      <section className="block" id="pipeline">
        <div className="wrap">
          <div className="kicker">// The pipeline</div>
          <h2>Packet in, containment out</h2>
          <p className="section-lede">
            Four stages, one data path. Every stage is watermark-tracked and survives restarts;
            nothing is re-processed and nothing is dropped silently.
          </p>
          <div className="pipeline">
            {PIPELINE.map((p) => (
              <div className="pipe-card" key={p.stage}>
                <div className="stage">{p.stage}</div>
                <h3>{p.title}</h3>
                <p>{p.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="block" id="console">
        <div className="wrap">
          <div className="kicker">// The console</div>
          <h2>Built for the 3 a.m. shift</h2>
          <p className="section-lede">
            Thirteen operator views on a single flight-deck design system: severity is the only
            loud color, every table streams live, and the state of the whole stack is visible
            from the top bar.
          </p>
          <div className="shots">
            <div className="shot">
              <Image src="/console-dashboard.png" alt="SocEyes dashboard with KPI strip, timeline and alert table" width={1280} height={800} />
              <div className="cap">
                <b>Dashboard</b> — KPI strip with sparklines, 24h timeline, severity donut, AI-verdict alert table
              </div>
            </div>
            <div className="shot">
              <Image src="/console-alerts.png" alt="SocEyes live alerts view" width={1280} height={800} />
              <div className="cap">
                <b>Alerts</b> — live-fire alerts with rule citations, triage verdicts and response preview
              </div>
            </div>
            <div className="shot">
              <Image src="/console-responses.png" alt="SocEyes response actions view" width={1280} height={800} />
              <div className="cap">
                <b>Responses</b> — enforcement actions with TTL, rollback state and audit trail
              </div>
            </div>
            <div className="shot">
              <Image src="/console-logs.png" alt="SocEyes log explorer view" width={1280} height={800} />
              <div className="cap">
                <b>Logs</b> — unified event explorer across capture, IDS and platform sources
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="block" id="engines">
        <div className="wrap">
          <div className="kicker">// Rule engines</div>
          <h2>Four platforms. One matcher loop.</h2>
          <p className="section-lede">
            The compiler turns each platform&apos;s native format into event matchers — verified
            with true-positive and false-positive probes on real payloads. Rules that can&apos;t
            discriminate (empty enrich indices, upstream stubs) are skipped with a stated reason.
          </p>
          <table className="engines">
            <thead>
              <tr>
                <th>Engine</th>
                <th>Compiled</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {ENGINES.map((e) => (
                <tr key={e.name}>
                  <td>{e.name}</td>
                  <td className="num">{e.compiled}</td>
                  <td>{e.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block" id="features">
        <div className="wrap">
          <div className="kicker">// Also in the box</div>
          <h2>Everything an operator asks for next</h2>
          <div className="features">
            {FEATURES.map((f) => (
              <div className="feat" key={f.title}>
                <h3>
                  <span className="tick">▸</span>
                  {f.title}
                </h3>
                <p>{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="block" id="setup">
        <div className="wrap">
          <div className="kicker">// Setup</div>
          <h2>Running in minutes</h2>
          <p className="section-lede">
            Linux host with Docker (for test traffic) and root access for capture. Everything
            else — Python env, Go toolchain for the agent build — is handled by the installer.
          </p>
          <div className="setup">
            {STEPS.map((s, i) => (
              <div className="step" key={s.title}>
                <div className="n">{String(i + 1).padStart(2, "0")}</div>
                <div>
                  <h3>{s.title}</h3>
                  <p>{s.body}</p>
                  <pre className="code">
                    {s.code.split("\n").map((line, j) => (
                      <div key={j}>{line.startsWith("#") ? <span className="c">{line}</span> : line}</div>
                    ))}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer>
        <div className="wrap">
          <span>SocEyes — open network detection &amp; response</span>
          <span className="mono">sigma · elastic · wazuh · panther → one engine</span>
        </div>
      </footer>
    </main>
  );
}
