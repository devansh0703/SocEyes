# Surface brief — SocEyes console (UI v3)

Scope: the whole operator console (shell + Mission + Command Center + tables).
Mode: Operate. The visitor assesses network state, decides, acts. Expression
never obscures task, state, or affordance.

Audience: a single security operator watching a single-box IDS/IPS. Real
usage scene: dark room, big monitor, glances between pages; stress moments
when a critical fires.

Constraints: Next.js static export, Recharts available, no new heavy deps,
data comes from the existing /api endpoints, keep all working behavior.

## Direction contract

THESIS: An instrument panel, not a marketing site — the page reads like an
ECAM deck: a status annunciation strip up top, dense data below, chrome so
quiet that severity is the only loud thing on screen. It refuses the
category-default arrangement of hero + uniform metric-card grid + kicker
labels on every heading.

OWN-WORLD: Graphite ground (#0c0d10 family), hairline #22252e dividers
instead of bordered card confetti, Archivo for UI/display and JetBrains Mono
for data/labels/numerals, one electric-blue accent (#4d8dff) for interactive
state, semantic severity (red/amber/yellow/slate) as the only saturated
colors. Structure comes from whitespace + hairlines + type scale, not boxes.

STORY: In five seconds the operator knows: is the system healthy, what is
burning right now, what needs my decision. Primary action lives at the point
of decision (incident rows, incident detail), never in a hero.

FIRST VIEWPORT: Top status bar (44px, full width): brand left, live capture
telemetry center (events, engines, agent), enforcement-mode pill + clock
right. Below: sidebar (grouped: DETECT / RESPOND / INTEGRATE) and the page.
Mission page opens with a system-state sentence + pulse (agent-health-aware
empty/all-clear per D10), a 24h detection waveform with severity breakdown,
and a "Needs attention" queue of open high/critical incidents with inline
actions. Command Center opens with a 6-tile KPI strip (each tile: label,
value, sparkline), then real charts (volume timeline, severity mix, top
sources), then a dense alert table.

FORM: "Flight-deck operations" — strongest grounded candidate. The audience's
world is full of it: Bloomberg density, glass-cockpit annunciation strips,
Splunk/Datadog quiet chrome. Signature interaction: the status bar's live
capture telemetry (events/s ticking, agent state) that makes the whole page
feel like a running instrument.

FINISH: unreviewed and undocumented is unfinished; this build ends with the
finish review, the verdict, DESIGN.md, and every shipping raster carrying
its provenance.
