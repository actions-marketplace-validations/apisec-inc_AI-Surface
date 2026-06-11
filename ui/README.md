# ai-surface viewer &mdash; "AI Attack Surface Map" (`ui/`)

A zero-build, offline web viewer for an ai-surface **schema-1.0** report. It does
**no scanning** &mdash; it only renders a `report.json` produced by the Python engine.
The centerpiece is a hand-rolled **attack-surface map**: the scanned repo at the
center, category hubs around it, and every finding as a leaf node.

- `index.html` &mdash; minimal shell (the page is built by JS into `#app`)
- `styles.css` &mdash; design system; dark-first with an elegant light mode
  (`prefers-color-scheme` + a manual toggle persisted in `localStorage`)
- `app.js` &mdash; vanilla JS; the only network call is `fetch("./report.json")`
- `report.json` &mdash; demo report (byte-equal copy of `fixtures/sample_report.json`)
  so the viewer runs standalone

No build step, no framework, no CDN, no SVG/graph library. Works fully offline.

## Run locally

From inside this directory:

```bash
cd ui
python3 -m http.server 8000
# then open http://localhost:8000
```

A static server is required because the viewer `fetch()`es `./report.json`;
opening `index.html` directly via `file://` is blocked by browser CORS rules.

To view a real scan instead of the demo, drop your engine output in as
`ui/report.json` (or generate `fixtures/sample_report.json` via
`python3 fixtures/generate_sample.py` and copy it here).

## How the CLI serves this

The viewer is designed to be served by the CLI (wired separately by the
integrator):

```bash
ai-surface scan --ui
```

The integrator's wiring should:

1. Run the normal scan and produce a schema-1.0 report object.
2. Write that report as `report.json` **next to these static assets** (the engine
   already emits this shape; no transform needed).
3. Serve this `ui/` directory over `http://localhost:<port>` with any static file
   server and open the browser at it.

The viewer requires only that `report.json` is reachable at `./report.json`
relative to `index.html`. Everything in the page is rendered from that file.

## What it renders

- **Hero + attack-surface map** &mdash; a radial-cluster SVG graph built by hand.
  Center node = the scanned repo; ring 1 = a hub per category present (with a count);
  ring 2 = the individual findings. Node **size** encodes importance (assessed and
  higher-severity findings are larger); node **color** uses the severity palette when
  a finding is assessed, neutral otherwise; assessed-with-risk nodes get a glowing
  severity ring. Hover focuses a category; clicking a leaf opens the detail drawer;
  clicking a hub jumps to that category in the findings explorer. The layout is pure
  trig (deterministic, no physics) and fans leaves into arcs that widen with count,
  so it looks intentional from ~4 to ~40 nodes and shows a clean empty state at 0.
- **Hero metrics rail** &mdash; total surfaces, number of categories, the
  **inventoried vs. assessed** split (discovery is severity-free by design), the
  severity distribution of *assessed* findings only, and a by-category breakdown.
  No fabricated aggregate "security score" &mdash; real counts only.
- **Top risks** &mdash; severity-ordered strip from `summary.top_risks`.
- **Runtime validation bridges** &mdash; de-duplicated `bridges` (ordered by
  `summary.bridges_available`) as confident, non-naggy CTAs to the paid APIsec
  platform; per-finding bridges also appear in that finding's drawer.
- **Findings explorer** &mdash; searchable, filterable by category and severity,
  grouped into collapsible category sections rendered **generically from data**
  (any future/unknown category appears automatically with a fallback icon/label).
- **Detail drawer** &mdash; full finding data: evidence (files + lines + snippet),
  permissions, risk indicators, the audit block when present (risk flags with
  severity + OWASP LLM01&ndash;LLM10 badges/tooltips + remediation; secrets shown by
  **name / type / severity / location only**, never a value; source trust), and the
  finding's bridge CTAs.
- **API findings** &mdash; method + path pills, framework/auth/spec chips, and a
  BOLA-candidate marker when present.

Empty/edge states handled: no findings (clean-result map empty state), no
severities (explicit "inventoried, not assessed" note), no audit, no bridges,
non-fatal `errors[]` (banner), and a failed `report.json` load (run instructions).
