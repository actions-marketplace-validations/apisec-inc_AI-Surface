# ai-surface viewer: "AI Attack Surface Map" (`ui/`)

A zero-build, offline web app for an ai-surface **schema-1.0** report. It does
**no scanning** itself: it renders a `report.json` produced by the Python engine,
and (optionally) asks a local `/api/scan` endpoint to produce one. The centerpiece
is a hand-rolled **attack-surface map**: the scanned repo at the center, category
hubs around it, every finding as a leaf node.

- `index.html`: minimal shell (the page is built by JS into `#app`)
- `styles.css`: design system; dark-first with an elegant light mode
  (`prefers-color-scheme` + a manual toggle persisted in `localStorage`)
- `app.js`: vanilla JS; the only network calls are `fetch("./report.json")` and a
  POST to `/api/scan`
- `report.json`: rich 28-surface demo report (byte-equal copy of
  `fixtures/sample_report.json`) so the viewer runs standalone

No build step, no framework, no CDN, no SVG/graph library. Works fully offline.

## App shape

The UI is structured like an app, not a single long marketing scroll:

1. **Welcome / front door** (shown when no report is loaded): the product name, a
   one-line value prop, and the input options as the entry point:
   - a "Scan a GitHub repo URL" field,
   - an "or scan a local path" field (prefilled `.`),
   - a primary **Scan** button and a secondary **View demo** button,
   - a hint for terminal users: `ai-surface scan . --ui`.
2. **Hero** (once a report is loaded): the **Attack Surface Map** plus a summary
   rail (total surfaces, the inventoried-vs-assessed split, by-category breakdown).
   This is the screenshot moment and is largely unchanged visually.
3. **Tabbed workspace** below the hero:
   - **Overview**: summary stats, the assessed-severity distribution, and the
     **Top risks** triage list (the "where do I start" view).
   - **Findings**: the full inventory explorer, searchable and filterable by
     category and severity (mostly severity-free inventory).
   - **MCP Audit**: a dedicated home for the deep-dive audit layer (the
     differentiator). Renders generically from `finding.audit`, so any future
     audited category appears automatically: risk flags with severity + OWASP +
     remediation, secrets (name/type only, never values), and source trust.
   - **Validate**: the paid bridges deduped by `sku`, framed as next steps.
   Tabs are keyboard accessible (arrow keys / Home / End, roving `tabindex`,
   `aria-selected`) and default to Overview.
4. **Detail drawer** (right-side slide-in): clicking any map node, any finding row,
   any Top-risks item, or any MCP Audit card opens that finding's full detail
   (evidence, files, snippet, permissions, risk indicators, the audit block when
   present, the API metadata when present, and the finding's bridge CTA). Closeable
   via the X button, Esc, or click-outside. Detail lives in the drawer, not inline.

**Top risks vs Findings** are no longer redundant siblings on one scroll: Top risks
is a severity-ordered triage shortlist in Overview; Findings is the full inventory
in its own tab.

## Run locally

From inside this directory:

```bash
cd ui
python3 -m http.server 8000
# then open http://localhost:8000
```

A static server is enough for **View demo**, which fetches `./report.json`. Opening
`index.html` directly via `file://` is blocked by browser CORS rules.

To view a real scan instead of the demo, drop your engine output in as
`ui/report.json` and use View demo, or wire the `/api/scan` endpoint below.

## The `/api/scan` endpoint (optional)

The **Scan** button POSTs JSON `{ "repo_url"?: "...", "path"?: "..." }` to
`/api/scan` and expects a **schema-1.0 report** back as JSON. The endpoint does the
scanning; the UI never scans in JS.

The endpoint may not exist yet. The UI degrades gracefully:

- **404 or network failure** (for example the static hosted demo with no local
  server): the UI shows "Live scanning needs the local tool. Install ai-surface and
  run `ai-surface scan . --ui`, or View demo." **View demo always works.**
- **Other HTTP errors**: the status text is surfaced inline.
- **Non-report responses**: rejected with a clear message.

A CLI integrator that serves this directory can implement `/api/scan` to run the
normal scan and return its schema-1.0 output directly (no transform needed).

## What it renders

- **Hero + attack-surface map**: a radial-cluster SVG graph built by hand. Center
  node = the scanned repo; ring 1 = a hub per category present (with a count); ring
  2 = the individual findings. Node **size** encodes importance (assessed and
  higher-severity findings are larger); node **color** uses the severity palette
  when a finding is assessed, neutral otherwise; assessed-with-risk nodes get a
  glowing severity ring. Hover focuses a category; clicking a leaf opens the detail
  drawer; clicking a hub jumps to that category in the Findings tab. The layout is
  pure trig (deterministic, no physics) and fans leaves into arcs that widen with
  count, so it looks intentional from ~4 to ~40 nodes and shows a clean empty state
  at 0.
- **Overview tab**: real counts only (no fabricated aggregate "security score"), the
  assessed-severity distribution, and the Top risks triage list.
- **Findings tab**: searchable, filterable by category and severity, grouped into
  collapsible category sections rendered **generically from data** (any
  future/unknown category appears automatically with a fallback icon/label).
- **MCP Audit tab**: every audited surface, severity-ordered, rendered generically
  from `finding.audit` (risk flags + OWASP LLM01 to LLM10 badges/tooltips +
  remediation; secrets by **name / type / severity / location only**, never a value;
  source trust).
- **Validate tab**: de-duplicated `bridges` (ordered by `summary.bridges_available`)
  as confident, non-naggy CTAs to the paid APIsec platform; per-finding bridges also
  appear in that finding's drawer.
- **Detail drawer**: full finding data: evidence (files + lines + snippet),
  permissions, risk indicators, the audit block when present, the API metadata when
  present, and the finding's bridge CTAs.

Empty/edge states handled: no report (welcome screen), no findings (clean-result map
empty state), no severities (explicit "inventoried, not assessed" note), no audit
(empty MCP Audit tab), no bridges (empty Validate tab), non-fatal `errors[]`
(banner), and a failed `report.json` load (inline status with run instructions).
