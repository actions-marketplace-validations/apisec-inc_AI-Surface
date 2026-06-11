# ai-surface report viewer (`ui/`)

A zero-build, offline web viewer for an ai-surface **schema-1.0** report. It does
**no scanning** &mdash; it only renders a `report.json` produced by the Python engine.

- `index.html` &mdash; page shell
- `styles.css` &mdash; design system (light + dark via `prefers-color-scheme`)
- `app.js` &mdash; vanilla JS; fetches `./report.json` and renders it
- `report.json` &mdash; demo report (copy of `fixtures/sample_report.json`) so the
  viewer runs standalone

No build step, no framework, no CDN. Works fully offline.

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

- **Summary hero** &mdash; total findings, counts by category, counts by severity
  (color-coded), and a top-risks banner from `summary`.
- **Runtime validation bridges** &mdash; de-duplicated `bridges` across findings as
  non-pushy CTA buttons to the paid APIsec platform.
- **Findings by category** &mdash; one collapsible section per category, rendered
  generically (not hardcoded to MCP). Each finding shows surface, evidence
  (files + line numbers + snippet), permissions, and risk indicators.
- **Deep-dive audit** (when `finding.audit` is present) &mdash; risk flags with
  severity + OWASP LLM Top 10 badges + remediation, and detected secrets shown by
  **name / type / severity only** (never any value).
- **API findings** &mdash; method + path, framework/auth/spec chips, and a BOLA
  candidate marker when present.

Empty states are handled for: no findings, no audit, no bridges, no severities,
and a failed `report.json` load.
