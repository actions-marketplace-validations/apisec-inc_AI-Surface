/* ============================================================================
 * ai-surface — "AI Attack Surface Map"
 * Renders a schema-1.0 report (docs/SCHEMA_v1.md). It does ZERO scanning.
 * Exactly one network call: fetch("./report.json").
 * Vanilla JS, no framework, no CDN, works fully offline.
 * ========================================================================== */

(() => {
  "use strict";

  /* ---- constants ---------------------------------------------------------- */
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

  // category presentation (icon + short description). Renders generically;
  // unknown categories fall back to a sensible default.
  const CATS = {
    "llm-sdk":         { label: "LLM SDKs",        desc: "LLM provider SDK call sites",            icon: "chip"   },
    "agent-framework": { label: "Agents",          desc: "Agent definitions and their tools",      icon: "agent"  },
    "mcp-server":      { label: "MCP Servers",     desc: "MCP servers (discovery + deep-dive audit)", icon: "plug" },
    "model-gateway":   { label: "Model Gateways",  desc: "Proxy / routing layers",                 icon: "route"  },
    "ai-infra":        { label: "AI Infra",        desc: "Self-hosted runtimes, cloud endpoints",  icon: "server" },
    "env-key":         { label: "Env Keys",        desc: "AI provider key names",                  icon: "key"    },
    "api":             { label: "APIs",            desc: "HTTP / REST endpoints + OpenAPI specs",  icon: "globe"  },
  };
  const CAT_ORDER = ["mcp-server", "agent-framework", "llm-sdk", "model-gateway", "ai-infra", "env-key", "api"];

  // OWASP LLM Top 10 (2025) — for badge tooltips.
  const OWASP = {
    LLM01: "Prompt Injection",
    LLM02: "Sensitive Information Disclosure",
    LLM03: "Supply Chain",
    LLM04: "Data and Model Poisoning",
    LLM05: "Improper Output Handling",
    LLM06: "Excessive Agency",
    LLM07: "System Prompt Leakage",
    LLM08: "Vector and Embedding Weaknesses",
    LLM09: "Misinformation",
    LLM10: "Unbounded Consumption",
  };

  const ICONS = {
    chip:   '<path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><rect x="6" y="6" width="12" height="12" rx="2.5" stroke="currentColor" stroke-width="1.6"/><rect x="9.5" y="9.5" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.6"/>',
    agent:  '<circle cx="12" cy="8" r="4" stroke="currentColor" stroke-width="1.6"/><path d="M4 21a8 8 0 0116 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    plug:   '<path d="M9 2v6M15 2v6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M7 8h10v3a5 5 0 01-5 5 5 5 0 01-5-5V8z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 16v6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    route:  '<circle cx="5" cy="6" r="2.5" stroke="currentColor" stroke-width="1.6"/><circle cx="19" cy="18" r="2.5" stroke="currentColor" stroke-width="1.6"/><path d="M5 8.5V12a4 4 0 004 4h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.6"/><rect x="3" y="13" width="18" height="7" rx="2" stroke="currentColor" stroke-width="1.6"/><circle cx="7" cy="7.5" r="1" fill="currentColor"/><circle cx="7" cy="16.5" r="1" fill="currentColor"/>',
    key:    '<circle cx="8" cy="8" r="4.5" stroke="currentColor" stroke-width="1.6"/><path d="M11.2 11.2L20 20M17 17l2-2M15 15l2-2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    globe:  '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18" stroke="currentColor" stroke-width="1.6"/>',
    node:   '<circle cx="12" cy="12" r="6" stroke="currentColor" stroke-width="1.6"/>',
    file:   '<path d="M5 3h8l6 6v12a0 0 0 010 0H5a0 0 0 010 0V3z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M13 3v6h6" stroke="currentColor" stroke-width="1.4"/>',
    arrow:  '<path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>',
    close:  '<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    search: '<circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.7"/><path d="M16.5 16.5L21 21" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    caret:  '<path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>',
    lock:   '<rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 018 0v3" stroke="currentColor" stroke-width="1.6"/>',
    shield: '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linejoin="round"/>',
    warn:   '<path d="M12 3l10 18H2L12 3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" fill="none"/><path d="M12 10v5M12 18h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    info:   '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 11v5M12 8h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    sun:    '<circle cx="12" cy="12" r="4.5" stroke="currentColor" stroke-width="1.7"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    moon:   '<path d="M21 12.8A8.5 8.5 0 1111.2 3a6.5 6.5 0 009.8 9.8z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" fill="none"/>',
  };

  /* ---- tiny helpers ------------------------------------------------------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const icon = (name, cls = "") =>
    `<svg viewBox="0 0 24 24" fill="none" class="${cls}" aria-hidden="true">${ICONS[name] || ICONS.node}</svg>`;
  const sevColor = (s) => s ? `var(--sev-${s})` : "var(--sev-none)";
  const catMeta = (c) => CATS[c] || { label: titleCase(c), desc: "Detected AI surface", icon: "node" };
  const titleCase = (s) => String(s || "").replace(/[-_]/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
  const catRank = (c) => { const i = CAT_ORDER.indexOf(c); return i < 0 ? 99 : i; };

  /* ---- state -------------------------------------------------------------- */
  let REPORT = null;
  let FINDINGS = [];           // augmented with stable index id
  const state = { q: "", cat: "all", sev: "all" };

  /* ======================================================================== *
   * BOOT
   * ======================================================================== */
  initTheme();
  fetch("./report.json", { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`); return r.json(); })
    .then((data) => { REPORT = data; renderApp(); })
    .catch((err) => renderFatal(err));

  /* ---- theme -------------------------------------------------------------- */
  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("ai-surface-theme"); } catch (_) {}
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    } else {
      const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
      document.documentElement.setAttribute("data-theme", prefersLight ? "light" : "dark");
    }
  }
  function toggleTheme() {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("ai-surface-theme", next); } catch (_) {}
    // map colors are baked from CSS vars at draw time -> redraw
    if (REPORT) drawMap();
  }

  /* ======================================================================== *
   * FATAL (report.json load failure)
   * ======================================================================== */
  function renderFatal(err) {
    const app = $("#app");
    app.removeAttribute("aria-busy");
    app.innerHTML = `
      <div class="shell">
        ${topbarHTML()}
        <div class="fatal reveal">
          <div class="ic">${icon("warn")}</div>
          <h2>Couldn't load <span class="mono">report.json</span></h2>
          <p>This viewer renders a <span class="mono">schema-1.0</span> report emitted by the
             ai-surface engine. It does no scanning itself. Serve this directory over HTTP so
             the page can <span class="mono">fetch("./report.json")</span> (opening via
             <span class="mono">file://</span> is blocked by the browser).</p>
          <pre>cd ui
python3 -m http.server 8000
# then open http://localhost:8000</pre>
          <p class="detail">${esc(err && err.message ? err.message : String(err))}</p>
        </div>
      </div>`;
    wireTopbar();
  }

  /* ======================================================================== *
   * RENDER APP
   * ======================================================================== */
  function renderApp() {
    FINDINGS = (REPORT.findings || []).map((f, i) => ({ ...f, _id: i }));
    const app = $("#app");
    app.removeAttribute("aria-busy");
    app.innerHTML = `
      <div class="shell">
        ${topbarHTML()}
        ${heroHTML()}
        ${risksHTML()}
        ${bridgesHTML()}
        ${explorerHTML()}
        ${errorsHTML()}
        ${footerHTML()}
      </div>`;
    wireTopbar();
    drawMap();
    wireMapInteraction();
    wireExplorer();
    wireDrawer();
    wireTooltips();
  }

  /* ---- topbar ------------------------------------------------------------- */
  function topbarHTML() {
    const root = REPORT && REPORT.scan_root ? REPORT.scan_root : "";
    const ver = REPORT && REPORT.tool_version ? REPORT.tool_version : "";
    return `
      <header class="topbar">
        <div class="logo">
          <span class="logo-mark"></span>
          <b>ai-surface</b>
          <span class="by">by APIsec</span>
        </div>
        <span class="topbar-spacer"></span>
        ${root ? `<span class="chip-mono">${esc(root)}</span>` : ""}
        ${ver ? `<span class="chip-mono">v${esc(ver)}</span>` : ""}
        <button class="theme-toggle" id="theme-toggle" aria-label="Toggle color theme" title="Toggle theme">
          <span class="ic-sun">${icon("sun")}</span><span class="ic-moon">${icon("moon")}</span>
        </button>
      </header>`;
  }
  function wireTopbar() {
    const t = $("#theme-toggle");
    if (t) t.addEventListener("click", toggleTheme);
  }

  /* ======================================================================== *
   * HERO  (map + metrics rail)
   * ======================================================================== */
  function heroHTML() {
    const s = REPORT.summary || {};
    const total = s.total_findings != null ? s.total_findings : FINDINGS.length;
    const bySev = s.by_severity || {};
    const byCat = s.by_category || {};
    const catCount = Object.keys(byCat).length || new Set(FINDINGS.map((f) => f.category)).size;
    const assessed = FINDINGS.filter((f) => f.severity).length;
    const inventoried = Math.max(total - assessed, 0);
    const assessedPct = total ? Math.round((assessed / total) * 100) : 0;
    const ts = fmtDate(REPORT.scan_timestamp);

    return `
      <section class="hero">
        <span class="eyebrow reveal"><span class="dot"></span>Static AI Surface Discovery${ts ? " &middot; " + esc(ts) : ""}</span>
        <h1 class="reveal d1">The <span class="grad">AI Attack Surface</span><br>of your codebase, mapped.</h1>
        <p class="lede reveal d2">Every LLM call, agent, MCP server, gateway, key, and API we found, drawn as one map.
           <b>Discovery is severity-free by design</b> &mdash; most surfaces are inventoried; a subset is assessed
           for risk. Runtime exploitability is validated in APIsec.</p>

        <div class="stage reveal d3">
          <div class="panel map-panel" id="map-panel">
            <div class="panel-head">
              <h2>Attack Surface Map</h2>
              <span class="sub">radial cluster &middot; click any node</span>
              <span class="grow"></span>
            </div>
            <div class="map-wrap" id="map-wrap">
              <div class="map-hint">hover to focus &middot; click to inspect</div>
              ${mapLegendHTML()}
            </div>
          </div>

          <div class="rail">
            <div class="panel metric-card">
              <div class="metric-top">
                <span class="big">${total}</span>
                <span class="label">AI surface${total === 1 ? "" : "s"} discovered<br>across ${catCount} categor${catCount === 1 ? "y" : "ies"}</span>
              </div>
              <div class="assess-split">
                <div class="split-bar" title="${assessed} assessed of ${total}">
                  <i class="assessed" style="width:${assessedPct}%"></i>
                </div>
                <div class="split-legend">
                  <span><b>${inventoried}</b> inventoried</span>
                  <span><b>${assessed}</b> assessed for risk</span>
                </div>
              </div>
            </div>

            <div class="panel metric-card">
              <div class="panel-head" style="margin:-18px -20px 14px;border-radius:var(--radius) var(--radius) 0 0;">
                <h2>Assessed severity</h2>
                <span class="grow"></span>
                <span class="sub">${assessed} of ${total}</span>
              </div>
              ${severityDistHTML(bySev, assessed)}
              <div style="margin-top:18px;">
                <div class="panel-head" style="margin:0 -20px 12px;padding-left:0;border:0;border-bottom:1px solid var(--line);">
                  <h2>By category</h2>
                </div>
                ${categoryChipsHTML(byCat)}
              </div>
            </div>
          </div>
        </div>
      </section>`;
  }

  function mapLegendHTML() {
    const items = SEV_ORDER.map((s) =>
      `<span class="lg"><span class="sw" style="background:var(--sev-${s})"></span>${s}</span>`).join("");
    return `<div class="map-legend">
      ${items}
      <span class="lg"><span class="sw" style="background:var(--sev-none)"></span>inventoried</span>
      <span class="lg" style="color:var(--brand)"><span class="sw ring"></span>assessed (risk ring)</span>
    </div>`;
  }

  function severityDistHTML(bySev, assessed) {
    if (!assessed) {
      return `<div class="sev-empty">No findings have been assessed for severity yet.
        Severity comes only from the deep-dive audit layer (MCP today). Everything else is
        inventoried, not assessed.</div>`;
    }
    const peak = Math.max(...SEV_ORDER.map((s) => bySev[s] || 0), 1);
    const rows = SEV_ORDER.filter((s) => (bySev[s] || 0) > 0).map((s) => {
      const n = bySev[s] || 0;
      const pct = Math.round((n / peak) * 100);
      return `<div class="sev-row">
        <span class="name">${s}</span>
        <span class="track"><i style="width:${pct}%;background:var(--sev-${s})"></i></span>
        <span class="n">${n}</span>
      </div>`;
    }).join("");
    return `<div class="sev-dist">${rows}</div>`;
  }

  function categoryChipsHTML(byCat) {
    const entries = Object.entries(byCat);
    if (!entries.length) return `<div class="sev-empty">No categories present.</div>`;
    entries.sort((a, b) => catRank(a[0]) - catRank(b[0]));
    return `<div class="cat-grid">` + entries.map(([c, n]) => {
      const m = catMeta(c);
      return `<span class="cat-pill"><span class="ic">${icon(m.icon)}</span>${esc(m.label)}<span class="n">${n}</span></span>`;
    }).join("") + `</div>`;
  }

  /* ======================================================================== *
   * MAP — hand-rolled radial cluster layout in SVG
   * ======================================================================== *
   * Layout algorithm:
   *  - Center node = scan root (the app/repo).
   *  - Ring 1 = one hub per category present, evenly spaced around a circle.
   *    Hub angular position derived from index; we bias starting angle so the
   *    densest categories don't collide visually.
   *  - Ring 2 = the findings (leaves) for each category, fanned out in a small
   *    arc centered on their hub's angle. Arc width and leaf radius scale with
   *    the number of leaves so 4 nodes and 40 nodes both look intentional.
   *  - Node radius (size) encodes importance: assessed findings are larger,
   *    higher severity larger still; hubs sized by child count.
   *  - Color: severity palette when assessed; neutral when inventory-only.
   *    Assessed-with-risk nodes get a glowing severity ring.
   *  Everything is pure trig; no physics, deterministic, stable across redraws.
   */
  function drawMap() {
    const wrap = $("#map-wrap");
    if (!wrap) return;
    // clear previous svg/empty (keep hint + legend)
    wrap.querySelectorAll("svg, .map-empty").forEach((n) => n.remove());

    const W = 1000, H = 688;               // viewBox units (16:11)
    const cx = W / 2, cy = H / 2;

    const byCat = {};
    FINDINGS.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });
    const cats = Object.keys(byCat);

    // empty scan
    if (!FINDINGS.length) {
      const root = REPORT.scan_root ? `<span class="mono">${esc(REPORT.scan_root)}</span>` : "this codebase";
      const div = document.createElement("div");
      div.className = "map-empty";
      div.innerHTML = `<div class="big">No AI surface detected</div>
        <div>ai-surface found nothing to map in ${root}.<br>That's a clean result, not an error.</div>`;
      wrap.appendChild(div);
      return;
    }

    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    const g = document.createElementNS(NS, "g");
    g.setAttribute("class", "graph");
    svg.appendChild(g);

    const edgeLayer = mk(NS, "g");
    const nodeLayer = mk(NS, "g");
    g.appendChild(edgeLayer); g.appendChild(nodeLayer);

    // radii scale to fit the viewport regardless of count
    const hubR = Math.min(W, H) * 0.215;
    const leafR = Math.min(W, H) * 0.40;
    const startAngle = -Math.PI / 2; // top

    // --- center node ---
    const center = mk(NS, "g"); center.setAttribute("class", "node node-center");
    center.appendChild(disc(NS, cx, cy, 34, "var(--hub-fill)", "var(--line-2)", 1.5));
    const cinner = disc(NS, cx, cy, 30, "url(#coreGrad)", "none", 0);
    center.appendChild(cinner);
    const clabel = text(NS, cx, cy + 60, rootName(), "lbl");
    clabel.setAttribute("text-anchor", "middle");
    center.appendChild(clabel);
    nodeLayer.appendChild(center);

    // gradient def for core (built node-by-node; innerHTML on SVG is unreliable)
    const defs = mk(NS, "defs");
    const grad = mk(NS, "radialGradient");
    grad.setAttribute("id", "coreGrad");
    grad.setAttribute("cx", "38%"); grad.setAttribute("cy", "32%");
    [["0%", "#a98bff"], ["55%", "#7c5cff"], ["100%", "#4f6dff"]].forEach(([o, c]) => {
      const st = mk(NS, "stop");
      st.setAttribute("offset", o); st.setAttribute("stop-color", c);
      grad.appendChild(st);
    });
    defs.appendChild(grad);
    svg.insertBefore(defs, g);

    // --- hubs + leaves ---
    cats.forEach((cat, i) => {
      const ang = startAngle + (i / cats.length) * Math.PI * 2;
      const hx = cx + Math.cos(ang) * hubR;
      const hy = cy + Math.sin(ang) * hubR;
      const leaves = byCat[cat];
      const m = catMeta(cat);

      // edge center -> hub
      edgeLayer.appendChild(edge(NS, cx, cy, hx, hy, 1.7, .7));

      // hub size by child count
      const hr = 13 + Math.min(leaves.length, 12) * 1.6;

      const hub = mk(NS, "g");
      hub.setAttribute("class", "node node-hub");
      hub.dataset.cat = cat;
      hub.appendChild(ringEl(NS, hx, hy, hr + 6, "var(--brand-2)", 1.2, .35));
      hub.appendChild(disc(NS, hx, hy, hr, "var(--hub-fill)", "var(--line-2)", 1.4));
      // category count
      const ct = text(NS, hx, hy + 4, String(leaves.length), "count");
      ct.setAttribute("text-anchor", "middle"); ct.setAttribute("fill", "var(--text)");
      hub.appendChild(ct);
      // hub label (outside)
      const lx = cx + Math.cos(ang) * (hubR + hr + 14);
      const ly = cy + Math.sin(ang) * (hubR + hr + 14);
      const hl = text(NS, lx, ly + 4, m.label, "lbl");
      hl.setAttribute("text-anchor", Math.cos(ang) < -0.25 ? "end" : Math.cos(ang) > 0.25 ? "start" : "middle");
      hub.appendChild(hl);
      nodeLayer.appendChild(hub);

      // leaves fanned in an arc around the hub's angle
      const n = leaves.length;
      // arc grows with count but caps; single leaf sits straight out
      const arc = n <= 1 ? 0 : Math.min(Math.PI * 0.95, 0.32 * n);
      const lr = leafR + Math.min(n, 14) * 4; // push out a bit as crowd grows
      leaves.forEach((f, j) => {
        const t = n === 1 ? 0 : (j / (n - 1)) - 0.5;
        const la = ang + t * arc;
        const lx2 = cx + Math.cos(la) * lr;
        const ly2 = cy + Math.sin(la) * lr;

        edgeLayer.appendChild(edge(NS, hx, hy, lx2, ly2, 1.2, .5));

        const sev = f.severity;
        const assessed = !!sev;
        // size: base + severity bump
        const r = assessed ? 9 + (SEV_RANK[sev] || 0) * 1.7 : 7.5;
        const fill = assessed ? sevColor(sev) : "var(--node-fill)";
        const stroke = assessed ? "transparent" : "var(--line-2)";

        const node = mk(NS, "g");
        node.setAttribute("class", "node node-leaf");
        node.dataset.id = String(f._id);
        node.dataset.cat = cat;

        if (assessed) {
          // glowing severity ring
          node.appendChild(ringEl(NS, lx2, ly2, r + 6, sevColor(sev), 2, .9, "ring"));
        }
        const d = disc(NS, lx2, ly2, r, fill, stroke, assessed ? 0 : 1.4, "disc");
        node.appendChild(d);

        // short label (only when not too crowded, else show on hover via title)
        if (n <= 8) {
          const showLeft = Math.cos(la) < 0;
          const tl = text(NS, lx2 + (showLeft ? -(r + 7) : (r + 7)), ly2 + 4, shortName(f.surface), "lbl");
          tl.setAttribute("text-anchor", showLeft ? "end" : "start");
          node.appendChild(tl);
        }
        const title = mk(NS, "title");
        title.textContent = `${f.surface}${sev ? " — " + sev : " — inventoried"}`;
        node.appendChild(title);

        nodeLayer.appendChild(node);
      });
    });

    wrap.insertBefore(svg, wrap.firstChild);
  }

  // svg builders
  function mk(NS, tag) { return document.createElementNS(NS, tag); }
  function disc(NS, x, y, r, fill, stroke, sw, cls) {
    const c = mk(NS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", r);
    c.setAttribute("fill", fill); c.setAttribute("stroke", stroke); c.setAttribute("stroke-width", sw);
    if (cls) c.setAttribute("class", cls);
    return c;
  }
  function ringEl(NS, x, y, r, stroke, sw, op, cls) {
    const c = mk(NS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y); c.setAttribute("r", r);
    c.setAttribute("fill", "none"); c.setAttribute("stroke", stroke);
    c.setAttribute("stroke-width", sw); c.setAttribute("opacity", op);
    c.setAttribute("class", cls ? cls : "ring");
    return c;
  }
  function edge(NS, x1, y1, x2, y2, sw, op) {
    const l = mk(NS, "path");
    // gentle quadratic curve for organic feel
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const dx = x2 - x1, dy = y2 - y1;
    const off = 0.12;
    const qx = mx - dy * off, qy = my + dx * off;
    l.setAttribute("d", `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${qx.toFixed(1)} ${qy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`);
    l.setAttribute("class", "edge");
    l.setAttribute("opacity", op);
    return l;
  }
  function text(NS, x, y, str, cls) {
    const t = mk(NS, "text");
    t.setAttribute("x", x); t.setAttribute("y", y); t.setAttribute("class", cls);
    t.textContent = str;
    return t;
  }
  function rootName() {
    const r = REPORT.scan_root || "app";
    const parts = String(r).split("/").filter(Boolean);
    return parts[parts.length - 1] || r;
  }
  function shortName(s) {
    s = String(s || "");
    s = s.replace(/^(MCP Server|REST API|LangChain Agent|.*Agent):\s*/i, "");
    return s.length > 22 ? s.slice(0, 21) + "…" : s;
  }

  function wireMapInteraction() {
    const g = $("#map-wrap .graph");
    if (!g) return;
    const nodes = g.querySelectorAll(".node-leaf, .node-hub");
    nodes.forEach((node) => {
      node.addEventListener("mouseenter", () => focusCategory(g, node.dataset.cat));
      node.addEventListener("mouseleave", () => unfocus(g));
      node.addEventListener("click", () => {
        if (node.classList.contains("node-leaf")) openDrawer(Number(node.dataset.id));
        else { // hub click -> jump to that category in explorer
          state.cat = node.dataset.cat; syncFilterUI(); applyFilters();
          const exp = $("#explorer"); if (exp) exp.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      });
    });
  }
  function focusCategory(g, cat) {
    g.classList.add("dim");
    g.querySelectorAll(".node").forEach((n) => {
      if (n.classList.contains("node-center") || n.dataset.cat === cat) n.classList.add("related");
    });
  }
  function unfocus(g) {
    g.classList.remove("dim");
    g.querySelectorAll(".related").forEach((n) => n.classList.remove("related"));
  }

  /* ======================================================================== *
   * TOP RISKS
   * ======================================================================== */
  function risksHTML() {
    const risks = (REPORT.summary && REPORT.summary.top_risks) || [];
    if (!risks.length) return "";
    const items = risks.slice(0, 10).map((r, i) => {
      const idx = r.indexOf(":");
      let src = "", rest = r;
      if (idx > 0 && idx < 60) { src = r.slice(0, idx); rest = r.slice(idx + 1); }
      return `<div class="risk-item">
        <span class="rank">${String(i + 1).padStart(2, "0")}</span>
        <span class="txt">${src ? `<span class="src">${esc(src)}:</span>` : ""}${esc(rest)}</span>
      </div>`;
    }).join("");
    return `
      <section class="section risks">
        <div class="section-head">
          <h2>Top risks</h2>
          <span class="sub">severity-ordered, from the assessed surface</span>
        </div>
        <div class="risks-strip">${items}</div>
      </section>`;
  }

  /* ======================================================================== *
   * BRIDGES (paid funnel — confident, not naggy)
   * ======================================================================== */
  function bridgesHTML() {
    // de-dup by sku across all findings; preserve summary order if given
    const map = new Map();
    FINDINGS.forEach((f) => (f.bridges || []).forEach((b) => { if (b && b.sku && !map.has(b.sku)) map.set(b.sku, b); }));
    const order = (REPORT.summary && REPORT.summary.bridges_available) || [];
    const ordered = [];
    order.forEach((sku) => { if (map.has(sku)) { ordered.push(map.get(sku)); map.delete(sku); } });
    map.forEach((b) => ordered.push(b));
    if (!ordered.length) return "";

    const cards = ordered.map((b) => `
      <a class="bridge" href="${esc(b.url)}" target="_blank" rel="noopener noreferrer">
        <span class="sku">${esc(b.sku)}</span>
        <span class="lbl">${esc(b.label)}</span>
        <span class="go">Open in APIsec ${icon("arrow")}</span>
      </a>`).join("");

    return `
      <section class="section">
        <div class="bridges-band">
          <div class="lead">
            <h3>Validate exploitability at runtime in APIsec</h3>
            <p>ai-surface maps what exists, statically. APIsec proves what's actually exploitable against your
               running system. These are the upgrade paths for what we found here.</p>
          </div>
          <div class="bridge-grid">${cards}</div>
        </div>
      </section>`;
  }

  /* ======================================================================== *
   * FINDINGS EXPLORER
   * ======================================================================== */
  function explorerHTML() {
    const sevPresent = SEV_ORDER.filter((s) => FINDINGS.some((f) => f.severity === s));
    const cats = uniqueCats();

    const catFilters = [`<button class="filter-chip" data-cat="all" aria-pressed="true">All categories <span class="n">${FINDINGS.length}</span></button>`]
      .concat(cats.map((c) => {
        const n = FINDINGS.filter((f) => f.category === c).length;
        return `<button class="filter-chip" data-cat="${esc(c)}" aria-pressed="false">${esc(catMeta(c).label)} <span class="n">${n}</span></button>`;
      })).join("");

    const sevFilters = sevPresent.length ? (
      `<button class="filter-chip" data-sev="all" aria-pressed="true">Any severity</button>` +
      sevPresent.map((s) => {
        const n = FINDINGS.filter((f) => f.severity === s).length;
        return `<button class="filter-chip" data-sev="${s}" aria-pressed="false"><span class="swatch" style="background:var(--sev-${s})"></span>${s} <span class="n">${n}</span></button>`;
      }).join("")
    ) : "";

    return `
      <section class="section" id="explorer">
        <div class="section-head">
          <h2>Findings</h2>
          <span class="sub">${FINDINGS.length} surface${FINDINGS.length === 1 ? "" : "s"} &middot; grouped by category</span>
        </div>
        <div class="explorer-controls">
          <label class="search">
            ${icon("search")}
            <input id="search" type="search" placeholder="Search surfaces, files, tools, paths&hellip;" autocomplete="off" />
          </label>
        </div>
        <div class="explorer-controls" style="margin-top:-8px;">
          <div class="filter-group" id="cat-filters">${catFilters}</div>
          ${sevFilters ? `<span style="width:1px;height:22px;background:var(--line);"></span><div class="filter-group" id="sev-filters">${sevFilters}</div>` : ""}
        </div>
        <div id="results"></div>
      </section>`;
  }

  function uniqueCats() {
    const present = [...new Set(FINDINGS.map((f) => f.category))];
    present.sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a), ib = CAT_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
    return present;
  }

  function wireExplorer() {
    const search = $("#search");
    if (search) search.addEventListener("input", (e) => { state.q = e.target.value.trim().toLowerCase(); applyFilters(); });
    document.querySelectorAll("#cat-filters .filter-chip").forEach((b) =>
      b.addEventListener("click", () => { state.cat = b.dataset.cat; syncFilterUI(); applyFilters(); }));
    document.querySelectorAll("#sev-filters .filter-chip").forEach((b) =>
      b.addEventListener("click", () => { state.sev = b.dataset.sev; syncFilterUI(); applyFilters(); }));
    applyFilters();
  }
  function syncFilterUI() {
    document.querySelectorAll("#cat-filters .filter-chip").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.cat === state.cat)));
    document.querySelectorAll("#sev-filters .filter-chip").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.sev === state.sev)));
  }

  function matches(f) {
    if (state.cat !== "all" && f.category !== state.cat) return false;
    if (state.sev !== "all" && f.severity !== state.sev) return false;
    if (state.q) {
      const hay = JSON.stringify([
        f.surface, f.category, f.permissions, f.risk_indicators,
        f.evidence && f.evidence.files, f.evidence && f.evidence.snippet,
        f.evidence && f.evidence.metadata,
        f.audit && f.audit.owasp_mappings,
        f.audit && (f.audit.risk_flags || []).map((x) => [x.flag, x.description]),
      ]).toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  }

  function applyFilters() {
    const root = $("#results");
    if (!root) return;
    const shown = FINDINGS.filter(matches);

    if (!shown.length) {
      root.innerHTML = `<div class="no-results">
        <div class="big">No matching surfaces</div>
        <div>Try clearing the search or filters.</div></div>`;
      return;
    }

    const byCat = {};
    shown.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });
    const cats = Object.keys(byCat).sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a), ib = CAT_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });

    root.innerHTML = cats.map((c) => groupHTML(c, byCat[c])).join("");

    // wire group toggles
    root.querySelectorAll(".cat-group-head").forEach((h) => h.addEventListener("click", () => {
      const grp = h.closest(".cat-group");
      grp.dataset.open = grp.dataset.open === "false" ? "true" : "false";
    }));
    // wire card -> drawer
    root.querySelectorAll(".card").forEach((c) => {
      c.addEventListener("click", (e) => {
        if (e.target.closest("a")) return;
        openDrawer(Number(c.dataset.id));
      });
    });
  }

  function groupHTML(cat, items) {
    const m = catMeta(cat);
    const assessed = items.filter((f) => f.severity).length;
    return `
      <div class="cat-group" data-open="true">
        <div class="cat-group-head">
          <span class="ic">${icon(m.icon)}</span>
          <span class="meta"><b>${esc(m.label)}</b><span class="d">${esc(m.desc)}</span></span>
          ${assessed ? `<span class="count" title="${assessed} assessed">${assessed} assessed</span>` : ""}
          <span class="count">${items.length}</span>
          <span class="caret">${icon("caret")}</span>
        </div>
        <div class="cards">${items.map(cardHTML).join("")}</div>
      </div>`;
  }

  function cardHTML(f) {
    const sev = f.severity;
    const accent = sevColor(sev);
    const sevTag = sev
      ? `<span class="sev-tag" style="--accent:${accent}">${sev}</span>`
      : `<span class="sev-tag none">inventoried</span>`;

    const chips = cardChips(f);
    const files = (f.evidence && f.evidence.files) || [];
    const fileChips = files.slice(0, 3).map((fp) =>
      `<span class="file">${icon("file")}${esc(fp)}</span>`).join("") +
      (files.length > 3 ? `<span class="file">+${files.length - 3} more</span>` : "");

    // foot: audit flag dots or risk indicator count
    let foot = "";
    if (f.audit && (f.audit.risk_flags || []).length) {
      const dots = (f.audit.risk_flags || []).map((rf) =>
        `<span class="b" style="background:${sevColor(rf.severity)}"></span>`).join("");
      foot = `<span class="flags">${dots}${f.audit.risk_flags.length} risk flag${f.audit.risk_flags.length === 1 ? "" : "s"}</span>`;
    } else if ((f.risk_indicators || []).length) {
      foot = `<span class="flags">${f.risk_indicators.length} risk indicator${f.risk_indicators.length === 1 ? "" : "s"}</span>`;
    } else {
      foot = `<span class="flags">inventory record</span>`;
    }

    return `
      <article class="card" data-id="${f._id}" style="--accent:${accent}" tabindex="0">
        <div class="card-head">
          <span class="title">${esc(f.surface)}</span>
          ${sevTag}
        </div>
        ${chips ? `<div class="chips">${chips}</div>` : ""}
        ${fileChips ? `<div class="files">${fileChips}</div>` : ""}
        <div class="card-foot">
          ${foot}
          <span class="open">Inspect ${icon("arrow")}</span>
        </div>
      </article>`;
  }

  // category-aware chips (generic fallback included)
  function cardChips(f) {
    const md = (f.evidence && f.evidence.metadata) || {};
    const out = [];
    if (f.category === "api") {
      if (md.method) {
        const meth = String(md.method);
        const cls = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(meth.toUpperCase())
          ? meth.toLowerCase() : "any";
        out.push(`<span class="chip method ${cls}">${esc(meth)}</span>`);
      }
      if (md.path) out.push(`<span class="chip path">${esc(md.path)}</span>`);
      if (md.framework) out.push(`<span class="chip"><b>framework</b> ${esc(md.framework)}</span>`);
      if (md.auth) out.push(`<span class="chip"><b>auth</b> ${esc(md.auth)}</span>`);
      if (md.source_spec) out.push(`<span class="chip mono">${esc(md.source_spec)}</span>`);
      if ((f.risk_indicators || []).some((r) => /bola/i.test(r))) out.push(`<span class="chip bola">BOLA candidate</span>`);
    } else if (f.category === "llm-sdk") {
      if (md.model) out.push(`<span class="chip"><b>model</b> ${esc(md.model)}</span>`);
      if (md.non_literal_input) out.push(`<span class="chip">non-literal input</span>`);
      (f.permissions || []).slice(0, 2).forEach((p) => out.push(`<span class="chip mono">${esc(p)}</span>`));
    } else if (f.category === "mcp-server" || f.category === "agent-framework") {
      const tools = (md.tools || f.permissions || []);
      tools.slice(0, 4).forEach((t) => out.push(`<span class="chip mono">${esc(t)}</span>`));
      if (tools.length > 4) out.push(`<span class="chip">+${tools.length - 4}</span>`);
      if (f.audit && (f.audit.owasp_mappings || []).length) {
        [...new Set(f.audit.owasp_mappings)].slice(0, 3).forEach((o) =>
          out.push(owaspChip(o)));
      }
    } else {
      // generic fallback: surface a few metadata key/values, then permissions
      Object.entries(md).slice(0, 3).forEach(([k, v]) => {
        if (v == null || typeof v === "object") return;
        out.push(`<span class="chip"><b>${esc(k)}</b> ${esc(v)}</span>`);
      });
      (f.permissions || []).slice(0, 2).forEach((p) => out.push(`<span class="chip mono">${esc(p)}</span>`));
    }
    return out.join("");
  }

  function owaspChip(code) {
    const name = OWASP[code] || "OWASP LLM";
    return `<span class="chip owasp" data-tip="${esc(code)}|${esc(name)}">${esc(code)}</span>`;
  }

  /* ======================================================================== *
   * DRAWER (finding inspector)
   * ======================================================================== */
  function wireDrawer() {
    const drawer = $("#drawer");
    drawer.querySelectorAll("[data-close]").forEach((e) => e.addEventListener("click", closeDrawer));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  }

  function openDrawer(id) {
    const f = FINDINGS.find((x) => x._id === id);
    if (!f) return;
    const drawer = $("#drawer");
    const panel = $(".drawer-panel", drawer);
    panel.innerHTML = drawerHTML(f);
    panel.scrollTop = 0;
    drawer.setAttribute("aria-hidden", "false");
    $(".dr-close", panel).addEventListener("click", closeDrawer);
    document.body.style.overflow = "hidden";
    // highlight matching node in the map
    document.querySelectorAll(".node-leaf.active").forEach((n) => n.classList.remove("active"));
    const mn = document.querySelector(`.node-leaf[data-id="${id}"]`);
    if (mn) mn.classList.add("active");
  }
  function closeDrawer() {
    const drawer = $("#drawer");
    if (drawer.getAttribute("aria-hidden") === "true") return;
    drawer.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    document.querySelectorAll(".node-leaf.active").forEach((n) => n.classList.remove("active"));
  }

  function drawerHTML(f) {
    const m = catMeta(f.category);
    const sev = f.severity;
    const accent = sevColor(sev);
    const sevTag = sev
      ? `<span class="sev-tag" style="--accent:${accent}">${sev}</span>`
      : `<span class="sev-tag none">inventoried</span>`;

    const ev = f.evidence || {};
    const md = ev.metadata || {};

    // evidence block
    const files = (ev.files || []).map((fp) => `<span class="perm">${esc(fp)}</span>`).join("");
    const lines = (ev.line_numbers || []).join(", ");
    let snippet = "";
    if (ev.snippet) snippet = `<div class="snippet">${esc(ev.snippet)}</div>`;

    // metadata kv (generic, so any category renders)
    const mdRows = Object.entries(md).map(([k, v]) => {
      const val = Array.isArray(v) ? v.join(", ") : (v === null ? "—" : String(v));
      return `<dt>${esc(k)}</dt><dd class="mono">${esc(val)}</dd>`;
    }).join("");

    const perms = (f.permissions || []).map((p) => `<span class="perm">${esc(p)}</span>`).join("");
    const ris = (f.risk_indicators || []).map((r) => `<span class="ri">${esc(r)}</span>`).join("");

    const blocks = [];

    // header summary kv
    const kv = [];
    kv.push(`<dt>category</dt><dd class="mono">${esc(f.category)}</dd>`);
    kv.push(`<dt>detector</dt><dd class="mono">${esc(f.detector_name || "—")}</dd>`);
    if (lines) kv.push(`<dt>lines</dt><dd class="mono">${esc(lines)}</dd>`);
    if (mdRows) kv.push(mdRows);
    blocks.push(`<div class="dr-block"><h4>Detail</h4><dl class="kv">${kv.join("")}</dl></div>`);

    if (files) blocks.push(`<div class="dr-block"><h4>Evidence ${snippet ? "" : ""}<span class="ct">${(ev.files || []).length} file${(ev.files || []).length === 1 ? "" : "s"}</span></h4><div class="tag-list" style="margin-bottom:${snippet ? "12px" : "0"}">${files}</div>${snippet}</div>`);
    else if (snippet) blocks.push(`<div class="dr-block"><h4>Evidence</h4>${snippet}</div>`);

    if (perms) blocks.push(`<div class="dr-block"><h4>Permissions / capabilities</h4><div class="tag-list">${perms}</div></div>`);
    if (ris) blocks.push(`<div class="dr-block"><h4>Risk indicators</h4><div class="tag-list">${ris}</div></div>`);

    // ---- audit block ----
    if (f.audit) blocks.push(auditHTML(f.audit));
    else blocks.push(`<div class="dr-block"><h4>Assessment</h4>
      <div class="secret-note">${icon("info")}<span>Inventoried, not assessed. Severity comes only from the
      deep-dive audit layer (MCP today). This surface was discovered but not risk-scored.</span></div></div>`);

    // ---- bridges ----
    const bridges = (f.bridges || []).map((b) => `
      <a class="dr-bridge" href="${esc(b.url)}" target="_blank" rel="noopener noreferrer">
        <span class="sku">${esc(b.sku)}</span>
        <span class="lbl">${esc(b.label)} ${icon("arrow", "")}</span>
      </a>`).join("");
    if (bridges) blocks.push(`<div class="dr-block"><h4>Validate at runtime</h4>${bridges}</div>`);

    return `
      <div class="dr-head">
        <button class="dr-close" aria-label="Close">${icon("close")}</button>
        <div class="ey"><span class="ic" style="color:var(--brand-2)">${icon(m.icon)}</span>
          <span class="cat">${esc(m.label)}</span>${sevTag}</div>
        <h3>${esc(f.surface)}</h3>
      </div>
      <div class="dr-body">${blocks.join("")}</div>`;
  }

  function auditHTML(a) {
    const flags = (a.risk_flags || []).map((rf) => {
      const accent = sevColor(rf.severity);
      const owasp = (rf.owasp || []).map(owaspChip).join("");
      return `
        <div class="flag">
          <div class="flag-top" style="--accent:${accent}">
            <span class="sev-tag" style="--accent:${accent}">${esc(rf.severity || "info")}</span>
            <span class="fid">${esc(rf.flag)}</span>
            <span class="grow"></span>
          </div>
          <div class="flag-body">
            ${rf.description ? `<p class="desc">${esc(rf.description)}</p>` : ""}
            ${owasp ? `<div class="owasp-row">${owasp}</div>` : ""}
            ${rf.remediation ? `<div class="rem"><b>Fix:</b> ${esc(rf.remediation)}</div>` : ""}
          </div>
        </div>`;
    }).join("");

    const secrets = (a.secrets || []).map((s) => `
      <div class="secret-row">
        <span class="lock">${icon("lock")}</span>
        <span style="flex:1">
          <span class="sname">${esc(s.name)}</span>
          <span class="smeta">${esc(s.secret_type || "secret")}${s.confidence ? " &middot; " + esc(s.confidence) + " confidence" : ""}${s.location ? " &middot; " + esc(s.location) : ""}</span>
        </span>
        ${s.severity ? `<span class="sev-tag" style="--accent:${sevColor(s.severity)}">${esc(s.severity)}</span>` : ""}
      </div>`).join("");

    const trust = [];
    if (a.trust_label) {
      const cls = a.trust_label === "verified" ? "verified" : a.trust_label === "unknown" ? "unknown" : "";
      trust.push(`<span class="trust-badge ${cls}">trust <b>${esc(a.trust_label)}</b></span>`);
    }
    if (a.trust_score != null) trust.push(`<span class="trust-badge">score <b>${esc(a.trust_score)}</b></span>`);
    if (a.registry_match) trust.push(`<span class="trust-badge">registry <b>${esc(a.registry_match)}</b></span>`);

    let html = `<div class="dr-block"><h4>${icon("shield")}Deep-dive audit <span class="ct">${(a.risk_flags || []).length} flag${(a.risk_flags || []).length === 1 ? "" : "s"}</span></h4>`;
    if (flags) html += flags;
    if (secrets) {
      html += `<h4 style="margin-top:20px">Detected secrets <span class="ct">${(a.secrets || []).length}</span></h4>${secrets}
        <div class="secret-note">${icon("lock")}<span>Names and types only. ai-surface never reads or stores a secret value &mdash; it stays on your machine.</span></div>`;
    }
    if (trust.length) html += `<h4 style="margin-top:20px">Source trust</h4><div class="trust-row">${trust.join("")}</div>`;
    html += `</div>`;
    return html;
  }

  /* ======================================================================== *
   * OWASP TOOLTIPS
   * ======================================================================== */
  function wireTooltips() {
    let tip = $(".tip");
    if (!tip) { tip = document.createElement("div"); tip.className = "tip"; document.body.appendChild(tip); }
    const show = (el) => {
      const data = el.getAttribute("data-tip");
      if (!data) return;
      const [code, name] = data.split("|");
      tip.innerHTML = `<span class="t">${esc(code)}</span>${esc(name)}`;
      const r = el.getBoundingClientRect();
      tip.style.left = Math.min(window.innerWidth - 290, r.left) + "px";
      tip.style.top = (r.bottom + 8) + "px";
      tip.classList.add("show");
    };
    const hide = () => tip.classList.remove("show");
    document.addEventListener("mouseover", (e) => {
      const el = e.target.closest("[data-tip]");
      if (el) show(el);
    });
    document.addEventListener("mouseout", (e) => {
      if (e.target.closest("[data-tip]")) hide();
    });
  }

  /* ======================================================================== *
   * ERRORS + FOOTER
   * ======================================================================== */
  function errorsHTML() {
    const errs = REPORT.errors || [];
    if (!errs.length) return "";
    return `
      <section class="errors-banner">
        <h4>${icon("warn")} ${errs.length} non-fatal detector ${errs.length === 1 ? "note" : "notes"}</h4>
        <ul>${errs.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
      </section>`;
  }

  function footerHTML() {
    const detectors = (REPORT.detectors_run || []).map((d) => `<span class="chip-mono">${esc(d)}</span>`).join(" ");
    return `
      <footer>
        <div class="row"><b>Privacy</b> ai-surface is static and fully offline. Secrets are reported by name and type only &mdash; no value is ever read into the report.</div>
        <div class="row"><b>Scope</b> Static discovery only. Runtime exploitability is the paid APIsec platform; this free tool routes to it via the bridges above.</div>
        ${detectors ? `<div class="row" style="margin-top:6px;"><b>Detectors run</b> ${detectors}</div>` : ""}
        <div class="row" style="margin-top:6px;color:var(--text-3)">schema ${esc(REPORT.schema_version || "1.0")} &middot; ai-surface by APIsec</div>
      </footer>`;
  }

  /* ---- misc --------------------------------------------------------------- */
  function fmtDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    try {
      return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    } catch (_) { return iso.slice(0, 10); }
  }
})();
