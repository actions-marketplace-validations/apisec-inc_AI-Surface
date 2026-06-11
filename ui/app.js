/* ai-surface report viewer
 * Renders a schema-1.0 report (docs/SCHEMA_v1.md). It does NO scanning.
 * Architecture rule: this UI only RENDERS report.json. No GitHub/repo logic here.
 */

// ---- static reference data (display only; never drives detection) ----

// Category presentation. New categories the engine may add still render
// generically via CATEGORY_FALLBACK, so the UI is not hardcoded to MCP.
const CATEGORY_META = {
  "llm-sdk":         { icon: "\u{1F9E0}", label: "LLM SDK Call Sites", blurb: "Provider SDK usage in code" },
  "agent-framework": { icon: "\u{1F916}", label: "Agent Frameworks",    blurb: "Agent definitions and tools" },
  "mcp-server":      { icon: "\u{1F50C}", label: "MCP Servers",         blurb: "Model Context Protocol servers (deep-dive audit)" },
  "model-gateway":   { icon: "\u{1F500}", label: "Model Gateways",      blurb: "Proxy / routing layers" },
  "ai-infra":        { icon: "\u{1F3D7}️", label: "AI Infrastructure", blurb: "Self-hosted runtimes and cloud endpoints" },
  "env-key":         { icon: "\u{1F511}", label: "Environment Keys",    blurb: "AI provider key names" },
  "api":             { icon: "\u{1F310}", label: "API Endpoints",       blurb: "HTTP / REST endpoints and specs" },
};
const CATEGORY_FALLBACK = { icon: "\u{1F4E6}", label: null, blurb: "Discovered surface" };

// Stable category render order; unknown categories append after.
const CATEGORY_ORDER = ["mcp-server", "agent-framework", "api", "model-gateway", "ai-infra", "llm-sdk", "env-key"];

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

// OWASP LLM Top 10 names for badge tooltips. Source: https://genai.owasp.org/llm-top-10/
const OWASP_LLM = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain Vulnerabilities",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

const BRIDGE_META = {
  "agent-validation": { icon: "\u{1F916}", desc: "Validate the AI/agent surface against runtime exploits." },
  "mcp-runtime":      { icon: "\u{1F50C}", desc: "Run MCP runtime validation in the APIsec platform." },
  "api-runtime":      { icon: "\u{1F310}", desc: "Outside-in runtime testing for discovered APIs." },
};

// ---- tiny DOM helpers ----
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const sevClass = (sev) => "b-" + (sev && SEVERITY_ORDER.includes(sev) ? sev : "none");
const catMeta = (c) => {
  const m = CATEGORY_META[c];
  if (m) return m;
  return Object.assign({}, CATEGORY_FALLBACK, { label: humanize(c) });
};
function humanize(s) {
  return String(s || "").split(/[-_]/).map(w => w ? w[0].toUpperCase() + w.slice(1) : w).join(" ");
}

// ---- boot ----
document.addEventListener("DOMContentLoaded", () => {
  fetch("./report.json", { cache: "no-store" })
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status + " for ./report.json");
      return r.json();
    })
    .then((report) => render(report))
    .catch((err) => {
      $("loading").classList.add("hidden");
      $("load-error").classList.remove("hidden");
      $("load-error-detail").textContent = err && err.message ? err.message : String(err);
    });
});

function render(report) {
  $("loading").classList.add("hidden");
  $("report").classList.remove("hidden");

  renderScanMeta(report);
  renderSummary(report);
  renderTopRisks(report);
  renderBridges(report);
  renderFindings(report);
  renderErrors(report);

  // collapsible category sections
  document.querySelectorAll(".cat-header").forEach((h) => {
    h.addEventListener("click", () => h.closest(".cat-section").classList.toggle("collapsed"));
  });
}

// ---- header meta ----
function renderScanMeta(report) {
  const bits = [];
  if (report.scan_root) bits.push(`<span class="meta-item">Scanned <code>${esc(report.scan_root)}</code></span>`);
  if (report.scan_timestamp) {
    let when = report.scan_timestamp;
    const d = new Date(report.scan_timestamp);
    if (!isNaN(d.getTime())) when = d.toLocaleString();
    bits.push(`<span class="meta-item">At <b>${esc(when)}</b></span>`);
  }
  if (report.tool_version) bits.push(`<span class="meta-item">ai-surface <b>v${esc(report.tool_version)}</b></span>`);
  if (report.schema_version) bits.push(`<span class="meta-item">schema <code>${esc(report.schema_version)}</code></span>`);
  if (Array.isArray(report.detectors_run) && report.detectors_run.length) {
    bits.push(`<span class="meta-item">Detectors <b>${report.detectors_run.length}</b></span>`);
  }
  $("scan-meta").innerHTML = bits.join("");
}

// ---- summary hero ----
function renderSummary(report) {
  const s = report.summary || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const total = s.total_findings != null ? s.total_findings : findings.length;
  const byCat = s.by_category || {};
  const bySev = s.by_severity || {};
  const assessed = Object.values(bySev).reduce((a, b) => a + (b || 0), 0);

  // stat cards
  const stats = [];
  stats.push(statCard(total, "Total Findings", "accent"));
  stats.push(statCard(Object.keys(byCat).length, "Categories"));
  // severity stat cards, only for severities present
  SEVERITY_ORDER.forEach((sev) => {
    if (bySev[sev]) stats.push(statCard(bySev[sev], sev, "has-sev sev-" + sev));
  });
  stats.push(statCard(assessed, "Assessed", "has-sev"));

  // category breakdown
  const catRows = orderedCategories(Object.keys(byCat)).map((c) => {
    const m = catMeta(c);
    return `<div class="cat-row">
      <span class="cat-icon">${m.icon}</span>
      <span class="cat-name">${esc(m.label)}</span>
      <span class="cat-count">${byCat[c]}</span>
    </div>`;
  }).join("");

  // severity legend (or discovery-only note)
  let sevHtml;
  if (assessed > 0) {
    sevHtml = `<div class="sev-legend">` + SEVERITY_ORDER.filter(sv => bySev[sv]).map((sv) =>
      `<span class="pill-count badge sev-pill ${sevClass(sv)}"><span class="n">${bySev[sv]}</span> ${sv}</span>`
    ).join("") + `</div>`;
  } else {
    sevHtml = `<p class="text-muted" style="font-size:0.88rem">No deep-dive findings carry a severity yet.
      Discovery is intentionally severity-free &mdash; absence of severity means
      <b>inventoried, not assessed</b>.</p>`;
  }

  $("summary").innerHTML = `
    <div class="stat-grid">${stats.join("")}</div>
    <div class="summary-cols">
      <div class="panel">
        <h3>Surface by Category</h3>
        <div class="cat-breakdown">${catRows || '<span class="text-muted">No findings.</span>'}</div>
      </div>
      <div class="panel">
        <h3>Severity (assessed surfaces)</h3>
        ${sevHtml}
      </div>
    </div>`;
}

function statCard(value, label, cls) {
  return `<div class="stat ${cls || ""}">
    <div class="stat-value">${esc(value)}</div>
    <div class="stat-label">${esc(label)}</div>
  </div>`;
}

function orderedCategories(cats) {
  const known = CATEGORY_ORDER.filter((c) => cats.includes(c));
  const rest = cats.filter((c) => !CATEGORY_ORDER.includes(c)).sort();
  return known.concat(rest);
}

// ---- top risks banner ----
function renderTopRisks(report) {
  const risks = (report.summary && report.summary.top_risks) || [];
  if (!risks.length) { $("top-risks").innerHTML = ""; return; }
  $("top-risks").innerHTML = `
    <div class="top-risks">
      <div class="tr-head">
        <span>⚠️</span><span>Top Risks</span>
        <span class="tr-count">${risks.length}</span>
      </div>
      <ul>${risks.map((r) => `<li><span class="marker">→</span><span>${esc(r)}</span></li>`).join("")}</ul>
    </div>`;
}

// ---- bridges (paid funnel) ----
function renderBridges(report) {
  // Prefer the de-duplicated bridges from the findings (these carry real URLs).
  const seen = new Map();
  (report.findings || []).forEach((f) => {
    (f.bridges || []).forEach((b) => {
      if (b && b.sku && !seen.has(b.sku)) seen.set(b.sku, b);
    });
  });
  const bridges = Array.from(seen.values());
  if (!bridges.length) { $("bridges").innerHTML = ""; return; }

  const cards = bridges.map((b) => {
    const meta = BRIDGE_META[b.sku] || { icon: "\u{1F517}", desc: "" };
    return `<div class="bridge-card">
      <span class="bridge-sku">${meta.icon} ${esc(b.sku)}</span>
      <span class="bridge-label">${esc(b.label || meta.desc || b.sku)}</span>
      ${meta.desc ? `<span class="text-muted" style="font-size:0.8rem">${esc(meta.desc)}</span>` : ""}
      <a class="bridge-cta" href="${esc(b.url || "#")}" target="_blank" rel="noopener">Open in APIsec →</a>
    </div>`;
  }).join("");

  $("bridges").innerHTML = `
    <div class="bridges">
      <div class="bridges-head">
        <h2>Validate at runtime</h2>
        <span class="sub">ai-surface finds the surface statically. These upgrade paths validate exploitability in the APIsec platform.</span>
      </div>
      <div class="bridge-grid">${cards}</div>
    </div>`;
}

// ---- findings grouped by category ----
function renderFindings(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  if (!findings.length) {
    $("findings").innerHTML = `<div class="card center-state">
      <div class="state-icon" style="background:var(--info-bg);color:var(--info-fg)">✓</div>
      <h2>No AI surface detected</h2>
      <p class="text-muted">ai-surface did not find any LLM SDKs, agents, MCP servers, gateways, infra, keys, or APIs in this scan root.</p>
    </div>`;
    return;
  }

  // group
  const groups = {};
  findings.forEach((f) => {
    const c = f.category || "unknown";
    (groups[c] = groups[c] || []).push(f);
  });

  const sections = orderedCategories(Object.keys(groups)).map((cat) => {
    const m = catMeta(cat);
    const items = groups[cat];
    // worst severity in this category (for the tally badge)
    const worst = SEVERITY_ORDER.find((sv) => items.some((f) => f.severity === sv));
    const tally = worst
      ? `<span class="badge ${sevClass(worst)}">${worst}</span>`
      : `<span class="badge b-neutral">inventory</span>`;
    return `<div class="cat-section">
      <div class="cat-header">
        <span class="cat-icon">${m.icon}</span>
        <span>
          <span class="cat-title">${esc(m.label)}</span>
          <span class="cat-sub"> &middot; ${esc(m.blurb)}</span>
        </span>
        <span class="cat-tally">
          ${tally}
          <span class="cat-count">${items.length}</span>
          <span class="chev">▼</span>
        </span>
      </div>
      <div class="cat-body">${items.map((f) => renderFinding(f, cat)).join("")}</div>
    </div>`;
  }).join("");

  $("findings").innerHTML = `<h2 class="section-title">Findings</h2>${sections}`;
}

function renderFinding(f, cat) {
  const sev = f.severity;
  const sevCls = sev ? "sev-" + sev : "";
  const meta = (f.evidence && f.evidence.metadata) || {};

  // --- head: name / api method+path / severity ---
  let nameHtml;
  if (cat === "api") {
    const method = (meta.method || "*").toString();
    const mcls = "m-" + method.toLowerCase().replace(/[^a-z]/g, "");
    nameHtml = `<span class="method-pill ${mcls}">${esc(method)}</span>
      <span class="api-path">${esc(meta.path || stripApiPrefix(f.surface))}</span>`;
  } else {
    nameHtml = `<span class="f-name">${esc(f.surface || humanize(cat))}</span>`;
  }
  const sevBadge = sev ? `<span class="badge sev-pill ${sevClass(sev)}">${esc(sev)}</span>` : "";

  // --- metadata chips (api gets the structured set + BOLA marker;
  //     other categories show any scalar metadata generically) ---
  let chips = "";
  const c = [];
  if (cat === "api") {
    if (meta.framework) c.push(chip("Framework", meta.framework));
    if (meta.auth) c.push(chip("Auth", meta.auth));
    if (meta.source_spec) c.push(chip("Spec", meta.source_spec));
    const bola = (f.risk_indicators || []).find((r) => /bola/i.test(r));
    if (bola) c.push(`<span class="chip" style="background:var(--med-bg);color:var(--med-fg)">⚠️ BOLA candidate</span>`);
  } else {
    // Generic, schema-agnostic: surface simple scalar metadata as chips
    // (e.g. llm-sdk "model", flags like non_literal_input). Arrays/objects
    // are skipped here because tools/permissions already render below.
    Object.keys(meta).forEach((k) => {
      const v = meta[k];
      if (v == null || typeof v === "object") return;
      if (typeof v === "boolean") { if (v) c.push(chip(humanize(k), "yes")); return; }
      c.push(chip(humanize(k), v));
    });
  }
  if (c.length) chips = `<div class="meta-chips">${c.join("")}</div>`;

  // --- evidence ---
  const ev = f.evidence || {};
  const lines = Array.isArray(ev.line_numbers) ? ev.line_numbers : [];
  const files = Array.isArray(ev.files) ? ev.files : [];
  const fileTags = files.map((file, i) => {
    const ln = lines[i] != null ? lines[i] : (files.length === 1 && lines.length ? lines.join(", ") : null);
    return `<span class="file-tag">${esc(file)}${ln != null ? `<span class="ln">:${esc(ln)}</span>` : ""}</span>`;
  }).join("");
  let evidenceHtml = "";
  if (files.length || ev.snippet) {
    evidenceHtml = `<div class="f-block">
      <div class="blk-label">Evidence</div>
      <div class="evidence">
        ${files.length ? `<div class="files">${fileTags}</div>` : ""}
        ${ev.snippet ? `<div class="snippet">${esc(ev.snippet)}</div>` : ""}
      </div>
    </div>`;
  }

  // --- permissions ---
  let permHtml = "";
  if (Array.isArray(f.permissions) && f.permissions.length) {
    permHtml = `<div class="f-block">
      <div class="blk-label">Permissions / Capabilities</div>
      <div class="tag-row">${f.permissions.map((p) => `<span class="tag">${esc(p)}</span>`).join("")}</div>
    </div>`;
  }

  // --- risk indicators (severity-free, plain English) ---
  let riskHtml = "";
  if (Array.isArray(f.risk_indicators) && f.risk_indicators.length) {
    riskHtml = `<div class="f-block">
      <div class="blk-label">Risk Indicators</div>
      <div class="tag-row">${f.risk_indicators.map((r) => `<span class="tag warn">${esc(r)}</span>`).join("")}</div>
    </div>`;
  }

  // --- audit (deep-dive layer; MCP today) ---
  const auditHtml = f.audit ? renderAudit(f.audit) : "";

  // --- per-finding bridges ---
  let bridgeHtml = "";
  if (Array.isArray(f.bridges) && f.bridges.length) {
    bridgeHtml = `<div class="finding-bridges">
      <span class="fb-label">Validate</span>
      ${f.bridges.map((b) => `<a class="inline-bridge" href="${esc(b.url || "#")}" target="_blank" rel="noopener">${esc(b.label || b.sku)} <span class="arrow">→</span></a>`).join("")}
    </div>`;
  }

  return `<div class="finding ${sevCls}">
    <div class="finding-head">
      ${nameHtml}<span class="spacer"></span>${sevBadge}
    </div>
    ${chips}
    ${evidenceHtml}
    ${permHtml}
    ${riskHtml}
    ${auditHtml}
    ${bridgeHtml}
  </div>`;
}

function chip(label, value) {
  return `<span class="chip"><b>${esc(label)}:</b> ${esc(value)}</span>`;
}
function stripApiPrefix(surface) {
  // "REST API: POST /path" -> "/path" fallback when metadata.path is absent
  const m = String(surface || "").match(/(\/\S+)/);
  return m ? m[1] : surface;
}

// ---- audit deep-dive ----
function renderAudit(audit) {
  const flags = Array.isArray(audit.risk_flags) ? audit.risk_flags : [];
  const secrets = Array.isArray(audit.secrets) ? audit.secrets : [];

  const trustLabel = audit.trust_label && audit.trust_label !== "unknown"
    ? `${esc(audit.trust_label)}${audit.trust_score != null ? ` (${esc(audit.trust_score)}/100)` : ""}`
    : "unverified source";

  const flagsHtml = flags.map((fl) => {
    const owasp = (fl.owasp || []).map(owaspTag).join("");
    return `<div class="risk-flag">
      <div class="rf-head">
        <span class="badge sev-pill ${sevClass(fl.severity)}">${esc(fl.severity || "info")}</span>
        <span class="rf-id">${esc(fl.flag || "")}</span>
        ${owasp}
      </div>
      ${fl.description ? `<div class="rf-desc">${esc(fl.description)}</div>` : ""}
      ${fl.remediation ? `<div class="rf-rem"><b>Fix:</b> ${esc(fl.remediation)}</div>` : ""}
    </div>`;
  }).join("");

  // secrets: NAME / TYPE / SEVERITY only — never any value
  let secretsHtml = "";
  if (secrets.length) {
    secretsHtml = `<div class="secrets-block">
      <div class="sb-head">\u{1F510} Secrets present <span class="no-value-note">&mdash; names &amp; types only, no values read</span></div>
      ${secrets.map((s) => `<div class="secret-row">
        <span class="badge sev-pill ${sevClass(s.severity)}">${esc(s.severity || "info")}</span>
        <span class="s-name">${esc(s.name || "(unnamed)")}</span>
        <span class="s-meta">${esc(s.secret_type || "secret")}${s.confidence ? ` &middot; ${esc(s.confidence)} confidence` : ""}</span>
        ${s.location ? `<span class="s-loc">${esc(s.location)}</span>` : ""}
      </div>`).join("")}
    </div>`;
  }

  if (!flags.length && !secrets.length) return "";

  return `<div class="audit-box">
    <div class="audit-head">
      <span>\u{1F50E} Deep-dive audit</span>
      <span class="trust">${esc(trustLabel)}</span>
    </div>
    <div class="audit-body">
      ${flagsHtml}
      ${secretsHtml}
    </div>
  </div>`;
}

function owaspTag(id) {
  const name = OWASP_LLM[id];
  return `<span class="owasp-tag"${name ? ` title="OWASP ${esc(id)}: ${esc(name)}"` : ""}>${esc(id)}</span>`;
}

// ---- non-fatal detector errors ----
function renderErrors(report) {
  const errs = Array.isArray(report.errors) ? report.errors : [];
  if (!errs.length) { $("errors").innerHTML = ""; return; }
  $("errors").innerHTML = `<div class="errors-box">
    <h3>⚠️ ${errs.length} detector ${errs.length === 1 ? "warning" : "warnings"} (non-fatal)</h3>
    <ul>${errs.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
  </div>`;
}
