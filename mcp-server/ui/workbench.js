// SPDX-License-Identifier: Apache-2.0
// Auditor Workbench — client-side SPA (vanilla ES module, no framework).
// Talks to /api/v1/* (FastAPI orchestrator). Air-gapped.

// ─── Session ────────────────────────────────────────────────────
const S = {
  token: sessionStorage.getItem("gov.token") || null,
  role: sessionStorage.getItem("gov.role") || null,
  clientId: sessionStorage.getItem("gov.clientId") || null,
  scopes: JSON.parse(sessionStorage.getItem("gov.scopes") || "[]"),
};
function setSession(t) {
  S.token = t.accessToken; S.role = t.role; S.scopes = t.scopes; S.clientId = t.clientId;
  sessionStorage.setItem("gov.token", t.accessToken);
  sessionStorage.setItem("gov.role", t.role);
  sessionStorage.setItem("gov.scopes", JSON.stringify(t.scopes));
  sessionStorage.setItem("gov.clientId", t.clientId);
}
function clearSession() { S.token = null; S.role = null; S.scopes = []; sessionStorage.clear(); }
function hasScope(s) { return S.scopes && S.scopes.includes(s); }

// ─── API client ─────────────────────────────────────────────────
async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (S.token && !opts.public) headers["Authorization"] = "Bearer " + S.token;
  const r = await fetch(path, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await r.text();
  let data; try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!r.ok) {
    const msg = data && data.detail ? (data.detail.message || JSON.stringify(data.detail)) : r.statusText;
    const err = new Error(msg); err.status = r.status; err.data = data;
    throw err;
  }
  return data;
}

// ─── DOM helpers ────────────────────────────────────────────────
const h = (tag, attrs = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k === "html") el.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (v === false || v == null) continue;
    else if (k === "checked" && typeof v === "boolean") el.checked = v;
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  return el;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (s, n = 10) => (s || "").length > n ? s.slice(0, n) + "…" : (s || "");
const fmtDate = (s) => s ? new Date(s).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "—";

// ─── Toasts ─────────────────────────────────────────────────────
const toaster = { el: null, ensure() { if (!this.el) { this.el = h("div", { class: "toasts" }); document.body.appendChild(this.el); } } };
function toast(msg, kind = "info", ms = 4000) {
  toaster.ensure();
  const t = h("div", { class: "toast " + kind }, msg);
  toaster.el.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

// ─── Sample demo payload (one-click demo) ───────────────────────
const DEMO_ARTIFACT_TEXT = {
  dpia: `Data Protection Impact Assessment — CV Screener v1.0

Section 1 — Systematic description of the processing operations
The purpose of processing is to rank candidate CVs for shortlisting in
recruitment. Nature of processing includes automated ranking of applicant
records. Scope of processing covers all applicants for open roles across EU
and India.

Section 2 — Necessity and proportionality of the processing
The processing is necessary and proportional to the legitimate interest of
the employer in efficient shortlisting.

Section 3 — Risks to the rights and freedoms of data subjects
Identified risks to rights and freedoms of data subjects include selection
bias, chilling effect on right to erasure, and risk of discrimination.

Section 4 — Measures envisaged (safeguards)
Measures envisaged (safeguards): technical and organisational measures
including audit logging, kill-switch, human oversight, mitigation measures
for identified bias, encryption at rest, and role-based access control.

Section 5 — DPO consultation
Consulted the DPO (Data Protection Officer) on 2025-11-05.

Retention period: 180 days.
Lawful basis: legitimate interest under GDPR Art. 6(1)(f).`,
  model_card: `Model Card — CV Screener v1.0

Intended use / deployment context: automated CV ranking to assist
recruiters in shortlisting job applicants.

Out-of-scope / prohibited uses: this model must NOT be used for fully
automated hiring decisions without human review. Foreseeable misuse
includes decisions made without oversight.

Training data — provenance and composition: dataset ds-cv-2025-q1
sourced from anonymised historical CVs. Provenance documented in the
dataset lineage record.

Evaluation / performance metrics: accuracy 0.83, F1-score 0.81 on the
held-out validation split; benchmark result exceeds internal baseline.

Known limitations: model may under-represent gap-year candidates and
non-linear career paths.

Bias / fairness considerations: demographic parity across gender was
tested; disparate impact ratio 0.94 exceeds the 0.8 threshold.

Human oversight recommendations: reviewer approval required for every
shortlist decision (human-in-the-loop).`,
  bias_test_output: `Bias Test Output — CV Screener v1.0

Sensitive attributes evaluated: gender, age band.
Disparate impact (DI) ratio, four-fifths rule:
  gender.F vs gender.M: 0.94 (PASS ≥ 0.8)
  age_band.25-34 vs age_band.45-54: 0.91 (PASS ≥ 0.8)

Demographic parity difference: 0.03.
Equal opportunity difference: 0.02.
Fairness threshold: 0.8. Result: PASSED.`,
  fairness_metrics_report: `Fairness Metrics Report — CV Screener Q1 2025

Per-group selection rates (positive rate):
  gender.F: 0.62 · gender.M: 0.66 · gap 0.04
  age_band.25-34: 0.65 · age_band.35-44: 0.63 · age_band.45-54: 0.59

Equal-opportunity (TPR difference): 0.02 across gender.
Mitigation strategy: reweighting during training + threshold calibration.`,
  robustness_test_log: `Robustness Test Log — CV Screener Q1 2025

Prompt-injection resistance test result: 0.97 (300/310 attempts blocked).
Jailbreak / evasion test coverage: prompt corpus v3 executed; bypass rate 0.02.
Adversarial input resistance metric: adversarial attack success rate 0.03.
Rate-limiting / throttling controls in place: 100 req/min per user.`,
  adversarial_test_report: `Red-team Adversarial Test Report

Attack corpus and pass rate: 500 adversarial payloads, resistance rate 0.94.
Red-team methodology: STRIDE-based threat model; two-week engagement.`,
  security_audit: `Security Audit Report — Q1 2025

Vulnerability findings enumerated: 3 low-severity findings (CVE-2025-11XX),
1 medium (log leakage) — all remediated.
Access control review: RBAC enforced, least privilege, quarterly rotation.`,
  explainability_report: `Explainability Report — SHAP

Explanation method declared: SHAP with TreeExplainer.
User-facing explanation format: human-readable top-3 feature attributions
shown to reviewers per decision.
Global vs local explanation coverage: global feature importance summary
plus per-decision local explanations.`,
  decision_log_sample: `timestamp,trace_id,input_hash,reviewer,decision
2025-11-01T09:00:12Z,tr-1001,ih-a,rev-01,shortlisted
2025-11-01T09:00:18Z,tr-1002,ih-b,rev-01,rejected
2025-11-01T09:00:35Z,tr-1003,ih-c,rev-02,shortlisted`,
  oversight_procedure: `Human Oversight Procedure — CV Screener

Human-in-the-loop step described: every shortlist decision is reviewed by
a compliance officer before being sent to the candidate.
Override / stop capability: reviewers may override or halt the pipeline;
kill-switch runbook available.
Named oversight roles: reviewer, compliance officer, data steward.`,
  kill_switch_evidence: `Kill-switch Runbook

Stop trigger / runbook step: on drift threshold breach or incident, run
'ops halt cvscreener-01'. Time to disable: 90 seconds.
Response / rollback SLA: 5 minutes to disable, 30 minutes to rollback.`,
  data_flow_map: `Data Flow Map — CV Screener

Data sources: HR ATS (upstream), applicant portal.
Cross-border transfer path: EU → India via SCC.`,
  ropa_record: `ROPA Record — Talent Platform CV Screener

Purposes of processing: shortlisting job applicants for recruiters.
Categories of data subjects: job applicants (EU and India).
Categories of personal data: contact info, employment history.
Retention periods: 180 days post-decision.`,
  dataset_lineage: `Dataset Lineage — ds-cv-2025-q1

Source: HR ATS export (2025-01 to 2025-03), version 1.
Provenance: internal HR system, anonymised.
Preprocessing / cleaning: deduplication, PII redaction, tokenization.
Split: 70% train / 15% validation / 15% test.`,
  risk_assessment: `Risk Assessment — CV Screener v1.0

Risk identification: risk register maintained; threats include bias, drift,
data poisoning, unauthorised access.
Risk mitigation: control library applied, mitigation actions tracked in
Jira; risk treatment plan reviewed quarterly.`,
  consent_ux_evidence: `Consent UX Evidence

Consent choice presented at intake: "I consent to automated screening" (opt-in checkbox).
Withdraw / opt-out path: candidates can withdraw consent via the applicant portal at any time.`,
  conformity_declaration: `EU AI Act Conformity Declaration (draft)

Signed by the responsible officer at Talent Platform.
Referenced harmonised standards: ISO/IEC 42001, IEC 62443.`,
  monitoring_dashboard: `Post-Market Monitoring Dashboard

Drift metric surfaced: population stability index (PSI) tracked per week.
Fairness monitoring metric: disparate impact monitored per weekly cohort.`,
  incident_report: `Incident Report — 2025-Q1 anomaly

Incident timeline: detected at 2025-02-14 09:12 UTC; contained by 09:45.
Root cause: upstream schema change → mis-encoded feature.
Corrective action: remediation deployed; automated schema guard added.`,
};

const DEMO = {
  modelId: `demo-cvscreener-${Date.now().toString(36)}`,
  modelVersion: "1.0.0",
  ownerTeam: "talent-platform",
  deploymentContext: { sector: "employment", regions: ["EU", "IN"], autonomyLevel: "supervised", description: "AI-assisted CV shortlisting for a European retail employer." },
  processingActivities: [{ name: "cv-ranking", purpose: "Rank candidate CVs for shortlisting", dataCategories: ["contact", "employment_history"], dataSubjects: ["job_applicants"], crossBorder: true }],
  datasets: [{ datasetId: "ds-cv-2025-q1", name: "CV corpus 2025 Q1", version: "1", containsPersonalData: true }],
  evidenceArtifacts: [
    { name: "CV Screener Model Card v1.0", type: "model_card", uri: "internal://docs/cvscreener/model-card-v1.md", tags: ["public"], contentSnippet: DEMO_ARTIFACT_TEXT.model_card },
    { name: "ROPA Registry — Talent Platform", type: "ropa_record", uri: "internal://records/ropa/talent.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.ropa_record },
    { name: "Risk Assessment — CV Screener", type: "risk_assessment", uri: "internal://risk/cvscreener-2025.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.risk_assessment },
    { name: "DPIA — CV Screener v1.0", type: "dpia", uri: "internal://dpia/cvscreener-dpia-v1.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.dpia },
    { name: "Data Flow Map — Talent Platform", type: "data_flow_map", uri: "internal://dataflow/cvscreener-2025.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.data_flow_map },
    { name: "Consent UX Screenshots", type: "consent_ux_evidence", uri: "internal://ux/consent-flow-2025.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.consent_ux_evidence },
    { name: "Bias Test Output — Q1 2025", type: "bias_test_output", uri: "internal://tests/bias/cvscreener-2025-q1.json", contentSnippet: DEMO_ARTIFACT_TEXT.bias_test_output },
    { name: "Fairness Metrics Report — Q1 2025", type: "fairness_metrics_report", uri: "internal://tests/fairness/cvscreener-2025-q1.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.fairness_metrics_report },
    { name: "Dataset Lineage — ds-cv-2025-q1", type: "dataset_lineage", uri: "internal://lineage/ds-cv-2025.json", contentSnippet: DEMO_ARTIFACT_TEXT.dataset_lineage },
    { name: "Red-team Adversarial Report", type: "adversarial_test_report", uri: "internal://tests/adversarial/cvscreener-red-team.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.adversarial_test_report },
    { name: "Robustness Test Log — Q1", type: "robustness_test_log", uri: "internal://logs/robustness/cvscreener-2025-q1.log", contentSnippet: DEMO_ARTIFACT_TEXT.robustness_test_log },
    { name: "Security Audit — Q1 2025", type: "security_audit", uri: "internal://security/audit-2025-q1.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.security_audit },
    { name: "SHAP Explainability Report", type: "explainability_report", uri: "internal://xai/shap-report-2025.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.explainability_report },
    { name: "Decision Log Sample — Q1 2025", type: "decision_log_sample", uri: "internal://logs/decisions/q1-2025.csv", contentSnippet: DEMO_ARTIFACT_TEXT.decision_log_sample },
    { name: "Human Oversight Procedure", type: "oversight_procedure", uri: "internal://procedures/oversight-v1.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.oversight_procedure },
    { name: "Kill-switch Runbook", type: "kill_switch_evidence", uri: "internal://ops/killswitch-runbook.md", contentSnippet: DEMO_ARTIFACT_TEXT.kill_switch_evidence },
    { name: "Conformity Declaration (draft)", type: "conformity_declaration", uri: "internal://legal/conformity-declaration-v1.pdf", contentSnippet: DEMO_ARTIFACT_TEXT.conformity_declaration },
    { name: "Monitoring Dashboard Screenshots", type: "monitoring_dashboard", uri: "internal://dashboards/cvscreener-monitoring.png", contentSnippet: DEMO_ARTIFACT_TEXT.monitoring_dashboard },
  ],
};

const DEMO_PHASE_INPUTS = {
  risk: { riskInputs: { annexIIICategories: ["employment"], interactsWithHumans: false } },
  data_protection: {
    dataProtection: {
      processesPersonalData: true, lawfulBasis: "legitimate_interest",
      specialCategoryBasis: "none",
      dpiaConducted: true, dpoAppointed: true, consentMechanism: true,
      crossBorderTransfers: [], retentionPeriodDays: 180,
      dataMinimisationApplied: true, privacyByDesign: true,
    },
  },
  fairness: {
    sensitiveFeatures: ["gender", "age_band"],
    fairnessThreshold: 0.8,
    datasetSample: [
      { attributes: { gender: "F", age_band: "25-34" }, outcome: 1, label: 1 },
      { attributes: { gender: "F", age_band: "35-44" }, outcome: 1, label: 1 },
      { attributes: { gender: "F", age_band: "45-54" }, outcome: 1, label: 1 },
      { attributes: { gender: "F", age_band: "25-34" }, outcome: 0, label: 0 },
      { attributes: { gender: "F", age_band: "35-44" }, outcome: 0, label: 0 },
      { attributes: { gender: "F", age_band: "45-54" }, outcome: 0, label: 0 },
      { attributes: { gender: "M", age_band: "25-34" }, outcome: 1, label: 1 },
      { attributes: { gender: "M", age_band: "35-44" }, outcome: 1, label: 1 },
      { attributes: { gender: "M", age_band: "45-54" }, outcome: 1, label: 1 },
      { attributes: { gender: "M", age_band: "25-34" }, outcome: 0, label: 0 },
      { attributes: { gender: "M", age_band: "35-44" }, outcome: 0, label: 0 },
      { attributes: { gender: "M", age_band: "45-54" }, outcome: 0, label: 0 },
    ],
  },
  robustness: {
    testSuites: ["prompt_injection", "jailbreak", "data_extraction", "evasion"],
    securityControls: {
      inputSanitization: true, outputFiltering: true, rateLimiting: true,
      adversarialTraining: true, anomalyMonitoring: true, accessControl: true,
    },
  },
  explainability: {
    oversight: { hasHumanInTheLoop: true, hasKillSwitch: true, overrideProcedureDocumented: true, oversightRoles: ["reviewer", "compliance-officer"] },
    explainability: { method: "shap", userFacingExplanations: true, decisionLogsRetained: true, logRetentionDays: 365 },
  },
  certification: { issuer: { name: "AI Governance Authority — Sandbox", contact: "compliance@example.internal" }, validityDays: 365 },
  monitoring: { monitors: { driftThreshold: 0.2, fairnessDriftThreshold: 0.1 } },
};

// ─── Roles ──────────────────────────────────────────────────────
const ROLES = [
  { clientId: "governance-admin", secret: "govern-admin-secret-dev", name: "Governance Admin", desc: "Full pipeline access — intake through certification, monitoring, reaudit.", scopesLbl: "all scopes" },
  { clientId: "intake-officer", secret: "intake-officer-secret-dev", name: "Intake Officer", desc: "Register models and scope regulatory framework mapping.", scopesLbl: "phase:intake · phase:scope · runs:read" },
  { clientId: "audit-engineer", secret: "audit-engineer-secret-dev", name: "Audit Engineer", desc: "Execute the risk, privacy, fairness, robustness and explainability engines.", scopesLbl: "phase:risk|privacy|fairness|robustness|explainability · runs:read" },
  { clientId: "certification-officer", secret: "certification-officer-secret-dev", name: "Certification Officer", desc: "Assemble VC 2.0 certificates, configure monitoring, trigger reaudits.", scopesLbl: "phase:certify · phase:monitor · reaudit:trigger · runs:read · certs:read" },
];

// ─── Router ─────────────────────────────────────────────────────
const routes = {};
function route(pattern, handler) { routes[pattern] = handler; }

async function router() {
  const hash = location.hash.replace(/^#\/?/, "") || "";
  const app = document.getElementById("app");
  app.innerHTML = "";

  if (!S.token && hash !== "login" && !hash.startsWith("verify")) {
    location.hash = "#/login"; return;
  }

  // find matching route
  for (const [pat, fn] of Object.entries(routes)) {
    const parts = pat.split("/");
    const bits = hash.split("/");
    if (parts.length !== bits.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < parts.length; i++) {
      if (parts[i].startsWith(":")) params[parts[i].slice(1)] = decodeURIComponent(bits[i]);
      else if (parts[i] !== bits[i]) { ok = false; break; }
    }
    if (ok) {
      try { await fn(app, params); } catch (e) { console.error(e); renderError(app, e); }
      return;
    }
  }
  location.hash = "#/dashboard";
}
window.addEventListener("hashchange", router);
window.addEventListener("load", router);

function renderError(app, e) {
  app.innerHTML = "";
  app.appendChild(renderShell(h("div", { class: "main" },
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Error"), h("div", { class: "sub" }, e.message))),
    h("pre", { class: "json-view" }, JSON.stringify(e.data || e.message, null, 2)),
  )));
}

// ─── Shell (sidebar + main) ─────────────────────────────────────
function renderShell(body) {
  const nav = [
    { href: "#/dashboard", label: "Dashboard", k: "D" },
    { href: "#/audit/new", label: "New Audit", k: "N" },
    { href: "#/runs", label: "Audit Runs", k: "R" },
    { href: "#/certificates", label: "Certificates", k: "C" },
    { href: "#/verify", label: "Verify Certificate", k: "V" },
    { href: "#/events", label: "Event Ledger", k: "E" },
    { href: "#/reaudit", label: "Reaudit", k: "A" },
    { href: "#/mcp", label: "MCP / API", k: "M" },
  ];
  const active = location.hash.replace(/^#\/?/, "").split("/")[0];
  const shell = h("div", { class: "shell" },
    h("aside", { class: "sidebar" },
      h("div", { class: "brand" },
        h("div", { class: "brand-mark" }, "◉"),
        h("div", null,
          h("div", { class: "brand-title" }, "AI Governance"),
          h("div", { class: "brand-sub" }, "AUDITOR WORKBENCH"),
        ),
      ),
      h("nav", null,
        h("div", { class: "nav-group" }, "Compliance"),
        ...nav.map(n => {
          const isActive = active && n.href.includes(active);
          return h("a", { href: n.href, class: "nav-item" + (isActive ? " active" : "") },
            h("span", null, n.label),
            h("span", { class: "k" }, n.k),
          );
        }),
      ),
      S.token ? h("div", { class: "identity" },
        h("div", { class: "u-role" }, S.role || "unknown"),
        h("div", { class: "u-name" }, "@" + (S.clientId || "?")),
        h("a", { class: "u-logout", onclick: () => { clearSession(); location.hash = "#/login"; } }, "Sign out"),
      ) : h("div", { class: "identity" },
        h("div", { class: "u-role" }, "guest"),
        h("div", { class: "u-name" }, "read-only mode"),
        h("a", { class: "u-logout", style: "color: var(--acc)", onclick: () => { location.hash = "#/login"; } }, "Sign in →"),
      ),
    ),
    body,
  );
  return shell;
}

// ─── LOGIN ──────────────────────────────────────────────────────
route("login", async (app) => {
  const err = h("div", { class: "err" });
  async function auth(clientId, secret) {
    err.textContent = "";
    try {
      const t = await api("/api/v1/auth/token", { method: "POST", public: true, body: { clientId, clientSecret: secret } });
      setSession({ ...t, clientId });
      toast(`Signed in as ${t.role}`, "success");
      location.hash = "#/dashboard";
    } catch (e) { err.textContent = e.message; }
  }
  const custom = { id: h("input", { placeholder: "clientId", value: "governance-admin" }), sec: h("input", { placeholder: "clientSecret", type: "password" }) };
  app.appendChild(h("div", { class: "login-wrap" },
    h("div", { class: "login-card" },
      h("div", { class: "brand-mark" }, "◉"),
      h("h1", null, "Auditor Workbench"),
      h("div", { class: "sub" },
        "On-premise AI compliance orchestration. Sign in with a service account — a human auditor drives the workbench, or an AI agent drives the identical pipeline via the MCP endpoint. ",
        "All 9 phases produce article-level evidence citations.",
      ),
      ...ROLES.map(r => h("button", { class: "role-btn", onclick: () => auth(r.clientId, r.secret) },
        h("div", { class: "role-name" }, r.name),
        h("div", { class: "role-desc" }, r.desc),
        h("div", { class: "role-scopes" }, r.scopesLbl),
      )),
      h("div", { class: "divider" }, h("span", null, "Or bring your own")),
      h("div", { class: "custom-cred" },
        custom.id, custom.sec,
        h("button", { class: "btn primary", onclick: () => auth(custom.id.value, custom.sec.value) }, "Sign in"),
        err,
      ),
    ),
  ));
});

// ─── DASHBOARD ──────────────────────────────────────────────────
route("dashboard", async (app) => {
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null,
        h("h1", null, "Dashboard"),
        h("div", { class: "sub" }, "Live infrastructure health, recent audit runs, active certificates. Both human auditors and AI agents (via MCP) produce identical evidence entries."),
      ),
      h("div", { class: "f-r" },
        h("a", { class: "btn primary", href: "#/audit/new" }, "＋ New Audit"),
      ),
    ),
    h("div", { id: "dash-metrics", class: "grid cols-4" }, h("div", { class: "card" }, "Loading…")),
    h("div", { id: "dash-runs", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Recent Audit Runs")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
    h("div", { id: "dash-certs", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Recent Certificates")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
  );
  app.appendChild(renderShell(body));

  const [health, runs, certs] = await Promise.all([
    api("/api/v1/health", { public: true }).catch(() => null),
    hasScope("runs:read") ? api("/api/v1/runs?limit=10").catch(() => ({ runs: [] })) : { runs: [] },
    hasScope("certs:read") ? api("/api/v1/certificates?limit=10").catch(() => ({ certificates: [] })) : { certificates: [] },
  ]);

  const svc = health?.services || { postgres: "?", neo4j: "?", redis: "?", certSigner: "?" };
  document.getElementById("dash-metrics").replaceWith(h("div", { class: "grid cols-4" },
    h("div", { class: "card" }, h("h3", null, "Overall"), h("div", { class: "metric" }, health?.status === "ok" ? h("span", { class: "pill ok" }, "Operational") : h("span", { class: "pill warn" }, health?.status || "?")), h("div", { class: "metric-sub" }, "System-wide readiness")),
    h("div", { class: "card" }, h("h3", null, "PostgreSQL"), h("div", { class: "metric" }, h("span", { class: "pill " + svc.postgres }, svc.postgres)), h("div", { class: "metric-sub" }, "Evidence store")),
    h("div", { class: "card" }, h("h3", null, "Neo4j Graph"), h("div", { class: "metric" }, h("span", { class: "pill " + svc.neo4j }, svc.neo4j)), h("div", { class: "metric-sub" }, "Lineage graph")),
    h("div", { class: "card" }, h("h3", null, "Redis Fabric"), h("div", { class: "metric" }, h("span", { class: "pill " + svc.redis }, svc.redis)), h("div", { class: "metric-sub" }, "Event streams")),
  ));

  const runsEl = document.getElementById("dash-runs").querySelector(".section-body");
  runsEl.innerHTML = "";
  runsEl.appendChild(runs.runs?.length ? renderRunsTable(runs.runs.slice(0, 10)) : h("div", { class: "empty" }, "No audit runs yet. Start with New Audit."));

  const certsEl = document.getElementById("dash-certs").querySelector(".section-body");
  certsEl.innerHTML = "";
  certsEl.appendChild(certs.certificates?.length ? renderCertsTable(certs.certificates.slice(0, 10)) : h("div", { class: "empty" }, "No certificates issued yet."));
});

function renderRunsTable(rows) {
  return h("table", null,
    h("thead", null, h("tr", null, ...["Run", "Model", "Version", "Status", "Started", ""].map(t => h("th", null, t)))),
    h("tbody", null, ...rows.map(r => h("tr", { class: "clickable", onclick: () => location.hash = `#/runs/${r.runId}` },
      h("td", null, h("code", null, short(r.runId, 12))),
      h("td", null, r.modelId),
      h("td", null, r.modelVersion),
      h("td", null, h("span", { class: "pill " + r.status }, r.status.replace("_", " "))),
      h("td", null, fmtDate(r.createdAt)),
      h("td", null, h("a", { class: "btn sm ghost", href: `#/runs/${r.runId}` }, "View →")),
    ))),
  );
}

function renderCertsTable(rows) {
  return h("table", null,
    h("thead", null, h("tr", null, ...["Certificate", "Model", "Status", "Issued", "Expires", ""].map(t => h("th", null, t)))),
    h("tbody", null, ...rows.map(c => h("tr", { class: "clickable", onclick: () => location.hash = `#/certificates/${encodeURIComponent(c.certificateId)}` },
      h("td", null, h("code", null, short(c.certificateId, 22))),
      h("td", null, c.modelId),
      h("td", null, h("span", { class: "pill " + c.status }, c.status)),
      h("td", null, fmtDate(c.issuedAt)),
      h("td", null, fmtDate(c.expiresAt)),
      h("td", null, h("a", { class: "btn sm ghost", href: `#/certificates/${encodeURIComponent(c.certificateId)}` }, "Open →")),
    ))),
  );
}

// ─── RUNS list ──────────────────────────────────────────────────
route("runs", async (app) => {
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null,
        h("h1", null, "Audit Runs"),
        h("div", { class: "sub" }, "Every run captures the 9-phase evidence chain with per-article citations back to the source artifacts."),
      ),
      h("a", { class: "btn primary", href: "#/audit/new" }, "＋ New Audit"),
    ),
    h("div", { id: "runs-tbl", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "All Runs")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
  );
  app.appendChild(renderShell(body));
  const data = await api("/api/v1/runs?limit=100");
  const el = document.getElementById("runs-tbl").querySelector(".section-body");
  el.innerHTML = "";
  el.appendChild(data.runs.length ? renderRunsTable(data.runs) : h("div", { class: "empty" }, "No runs yet."));
});

// ─── CERTIFICATES list ─────────────────────────────────────────
route("certificates", async (app) => {
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Certificates"), h("div", { class: "sub" }, "Signed W3C Verifiable Credentials 2.0 issued by the certification phase.")),
      h("a", { class: "btn", href: "#/verify" }, "Verify a certificate"),
    ),
    h("div", { id: "certs-tbl", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "All Certificates")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
  );
  app.appendChild(renderShell(body));
  if (!hasScope("certs:read")) {
    document.getElementById("certs-tbl").querySelector(".section-body").innerHTML = "";
    document.getElementById("certs-tbl").querySelector(".section-body").appendChild(h("div", { class: "empty" }, "Your role does not have certs:read scope. Sign in as Certification Officer or Governance Admin."));
    return;
  }
  const data = await api("/api/v1/certificates?limit=100");
  const el = document.getElementById("certs-tbl").querySelector(".section-body");
  el.innerHTML = "";
  el.appendChild(data.certificates.length ? renderCertsTable(data.certificates) : h("div", { class: "empty" }, "No certificates yet."));
});

// ─── VERIFY CERT (public) ──────────────────────────────────────
route("verify", async (app) => {
  const inp = h("input", { placeholder: "urn:uuid:… certificate id", style: "width: 100%; padding: 10px 12px; background: var(--bg-elev); border: 1px solid var(--line); border-radius: 6px; color: var(--ink); font-family: var(--mono);" });
  const out = h("div", null);
  async function run() {
    out.innerHTML = "";
    if (!inp.value.trim()) return;
    try {
      const [v, c] = await Promise.all([
        api(`/api/v1/certificates/${encodeURIComponent(inp.value.trim())}/verify`, { public: true }),
        api(`/api/v1/certificates/${encodeURIComponent(inp.value.trim())}`, { public: true }).catch(() => null),
      ]);
      out.appendChild(renderVerifyResult(v, c));
    } catch (e) {
      out.appendChild(h("div", { class: "err" }, "Verification failed: " + e.message));
    }
  }
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Verify Certificate"), h("div", { class: "sub" }, "Public, offline Ed25519 (eddsa-jcs-2022) signature verification against the on-premise DID. No network egress.")),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Certificate ID")),
      h("div", { style: "padding: 20px;" },
        h("div", { class: "field" }, inp, h("div", { class: "hint" }, "Paste the certificateId from any issued credential (urn:uuid:…).")),
        h("button", { class: "btn primary", onclick: run }, "Verify"),
      ),
    ),
    out,
  );
  app.appendChild(renderShell(body));
});

function renderVerifyResult(v, c) {
  const checks = v.checks || {};
  const rows = [
    ["Signature (Ed25519 · eddsa-jcs-2022)", checks.signatureValid],
    ["Schema (W3C VC 2.0 + governance context)", checks.schemaValid],
    ["Not expired", checks.notExpired],
    ["Not revoked", checks.notRevoked],
  ];
  return h("div", null,
    h("div", { class: "cert-header" },
      h("div", { class: "cert-title" }, v.verified ? "✓ Certificate is valid" : "✗ Certificate FAILED verification"),
      h("div", { class: "cert-id" }, v.certificateId),
      h("div", { class: "cert-meta" },
        h("div", null, h("div", { class: "cm-k" }, "Overall"), h("div", { class: "cm-v acc" }, v.verified ? "verified" : "invalid")),
        h("div", null, h("div", { class: "cm-k" }, "Status"), h("div", { class: "cm-v" }, v.status)),
        h("div", null, h("div", { class: "cm-k" }, "Anchor hash"), h("div", { class: "cm-v" }, short(v.anchorHash, 20))),
        h("div", null, h("div", { class: "cm-k" }, "Method"), h("div", { class: "cm-v" }, short(c?.verification_method || c?.verificationMethod || "did:key:…", 24))),
      ),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Verification Checks")),
      h("div", { style: "padding: 14px 20px;" },
        ...rows.map(([label, ok]) => h("div", { class: "verify-row" },
          h("span", { style: `color: var(--${ok ? "acc" : "red"})` }, ok ? "✓" : "✗"),
          h("span", null, label),
          h("span", { class: "pill " + (ok ? "ok" : "fail") }, ok ? "PASS" : "FAIL"),
        )),
      ),
    ),
    c ? h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "W3C Verifiable Credential")),
      h("div", { style: "padding: 14px 20px;" }, h("pre", { class: "json-view" }, JSON.stringify(c.vc_payload || c, null, 2))),
    ) : null,
  );
}

// ─── EVENTS ─────────────────────────────────────────────────────
route("events", async (app) => {
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Event Ledger"), h("div", { class: "sub" }, "Redis streams — phase events (webhook fabric) and the dead-letter queue after 3 delivery attempts.")),
      h("button", { class: "btn", onclick: async () => { try { await api("/api/v1/events/test-dead-letter", { method: "POST" }); toast("Poison event published — will land in DLQ", "info"); setTimeout(router, 1500); } catch (e) { toast(e.message, "error"); } } }, "Inject test DLQ event"),
    ),
    h("div", { id: "ev-recent", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Recent Events (delivered)")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
    h("div", { id: "ev-dlq", class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Dead-Letter Queue")), h("div", { class: "section-body" }, h("div", { class: "empty" }, "Loading…"))),
  );
  app.appendChild(renderShell(body));
  const [rec, dlq] = await Promise.all([
    api("/api/v1/events/recent"),
    api("/api/v1/events/dead-letter"),
  ]);
  function evTable(rows) {
    if (!rows.length) return h("div", { class: "empty" }, "No events.");
    return h("table", null,
      h("thead", null, h("tr", null, ...["Event", "Phase", "Run", "Status", "Attempts", "At"].map(t => h("th", null, t)))),
      h("tbody", null, ...rows.map(e => h("tr", null,
        h("td", null, h("code", null, e.event_type || e.type || "?")),
        h("td", null, e.phase_key || "—"),
        h("td", null, e.run_id ? h("a", { href: `#/runs/${e.run_id}` }, h("code", null, short(e.run_id, 8))) : "—"),
        h("td", null, h("span", { class: "pill " + (e.status || "info") }, e.status || "?")),
        h("td", null, h("code", null, e.attempts ?? "—")),
        h("td", null, fmtDate(e.created_at)),
      ))),
    );
  }
  const r1 = document.getElementById("ev-recent").querySelector(".section-body"); r1.innerHTML = ""; r1.appendChild(evTable(rec.events || []));
  const r2 = document.getElementById("ev-dlq").querySelector(".section-body"); r2.innerHTML = ""; r2.appendChild(evTable(dlq.ledger || []));
});

// ─── MCP / API reference ────────────────────────────────────────
route("mcp", async (app) => {
  const cmds = [
    { t: "Get a JWT (client credentials)", c: `curl -X POST /api/v1/auth/token -H 'Content-Type: application/json' \\\n  -d '{"clientId":"governance-admin","clientSecret":"govern-admin-secret-dev"}'` },
    { t: "List runs", c: `curl /api/v1/runs -H "Authorization: Bearer $TOKEN"` },
    { t: "Get run detail (with citations)", c: `curl /api/v1/runs/<runId> -H "Authorization: Bearer $TOKEN"` },
    { t: "List artifacts for a run", c: `curl /api/v1/runs/<runId>/artifacts -H "Authorization: Bearer $TOKEN"` },
    { t: "Verify a certificate (public, offline)", c: `curl /api/v1/certificates/<certId>/verify` },
    { t: "Connect an MCP client (Streamable HTTP)", c: `POST /mcp    # tools + resources + prompts` },
  ];
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "MCP / API"), h("div", { class: "sub" }, "The same 9-phase pipeline is exposed over the Model Context Protocol (11 governance tools) and over REST. An AI agent connected via MCP produces identical evidence rows and certificate artifacts as the human workbench.")),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Endpoints")),
      h("div", { style: "padding: 14px 20px;" },
        ...cmds.map(cmd => h("div", { style: "margin-bottom: 16px;" },
          h("div", { style: "font-size: 12px; color: var(--ink-dim); margin-bottom: 6px;" }, cmd.t),
          h("pre", { class: "json-view" }, cmd.c),
        )),
      ),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Governance MCP Tools")),
      h("div", { style: "padding: 14px 20px; display: flex; flex-wrap: wrap; gap: 6px;" },
        ...["intake_register", "map_regulatory_scope", "classify_risk", "check_data_protection", "evaluate_fairness", "test_robustness", "verify_explainability", "assemble_certification", "configure_monitoring", "trigger_reaudit", "get_audit_run"].map(t => h("span", { class: "tag" }, t)),
      ),
    ),
  );
  app.appendChild(renderShell(body));
});

// ─── REAUDIT ────────────────────────────────────────────────────
route("reaudit", async (app) => {
  const modelIn = h("input", { placeholder: "modelId to reaudit" });
  const typeSel = h("select", null, ...["model_version_change", "dataset_revision", "policy_update", "critical_incident", "drift_threshold_breach"].map(t => h("option", { value: t }, t)));
  const detail = h("input", { placeholder: "Trigger detail (free-text summary)" });
  const out = h("div", { style: "margin-top: 16px;" });
  async function run() {
    if (!modelIn.value.trim()) { toast("Enter a modelId first", "error"); return; }
    if (!hasScope("reaudit:trigger")) { toast("Your role lacks reaudit:trigger", "error"); return; }
    out.innerHTML = "";
    try {
      const res = await api("/api/v1/reaudit", { method: "POST", body: {
        modelId: modelIn.value.trim(),
        trigger: { type: typeSel.value, detail: detail.value || `${typeSel.value} via workbench` },
      } });
      out.appendChild(h("div", { class: "phase-result passed" },
        h("div", { class: "r-head" }, h("span", { class: "r-title" }, "Reaudit executed"),
          h("span", { class: "r-hash" }, res.reauditRunId)),
        h("pre", { class: "json-view" }, JSON.stringify(res, null, 2)),
        h("a", { class: "btn sm primary", href: `#/runs/${res.reauditRunId}`, style: "margin-top: 12px;" }, "Open reaudit run →"),
      ));
      toast("Reaudit completed", "success");
    } catch (e) { toast(e.message, "error"); out.appendChild(h("pre", { class: "json-view" }, JSON.stringify(e.data || e.message, null, 2))); }
  }
  const body = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Reaudit"), h("div", { class: "sub" }, "Impact-scoped re-run: only phases affected by the trigger are re-executed; unaffected evidence is carried forward with a signed link to the original run.")),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Trigger a reaudit")),
      h("div", { style: "padding: 22px;" },
        h("div", { class: "field-row" },
          h("div", { class: "field" }, h("label", null, "Model ID ", h("span", { class: "req" }, "*")), modelIn),
          h("div", { class: "field" }, h("label", null, "Trigger type"), typeSel),
        ),
        h("div", { class: "field" }, h("label", null, "Detail"), detail),
        h("button", { class: "btn primary", onclick: run }, "Trigger reaudit"),
        out,
      ),
    ),
  );
  app.appendChild(renderShell(body));
});

// ─── AUDIT WIZARD ───────────────────────────────────────────────
const PHASES = [
  { key: "intake", label: "1 · Intake" },
  { key: "scope", label: "2 · Scope" },
  { key: "risk", label: "3 · Risk" },
  { key: "data_protection", label: "4 · Data Protection" },
  { key: "fairness", label: "5 · Fairness" },
  { key: "robustness", label: "6 · Robustness" },
  { key: "explainability", label: "7 · Explainability" },
  { key: "certification", label: "8 · Certification" },
  { key: "monitoring", label: "9 · Monitoring" },
];

route("audit/new", async (app) => {
  await renderWizard(app, null);
});

async function renderWizard(app, existingRunId) {
  const state = {
    runId: existingRunId,
    current: 0,
    intake: JSON.parse(JSON.stringify(DEMO)),   // pre-fill with demo
    phaseInputs: JSON.parse(JSON.stringify(DEMO_PHASE_INPUTS)),
    results: {},                                 // phaseKey → response
    blocked: false,
  };

  function setPhaseStatus(idx, status) {
    // updates step-list class
    const item = document.querySelector(`.step[data-idx="${idx}"]`);
    if (!item) return;
    item.classList.remove("done", "blocked");
    if (status === "passed") item.classList.add("done");
    if (status === "blocked") item.classList.add("blocked");
  }

  function stepList() {
    return h("div", { class: "step-list" },
      ...PHASES.map((p, i) => h("div", {
        class: "step" + (i === state.current ? " active" : "") + (state.results[p.key]?.status === "passed" ? " done" : "") + (state.results[p.key]?.status === "blocked" ? " blocked" : ""),
        "data-idx": i,
        onclick: () => { if (state.results[p.key] || i === state.current) { state.current = i; rerender(); } },
      },
        h("div", { class: "step-num" }, state.results[p.key]?.status === "passed" ? "✓" : state.results[p.key]?.status === "blocked" ? "!" : String(i + 1)),
        h("div", { class: "step-title" }, p.label),
      )),
      h("div", { style: "margin-top: 14px; padding: 10px; border-top: 1px solid var(--line-soft);" },
        h("button", { class: "btn primary sm", style: "width: 100%;", onclick: () => runDemo(state, rerender) }, "▶ Run full demo audit"),
        h("div", { class: "hint", style: "margin-top: 8px; text-align: center;" }, "Auto-executes phases 1–9 with the pre-filled sample."),
      ),
    );
  }

  function rerender() {
    const p = PHASES[state.current];
    app.innerHTML = "";
    const body = h("div", { class: "main" },
      h("div", { class: "page-head" },
        h("div", null,
          h("h1", null, state.runId ? "Audit Run — Continue" : "New Audit"),
          h("div", { class: "sub" }, state.runId ? `Run ${short(state.runId, 24)} — pick up where you left off, or run the remaining phases in one click.` : "Sandbox flow. Submit evidence artifacts inline; each phase records which artifacts were inspected against which regulatory article."),
        ),
        state.runId ? h("a", { class: "btn", href: `#/runs/${state.runId}` }, "Full run detail →") : null,
      ),
      h("div", { class: "wizard" }, stepList(), phaseBody(p, state, rerender)),
    );
    app.appendChild(renderShell(body));
  }
  rerender();
}

async function runDemo(state, rerender) {
  toast("Running demo audit — 9 phases…", "info", 3000);
  try {
    // If no run yet, run intake first
    if (!state.runId) {
      const r = await api("/api/v1/phases/intake", { method: "POST", body: state.intake });
      state.runId = r.runId; state.results.intake = r;
      if (r.blockers?.length) { toast("Intake blocked", "error"); state.blocked = true; rerender(); return; }
    }
    // Run remaining phases in sequence
    const seq = ["scope", "risk", "data_protection", "fairness", "robustness", "explainability", "certification", "monitoring"];
    for (const key of seq) {
      if (state.results[key]?.status === "passed") continue;
      const body = { runId: state.runId, ...(state.phaseInputs[key] || {}) };
      const path = "/api/v1/phases/" + key.replace(/_/g, "-");
      try {
        const r = await api(path, { method: "POST", body });
        state.results[key] = r;
        state.current = Math.min(PHASES.length - 1, PHASES.findIndex(p => p.key === key) + 1);
        rerender();
        if (r.blockers?.length) { toast(`Phase ${key} produced a blocker — pipeline halted`, "error"); state.blocked = true; break; }
      } catch (e) { toast(`Phase ${key} failed: ${e.message}`, "error"); break; }
    }
    if (!state.blocked && state.results.certification) toast("Demo audit complete — certificate issued.", "success");
    rerender();
  } catch (e) { toast(e.message, "error"); }
}

function phaseBody(p, state, rerender) {
  const wrap = h("div", { class: "wizard-body" });
  const result = state.results[p.key];

  const phaseDescription = {
    intake: "Register the model and submit the primary compliance documents. These artifacts will be cited throughout every subsequent phase.",
    scope: "Map the applicable regulatory frameworks based on deployment context (sector, regions, data categories). Deterministic — no inputs required.",
    risk: "Classify EU AI Act risk tier — prohibited / high / limited / minimal — from Annex III use cases and Art. 5 practices.",
    data_protection: "Assess GDPR + DPDP Act obligations: lawful basis, DPIA (Art. 35), cross-border transfers, consent mechanism, retention.",
    fairness: "Compute demographic parity + disparate-impact ratio (four-fifths rule) + equal-opportunity difference across sensitive features.",
    robustness: "Deterministic in-boundary corpus: prompt injection, jailbreak, data extraction, evasion, poisoning resilience. Passes iff every required control is declared.",
    explainability: "Verify Art. 12/13/14 human oversight — kill switch, HITL, explainability method, decision logs, GDPR Art. 22 explanations.",
    certification: "Assemble + Ed25519-sign the W3C VC 2.0 credential (eddsa-jcs-2022). Blocked if any prior phase raised a blocker.",
    monitoring: "Configure drift + fairness thresholds + reaudit triggers on Redis. Enters `monitoring_active` state.",
  };

  wrap.appendChild(h("h2", null, p.label.replace("·", "—")));
  wrap.appendChild(h("div", { class: "sub" }, phaseDescription[p.key]));

  // form
  wrap.appendChild(phaseForm(p, state));

  // action bar
  const canRun = p.key === "intake" || (state.runId && !state.blocked);
  const done = !!result;
  const runBtn = h("button", { class: "btn primary", disabled: !canRun, onclick: async () => {
    try {
      let body, path;
      if (p.key === "intake") { body = state.intake; path = "/api/v1/phases/intake"; }
      else { body = { runId: state.runId, ...(state.phaseInputs[p.key] || {}) }; path = "/api/v1/phases/" + p.key.replace(/_/g, "-"); }
      runBtn.disabled = true; runBtn.textContent = "Running…";
      const r = await api(path, { method: "POST", body });
      state.results[p.key] = r;
      if (p.key === "intake") state.runId = r.runId;
      if (r.blockers?.length) { state.blocked = true; toast(`${p.label} — BLOCKED`, "error"); }
      else { toast(`${p.label} — Passed`, "success"); }
      if (state.current < PHASES.length - 1) state.current += 1;
      rerender();
    } catch (e) { toast(e.message, "error"); runBtn.disabled = false; runBtn.textContent = done ? "Re-run phase" : "Run phase"; }
  } }, done ? "Re-run phase" : "Run phase");

  wrap.appendChild(h("div", { class: "wizard-nav" },
    h("button", { class: "btn ghost", disabled: state.current === 0, onclick: () => { state.current -= 1; rerender(); } }, "← Back"),
    h("div", { class: "f-r" },
      runBtn,
      h("button", { class: "btn", disabled: !done || state.current === PHASES.length - 1, onclick: () => { state.current += 1; rerender(); } }, "Next →"),
    ),
  ));

  if (result) wrap.appendChild(phaseResultView(p, result));
  return wrap;
}

function phaseForm(p, state) {
  const box = h("div", null);
  if (p.key === "intake") {
    const i = state.intake;
    const box2 = h("div", null,
      h("div", { class: "field-row" },
        h("div", { class: "field" }, h("label", null, "Model ID ", h("span", { class: "req" }, "*")), h("input", { value: i.modelId, oninput: (e) => i.modelId = e.target.value })),
        h("div", { class: "field" }, h("label", null, "Version"), h("input", { value: i.modelVersion, oninput: (e) => i.modelVersion = e.target.value })),
      ),
      h("div", { class: "field-row" },
        h("div", { class: "field" }, h("label", null, "Owner team"), h("input", { value: i.ownerTeam, oninput: (e) => i.ownerTeam = e.target.value })),
        h("div", { class: "field" }, h("label", null, "Sector"),
          (() => { const s = h("select", null, ...["employment", "credit", "healthcare", "education", "law_enforcement", "essential_services", "other"].map(o => h("option", { value: o, selected: i.deploymentContext.sector === o }, o))); s.onchange = (e) => i.deploymentContext.sector = e.target.value; return s; })(),
        ),
      ),
      h("div", { class: "field" }, h("label", null, "Regions (comma-separated)"), h("input", { value: i.deploymentContext.regions.join(", "), oninput: (e) => i.deploymentContext.regions = e.target.value.split(",").map(s => s.trim()).filter(Boolean) })),
      h("div", { class: "field" }, h("label", null, "Description"), h("input", { value: i.deploymentContext.description || "", oninput: (e) => i.deploymentContext.description = e.target.value })),
    );
    box.appendChild(box2);
    box.appendChild(renderArtifactEditor(i));
  }
  if (p.key === "risk") {
    const r = state.phaseInputs.risk.riskInputs;
    box.appendChild(h("div", { class: "field" }, h("label", null, "Annex III categories (comma-separated)"),
      h("input", { value: r.annexIIICategories.join(", "), oninput: (e) => r.annexIIICategories = e.target.value.split(",").map(s => s.trim()).filter(Boolean) })));
    box.appendChild(checkboxGrid(r, [
      ["isSafetyComponent", "Safety component of a regulated product"],
      ["interactsWithHumans", "Interacts with humans"],
      ["generatesSyntheticContent", "Generates synthetic content"],
      ["usesRealtimeBiometricId", "Uses real-time biometric identification (Art. 5)"],
      ["usesSocialScoring", "Social scoring of natural persons (Art. 5)"],
      ["usesManipulativeTechniques", "Manipulative techniques causing harm (Art. 5)"],
    ]));
  }
  if (p.key === "data_protection") {
    const d = state.phaseInputs.data_protection.dataProtection;
    box.appendChild(h("div", { class: "field-row" },
      h("div", { class: "field" }, h("label", null, "Lawful basis"),
        (() => { const s = h("select", null, ...["none", "consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interest"].map(o => h("option", { value: o, selected: d.lawfulBasis === o }, o))); s.onchange = (e) => d.lawfulBasis = e.target.value; return s; })(),
      ),
      h("div", { class: "field" }, h("label", null, "Retention (days)"), h("input", { type: "number", value: d.retentionPeriodDays || 0, oninput: (e) => d.retentionPeriodDays = parseInt(e.target.value) || null })),
    ));
    box.appendChild(checkboxGrid(d, [
      ["processesPersonalData", "Processes personal data"],
      ["dpiaConducted", "DPIA conducted (Art. 35)"],
      ["dpoAppointed", "DPO appointed"],
      ["consentMechanism", "Consent mechanism (DPDP Sec. 6)"],
      ["dataMinimisationApplied", "Data minimisation applied"],
      ["privacyByDesign", "Privacy by design & default"],
    ]));
  }
  if (p.key === "fairness") {
    const f = state.phaseInputs.fairness;
    box.appendChild(h("div", { class: "field-row" },
      h("div", { class: "field" }, h("label", null, "Sensitive features (comma-separated)"),
        h("input", { value: f.sensitiveFeatures.join(", "), oninput: (e) => f.sensitiveFeatures = e.target.value.split(",").map(s => s.trim()).filter(Boolean) })),
      h("div", { class: "field" }, h("label", null, "Disparate-impact threshold"),
        h("input", { type: "number", step: "0.01", value: f.fairnessThreshold, oninput: (e) => f.fairnessThreshold = parseFloat(e.target.value) || 0.8 })),
    ));
    box.appendChild(h("div", { class: "field" }, h("label", null, "Dataset sample (JSON array of {attributes, outcome, label})"),
      h("textarea", { value: JSON.stringify(f.datasetSample, null, 2), oninput: (e) => { try { f.datasetSample = JSON.parse(e.target.value); } catch {} } })));
  }
  if (p.key === "robustness") {
    const rb = state.phaseInputs.robustness;
    box.appendChild(h("div", { class: "field" }, h("label", null, "Test suites"), h("div", { class: "checkbox-grid" },
      ...["prompt_injection", "jailbreak", "data_extraction", "evasion", "poisoning_resilience"].map(suite =>
        h("label", { class: "checkbox" },
          h("input", { type: "checkbox", checked: rb.testSuites.includes(suite), onchange: (e) => { if (e.target.checked) rb.testSuites = [...new Set([...rb.testSuites, suite])]; else rb.testSuites = rb.testSuites.filter(s => s !== suite); } }),
          h("span", null, suite),
        )),
    )));
    box.appendChild(h("div", { class: "field" }, h("label", null, "Security controls"), checkboxGridInner(rb.securityControls, [
      ["inputSanitization", "Input sanitization"],
      ["outputFiltering", "Output filtering"],
      ["rateLimiting", "Rate limiting"],
      ["adversarialTraining", "Adversarial training"],
      ["anomalyMonitoring", "Anomaly monitoring"],
      ["accessControl", "Access control"],
    ])));
  }
  if (p.key === "explainability") {
    const ex = state.phaseInputs.explainability;
    box.appendChild(h("div", { class: "field" }, h("label", null, "Explainability method"),
      (() => { const s = h("select", null, ...["none", "shap", "lime", "integrated_gradients", "attention_maps", "rule_based"].map(o => h("option", { value: o, selected: ex.explainability.method === o }, o))); s.onchange = (e) => ex.explainability.method = e.target.value; return s; })(),
    ));
    box.appendChild(h("div", { class: "field" }, h("label", null, "Decision log retention (days)"),
      h("input", { type: "number", value: ex.explainability.logRetentionDays || 0, oninput: (e) => ex.explainability.logRetentionDays = parseInt(e.target.value) || null })));
    box.appendChild(h("div", { class: "field" }, h("label", null, "Oversight"), checkboxGridInner(ex.oversight, [
      ["hasHumanInTheLoop", "Human-in-the-loop"],
      ["hasKillSwitch", "Kill switch"],
      ["overrideProcedureDocumented", "Override procedure documented"],
    ])));
    box.appendChild(h("div", { class: "field" }, h("label", null, "Explainability signals"), checkboxGridInner(ex.explainability, [
      ["userFacingExplanations", "User-facing explanations"],
      ["decisionLogsRetained", "Decision logs retained"],
    ])));
  }
  if (p.key === "certification") {
    const c = state.phaseInputs.certification;
    box.appendChild(h("div", { class: "field-row" },
      h("div", { class: "field" }, h("label", null, "Issuer name"), h("input", { value: c.issuer.name, oninput: (e) => c.issuer.name = e.target.value })),
      h("div", { class: "field" }, h("label", null, "Validity (days)"), h("input", { type: "number", value: c.validityDays, oninput: (e) => c.validityDays = parseInt(e.target.value) || 365 })),
    ));
  }
  if (p.key === "monitoring") {
    const m = state.phaseInputs.monitoring.monitors;
    box.appendChild(h("div", { class: "field-row" },
      h("div", { class: "field" }, h("label", null, "Drift threshold"), h("input", { type: "number", step: "0.05", value: m.driftThreshold, oninput: (e) => m.driftThreshold = parseFloat(e.target.value) })),
      h("div", { class: "field" }, h("label", null, "Fairness drift threshold"), h("input", { type: "number", step: "0.05", value: m.fairnessDriftThreshold, oninput: (e) => m.fairnessDriftThreshold = parseFloat(e.target.value) })),
    ));
  }
  return box;
}

function checkboxGrid(target, fields) {
  return h("div", { class: "field" }, checkboxGridInner(target, fields));
}
function checkboxGridInner(target, fields) {
  return h("div", { class: "checkbox-grid" }, ...fields.map(([k, l]) =>
    h("label", { class: "checkbox" },
      h("input", { type: "checkbox", checked: !!target[k], onchange: (e) => target[k] = e.target.checked }),
      h("span", null, l),
    ),
  ));
}

function renderArtifactEditor(intake) {
  const list = h("div", { class: "artifact-list" });
  function refresh() {
    list.innerHTML = "";
    if (!intake.evidenceArtifacts.length) {
      list.appendChild(h("div", { class: "empty" }, "No artifacts yet."));
      return;
    }
    intake.evidenceArtifacts.forEach((a, idx) => {
      const hasBytes = !!a.contentBase64;
      list.appendChild(h("div", { class: "artifact-item" },
        h("span", { class: "icon" }, hasBytes ? "📄" : "◈"),
        h("div", { class: "name" },
          h("b", null, a.name,
            hasBytes ? h("span", { class: "pill ok", style: "margin-left:6px;font-size:9.5px;" }, "bytes uploaded") : null),
          h("span", { class: "meta" }, a.type + " · " + (a.uri || (hasBytes ? `${(a.contentBase64.length * 0.75 / 1024).toFixed(1)} KB` : "descriptor-only"))),
        ),
        h("button", { class: "btn sm danger", onclick: () => { intake.evidenceArtifacts.splice(idx, 1); refresh(); } }, "Remove"),
      ));
    });
  }
  refresh();
  const nameIn = h("input", { placeholder: "Artifact name (e.g. DPIA v1.0)" });
  const typeSel = h("select", null, ...[
    "model_card", "dpia", "dataset_lineage", "training_log",
    "bias_test_output", "fairness_metrics_report",
    "robustness_test_log", "security_audit", "adversarial_test_report",
    "explainability_report", "decision_log_sample",
    "oversight_procedure", "kill_switch_evidence",
    "consent_ux_evidence", "data_flow_map", "ropa_record",
    "risk_assessment", "conformity_declaration",
    "monitoring_dashboard", "incident_report", "other",
  ].map(t => h("option", { value: t }, t)));
  const uriIn = h("input", { placeholder: "URI or reference (internal://…) — optional" });
  const fileIn = h("input", { type: "file", accept: ".pdf,.csv,.json,.md,.txt,.log" });

  const addBtn = h("button", { class: "btn primary sm", onclick: async () => {
    if (!nameIn.value.trim()) { toast("Name required", "error"); return; }
    const artifact = { name: nameIn.value.trim(), type: typeSel.value };
    if (uriIn.value.trim()) artifact.uri = uriIn.value.trim();
    const f = fileIn.files && fileIn.files[0];
    if (f) {
      if (f.size > 20 * 1024 * 1024) { toast("File exceeds 20 MB", "error"); return; }
      const buf = await f.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = ""; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      artifact.contentBase64 = btoa(bin);
      artifact.mimeType = f.type || null;
      if (!artifact.uri) artifact.uri = `upload://${f.name}`;
      toast(`Loaded ${f.name} (${(f.size / 1024).toFixed(1)} KB)`, "info", 2500);
    }
    intake.evidenceArtifacts.push(artifact);
    nameIn.value = ""; uriIn.value = ""; fileIn.value = "";
    refresh();
  } }, "＋ Add");
  return h("div", { class: "field" },
    h("label", null, "Evidence artifacts submitted with this run ",
      h("span", { class: "hint" }, "· cited by phases 1-9 against specific regulatory articles · uploaded files are text-extracted & gap-analyzed server-side")),
    list,
    h("div", { class: "artifact-add" }, nameIn, typeSel, addBtn),
    h("div", { class: "field-row" },
      h("div", { class: "field" }, h("label", null, "URI (optional)"), uriIn),
      h("div", { class: "field" }, h("label", null, "File (optional — PDF / CSV / JSON / MD / TXT · max 20 MB)"), fileIn),
    ),
  );
}

function phaseResultView(p, result) {
  const s = result.status;
  const outputs = result.outputs || {};
  const blockers = result.blockers || [];
  const cited = outputs.citedArtifacts || result.citedArtifacts || [];
  const missing = outputs.missingArtifacts || result.missingArtifacts || [];
  const docGaps = outputs.documentGaps || result.documentGaps || [];
  const gapSummary = outputs.documentGapSummary;
  const findings = outputs.findings || [];

  return h("div", { class: "phase-result " + s },
    h("div", { class: "r-head" },
      h("span", { class: "pill " + s }, s.toUpperCase()),
      h("span", { class: "r-title" }, p.label + " — " + (s === "passed" ? "Passed" : "Blocked")),
      h("span", { class: "r-hash" }, "hash " + short(result.integrityHash, 22)),
    ),
    gapSummary ? h("div", { style: "font-size: 11.5px; color: var(--ink-dim); margin-bottom: 12px; padding: 8px 12px; background: var(--bg); border: 1px solid var(--line-soft); border-radius: 6px;" },
      h("b", { style: "color: var(--ink)" }, "Document gap analysis: "),
      `${gapSummary.present} present · ${gapSummary.partial} partial · ${gapSummary.gap} gap · `,
      h("b", { style: `color: var(--${gapSummary.blockerGaps > 0 ? "red" : "acc"})` }, `${gapSummary.blockerGaps} blocker`),
      ", ",
      h("b", { style: `color: var(--${gapSummary.warningGaps > 0 ? "amber" : "ink-dim"})` }, `${gapSummary.warningGaps} warning`),
    ) : null,
    blockers.length ? h("div", null,
      h("div", { class: "tl-subhead" }, "Blockers"),
      ...blockers.map(b => h("div", { class: "blocker" },
        h("b", null, `${b.framework} ${b.article} — ${b.code}: ${b.reason}`),
        b.remediation ? h("div", { class: "rem" }, "Remediation: " + b.remediation) : null,
      )),
    ) : null,
    docGaps.length ? h("div", null,
      h("div", { class: "tl-subhead" }, "Document gap analysis — sections found / partial / missing"),
      ...docGaps.map(g => h("div", { class: "cit-row" },
        h("span", { class: "art-icon", style: `color: var(--${g.verdict === "gap" && g.severity === "blocker" ? "red" : g.verdict === "gap" ? "amber" : g.verdict === "partial" ? "amber" : g.verdict === "pending" ? "ink-dim" : "acc"})` },
          g.verdict === "gap" ? "✗" : g.verdict === "partial" ? "!" : g.verdict === "pending" ? "○" : "✓"),
        h("code", null, g.framework),
        h("code", null, g.article),
        h("div", { class: "art" },
          h("b", null, g.section),
          h("div", { class: "meta" }, g.artifactName + " · " + g.artifactType),
          g.evidenceSpan ? h("div", { style: "color: var(--acc-2); font-size: 11px; margin-top: 3px; font-style: italic;" }, g.evidenceSpan) : null,
          g.verdict !== "present" ? h("div", { class: "missing-note", style: `color: var(--${g.severity === "blocker" ? "red" : "amber"})` }, g.note) : null,
        ),
        h("span", { class: "pill " + (g.verdict === "gap" ? (g.severity === "blocker" ? "fail" : "warning") : g.verdict === "partial" ? "warning" : g.verdict === "pending" ? "muted" : "ok") }, g.verdict + " · " + g.severity),
      )),
    ) : null,
    cited.length ? h("div", null,
      h("div", { class: "tl-subhead" }, "Article-level citations (artifacts inspected)"),
      ...cited.map(c => h("div", { class: "cit-row" },
        h("span", { class: "art-icon", style: `color: var(--${c.verdict === "fail" ? "red" : c.verdict === "warning" ? "amber" : "acc"})` }, c.verdict === "fail" ? "✗" : c.verdict === "warning" ? "!" : "✓"),
        h("code", null, c.framework),
        h("code", null, c.article),
        h("div", { class: "art" },
          h("b", null, c.name),
          h("div", { class: "meta" }, c.type + " · sha256 " + short(c.sha256, 12) + (c.extractionStatus ? " · " + c.extractionStatus : "") + (c.gapScore != null ? ` · gap-score ${c.gapScore.toFixed(2)}` : "")),
        ),
        h("span", { class: "pill " + c.verdict }, c.verdict),
      )),
    ) : null,
    missing.length ? h("div", null,
      h("div", { class: "tl-subhead" }, "Missing artifacts (no evidence submitted)"),
      ...missing.map(m => h("div", { class: "cit-row" },
        h("span", { class: "art-icon", style: "color: var(--red)" }, "?"),
        h("code", null, m.framework),
        h("code", null, m.article),
        h("div", { class: "art" }, h("b", null, "Missing: " + m.expectedType), h("div", { class: "missing-note" }, m.reason)),
        h("span", { class: "pill missing" }, "missing"),
      )),
    ) : null,
    findings.length ? h("div", null,
      h("div", { class: "tl-subhead" }, "Engine findings"),
      ...findings.map(f => h("div", { class: "verify-row" },
        h("span", { style: `color: var(--${f.status === "pass" ? "acc" : f.status === "warning" ? "amber" : "red"})` }, f.status === "pass" ? "✓" : f.status === "warning" ? "!" : "✗"),
        h("span", null, h("b", null, f.check), h("br"), h("span", { style: "color: var(--ink-dim); font-size: 11.5px;" }, `${f.framework} ${f.article} — ${f.detail}`)),
        h("span", { class: "pill " + f.status }, f.status),
      )),
    ) : null,
  );
}

// ─── RUN DETAIL ────────────────────────────────────────────────
route("runs/:runId", async (app, params) => {
  const body = h("div", { class: "main" }, h("div", { class: "empty" }, "Loading run…"));
  app.appendChild(renderShell(body));
  const [run] = await Promise.all([api(`/api/v1/runs/${params.runId}`)]);
  app.innerHTML = "";
  app.appendChild(renderShell(renderRunDetail(run)));
});

function renderRunDetail(run) {
  const totalGaps = (run.gaps || []).filter(g => g.verdict === "gap" && g.severity === "blocker").length;
  const warnGaps = (run.gaps || []).filter(g => g.verdict === "gap" && g.severity === "warning").length;
  const container = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null,
        h("h1", null, `Run · ${run.modelId} v${run.modelVersion}`),
        h("div", { class: "sub" }, `runId ${run.runId} — ${fmtDate(run.createdAt)}`),
      ),
      h("div", { class: "f-r" },
        h("span", { class: "pill " + run.status }, run.status.replace("_", " ")),
        run.certificateId ? h("a", { class: "btn primary", href: `#/certificates/${encodeURIComponent(run.certificateId)}` }, "View Certificate →") : null,
      ),
    ),
    h("div", { class: "grid cols-4" },
      h("div", { class: "card" }, h("h3", null, "Phases"), h("div", { class: "metric" }, `${run.phases.length}/9`), h("div", { class: "metric-sub" }, run.phases.filter(p => p.status === "passed").length + " passed, " + run.phases.filter(p => p.status === "blocked").length + " blocked")),
      h("div", { class: "card" }, h("h3", null, "Artifacts"), h("div", { class: "metric" }, run.artifacts?.length ?? 0), h("div", { class: "metric-sub" }, "Evidence documents submitted")),
      h("div", { class: "card" }, h("h3", null, "Citations"), h("div", { class: "metric" }, run.citations?.length ?? 0), h("div", { class: "metric-sub" }, "Artifact ↔ article mappings")),
      h("div", { class: "card" }, h("h3", null, "Document gaps"), h("div", { class: "metric", style: `color: var(--${totalGaps > 0 ? "red" : warnGaps > 0 ? "amber" : "acc"})` }, totalGaps + " / " + warnGaps), h("div", { class: "metric-sub" }, "Blocker · warning sections missing")),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "9-Phase Timeline"), h("span", { class: "pill muted" }, "click a phase to expand")),
      h("div", { class: "section-body", style: "padding: 14px 16px;" },
        ...run.phases.map(ph => renderTimelinePhase(ph, run)),
      ),
    ),
    h("div", { class: "section" },
      h("div", { class: "section-head" }, h("h2", null, "Evidence Artifacts")),
      h("div", { class: "section-body" }, artifactTable(run.artifacts || [], run.citations || [])),
    ),
  );
  return container;
}

function renderTimelinePhase(ph, run) {
  const body = h("div", { class: "tl-body" });
  const head = h("div", { class: "tl-head " + ph.status, onclick: () => { body.classList.toggle("open"); } },
    h("div", { class: "tl-num" }, ph.status === "passed" ? "✓" : ph.status === "blocked" ? "!" : String(ph.phaseNumber)),
    h("div", { class: "tl-title" }, `${ph.phaseNumber}. ${humanizePhase(ph.phase)}`,
      h("div", { class: "tl-desc" }, ph.legalMappings.map(m => `${m.framework}:${m.article}`).join(" · ")),
    ),
    h("span", { class: "pill " + ph.status }, ph.status),
    h("code", { style: "color: var(--ink-mute); font-size: 10.5px;" }, short(ph.integrityHash, 20)),
    h("span", { style: "color: var(--ink-mute);" }, "▾"),
  );
  const citations = (run.citations || []).filter(c => c.phaseKey === ph.phase);
  const cited = citations.filter(c => c.verdict !== "missing");
  const missing = citations.filter(c => c.verdict === "missing");
  const gaps = (run.gaps || []).filter(g => g.phaseKey === ph.phase);
  const gapsBlocker = gaps.filter(g => g.verdict === "gap" && g.severity === "blocker");
  const gapsWarning = gaps.filter(g => g.verdict === "gap" && g.severity === "warning");
  const gapsPresent = gaps.filter(g => g.verdict === "present" || g.verdict === "partial");

  body.appendChild(h("div", { class: "tl-subhead" }, "Hash chain"));
  body.appendChild(h("div", { class: "hash-chain" }, h("b", null, "This: "), ph.integrityHash, h("br"), h("b", null, "Prev: "), ph.prevHash));

  if (ph.blockers && ph.blockers.length) {
    body.appendChild(h("div", { class: "tl-subhead" }, "Blockers"));
    ph.blockers.forEach(b => body.appendChild(h("div", { class: "blocker" },
      h("b", null, `${b.framework} ${b.article} — ${b.code}: ${b.reason}`),
      b.remediation ? h("div", { class: "rem" }, "Remediation: " + b.remediation) : null,
    )));
  }

  if (gaps.length) {
    body.appendChild(h("div", { class: "tl-subhead" },
      `Document gap analysis — ${gapsBlocker.length} blocker · ${gapsWarning.length} warning · ${gapsPresent.length} present/partial`));
    gaps.forEach(g => body.appendChild(h("div", { class: "cit-row" },
      h("span", { class: "art-icon", style: `color: var(--${g.verdict === "gap" && g.severity === "blocker" ? "red" : g.verdict === "gap" ? "amber" : g.verdict === "partial" ? "amber" : "acc"})` },
        g.verdict === "gap" ? "✗" : g.verdict === "partial" ? "!" : "✓"),
      h("code", null, g.framework),
      h("code", null, g.article),
      h("div", { class: "art" },
        h("b", null, g.section),
        h("div", { class: "meta" }, (g.artifactName || "?") + " · " + (g.artifactType || "?")),
        g.evidenceSpan ? h("div", { style: "color: var(--acc-2); font-size: 11px; margin-top: 3px; font-style: italic;" }, g.evidenceSpan) : null,
        g.verdict !== "present" ? h("div", { class: "missing-note", style: `color: var(--${g.severity === "blocker" ? "red" : "amber"})` }, g.note) : null,
      ),
      h("span", { class: "pill " + (g.verdict === "gap" ? (g.severity === "blocker" ? "fail" : "warning") : g.verdict === "partial" ? "warning" : "ok") }, g.verdict + " · " + g.severity),
    )));
  }

  if (cited.length) {
    body.appendChild(h("div", { class: "tl-subhead" }, "Articles evidenced — artifacts inspected"));
    cited.forEach(c => body.appendChild(h("div", { class: "cit-row" },
      h("span", { class: "art-icon", style: `color: var(--${c.verdict === "fail" ? "red" : c.verdict === "warning" ? "amber" : "acc"})` }, c.verdict === "fail" ? "✗" : c.verdict === "warning" ? "!" : "✓"),
      h("code", null, c.framework),
      h("code", null, c.article),
      h("div", { class: "art" }, h("b", null, c.artifactName || c.expectedType), h("div", { class: "meta" }, `${c.artifactType || "—"} · ${c.control} · sha256 ${short(c.artifactSha256, 12)}`)),
      h("span", { class: "pill " + c.verdict }, c.verdict),
    )));
  }
  if (missing.length) {
    body.appendChild(h("div", { class: "tl-subhead" }, "Missing evidence — controls not covered"));
    missing.forEach(m => body.appendChild(h("div", { class: "cit-row" },
      h("span", { class: "art-icon", style: "color: var(--red)" }, "?"),
      h("code", null, m.framework),
      h("code", null, m.article),
      h("div", { class: "art" }, h("b", null, "Missing: " + m.expectedType), h("div", { class: "missing-note" }, m.note)),
      h("span", { class: "pill missing" }, "missing"),
    )));
  }

  body.appendChild(h("div", { class: "tl-subhead" }, "Engine outputs (JSONB evidence)"));
  body.appendChild(h("pre", { class: "json-view" }, JSON.stringify(ph.outputs || {}, null, 2)));

  return h("div", { class: "tl-phase" }, head, body);
}

function humanizePhase(k) {
  return ({
    intake: "Intake & Context Registration",
    scope: "Regulatory Scope Mapping",
    risk: "Risk Classification (EU AI Act Art. 5/6/50)",
    data_protection: "Data Protection & Privacy (GDPR / DPDP Act)",
    fairness: "Fairness & Bias Evaluation",
    robustness: "Robustness, Security & Resilience",
    explainability: "Explainability & Human Oversight",
    certification: "Certification Assembly (VC 2.0)",
    monitoring: "Continuous Monitoring & Reaudit",
  })[k] || k;
}

function artifactTable(arts, cits) {
  if (!arts.length) return h("div", { class: "empty" }, "No artifacts submitted for this run.");
  return h("table", null,
    h("thead", null, h("tr", null, ...["Name", "Type", "Extraction", "Gap score", "sha256", "Cited in phases", "Submitted"].map(t => h("th", null, t)))),
    h("tbody", null, ...arts.map(a => {
      const phases = [...new Set(cits.filter(c => c.artifactId === a.artifactId).map(c => c.phaseKey))];
      const g = a.gapScore;
      const gPill = g == null ? h("span", { class: "pill muted" }, "—") :
                    h("span", { class: "pill " + (g >= 0.8 ? "ok" : g >= 0.5 ? "warning" : "fail") },
                      (g * 100).toFixed(0) + "%");
      return h("tr", null,
        h("td", null, h("b", null, a.name), a.uri ? h("div", { style: "font-size: 10.5px; color: var(--ink-mute); font-family: var(--mono); margin-top: 2px;" }, short(a.uri, 60)) : null),
        h("td", null, h("code", null, a.type)),
        h("td", null,
          h("span", { class: "pill " + (a.extractionStatus === "extracted" ? "ok" : a.extractionStatus === "pending" ? "muted" : "warning") }, a.extractionStatus || "—"),
          a.extractedChars ? h("div", { style: "font-size: 10.5px; color: var(--ink-mute); margin-top: 2px;" }, `${a.extractedChars} chars`) : null,
        ),
        h("td", null, gPill),
        h("td", null, h("code", null, short(a.sha256, 12))),
        h("td", null, phases.length ? phases.map(p => h("span", { class: "tag" }, p)) : h("span", { class: "pill muted" }, "not cited")),
        h("td", null, fmtDate(a.submittedAt)),
      );
    })),
  );
}

// ─── CERTIFICATE DETAIL ────────────────────────────────────────
route("certificates/:certId", async (app, params) => {
  const body = h("div", { class: "main" }, h("div", { class: "empty" }, "Loading certificate…"));
  app.appendChild(renderShell(body));
  const [cert, ver] = await Promise.all([
    api(`/api/v1/certificates/${encodeURIComponent(params.certId)}`),
    api(`/api/v1/certificates/${encodeURIComponent(params.certId)}/verify`, { public: true }),
  ]);
  app.innerHTML = "";
  const vc = cert.vc_payload;
  const detail = h("div", { class: "main" },
    h("div", { class: "page-head" },
      h("div", null,
        h("h1", null, "Certificate"),
        h("div", { class: "sub" }, "W3C Verifiable Credential 2.0 · eddsa-jcs-2022 · Ed25519 · did:key"),
      ),
      h("div", { class: "f-r" },
        h("span", { class: "pill " + cert.status }, cert.status),
        hasScope("certs:read") && cert.status === "active" ? h("button", { class: "btn danger", onclick: () => revokeCert(params.certId) }, "Revoke…") : null,
      ),
    ),
    h("div", { class: "cert-header" },
      h("div", { class: "cert-title" }, vc.credentialSubject?.model || cert.model_id),
      h("div", { class: "cert-id" }, cert.certificate_id),
      h("div", { class: "cert-meta" },
        h("div", null, h("div", { class: "cm-k" }, "Issued"), h("div", { class: "cm-v" }, fmtDate(cert.issued_at))),
        h("div", null, h("div", { class: "cm-k" }, "Valid until"), h("div", { class: "cm-v" }, fmtDate(cert.expires_at))),
        h("div", null, h("div", { class: "cm-k" }, "Verification"), h("div", { class: "cm-v acc" }, ver.verified ? "✓ VERIFIED" : "✗ INVALID")),
        h("div", null, h("div", { class: "cm-k" }, "Anchor"), h("div", { class: "cm-v" }, short(cert.anchor_hash, 20))),
      ),
    ),
    h("div", { class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Verification Checks")),
      h("div", { style: "padding: 14px 20px;" },
        ...Object.entries(ver.checks || {}).map(([k, ok]) => h("div", { class: "verify-row" },
          h("span", { style: `color: var(--${ok ? "acc" : "red"})` }, ok ? "✓" : "✗"),
          h("span", null, k),
          h("span", { class: "pill " + (ok ? "ok" : "fail") }, ok ? "PASS" : "FAIL"),
        )),
      ),
    ),
    h("div", { class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Credential Subject (audit summary)")),
      h("div", { style: "padding: 14px 20px;" }, h("pre", { class: "json-view" }, JSON.stringify(vc.credentialSubject || {}, null, 2))),
    ),
    h("div", { class: "section" }, h("div", { class: "section-head" }, h("h2", null, "Full W3C VC 2.0 JSON")),
      h("div", { style: "padding: 14px 20px;" }, h("pre", { class: "json-view" }, JSON.stringify(vc, null, 2))),
    ),
  );
  app.appendChild(renderShell(detail));
});

async function revokeCert(certId) {
  const reason = prompt("Reason for revocation? (min 3 chars)");
  if (!reason || reason.length < 3) return;
  try {
    await api(`/api/v1/certificates/${encodeURIComponent(certId)}/revoke`, { method: "POST", body: { reason } });
    toast("Certificate revoked", "success");
    router();
  } catch (e) { toast(e.message, "error"); }
}
