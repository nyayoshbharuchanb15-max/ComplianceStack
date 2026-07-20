// SPDX-License-Identifier: Apache-2.0
// Operational status console served at GET / — makes the headless MCP/API
// stack visible in a browser. Read-only; no regulated data is rendered.

import { TOOL_SCHEMAS } from "./tool-schemas.js";
import { GOVERNANCE_TOOL_SCHEMAS } from "./governance-tools.js";
import { callGovernance } from "./governance-client.js";

const GOVERNANCE_API_URL = process.env.GOVERNANCE_API_URL || "http://localhost:8001";

const PHASES: Array<[string, string, string]> = [
  ["1", "Intake & Context Registration", "intake_register"],
  ["2", "Regulatory Scope Mapping", "map_regulatory_scope"],
  ["3", "Risk Classification", "classify_risk"],
  ["4", "Data Protection & Privacy Checks", "check_data_protection"],
  ["5", "Fairness & Bias Evaluation", "evaluate_fairness"],
  ["6", "Robustness, Security & Resilience", "test_robustness"],
  ["7", "Explainability & Human Oversight", "verify_explainability"],
  ["8", "Certification Assembly (VC 2.0)", "assemble_certification"],
  ["9", "Continuous Monitoring & Reaudit", "configure_monitoring"],
];

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

type Health = { status: string; services: Record<string, string> };
type EventRow = { event_type: string; phase_key?: string; run_id?: string; status: string; created_at: string };

export async function buildStatusPage(sessionCount: number, version: string): Promise<string> {
  let health: Health | null = null;
  try {
    const resp = await fetch(`${GOVERNANCE_API_URL}/api/v1/health`, { signal: AbortSignal.timeout(4000) });
    if (resp.ok) health = (await resp.json()) as Health;
  } catch { /* orchestrator down */ }

  let events: EventRow[] = [];
  try {
    const data = await callGovernance<{ events: EventRow[] }>(
      "/api/v1/events/recent", "runs:read", undefined, "GET", 5000);
    events = (data.events || []).slice(0, 8);
  } catch { /* no read scope or fabric empty */ }

  const svc = health?.services ?? { postgres: "unknown", neo4j: "unknown", redis: "unknown", certSigner: "unknown" };
  const dot = (s: string) =>
    `<span class="dot ${s === "connected" || s === "operational" ? "up" : "down"}"></span>`;

  const phaseRows = PHASES.map(([n, name, tool]) => `
      <tr><td class="num">${n}</td><td>${esc(name)}</td><td><code>${esc(tool)}</code></td></tr>`).join("");

  const eventRows = events.length
    ? events.map((e) => `
      <tr><td><code>${esc(e.event_type)}</code></td><td>${esc(e.phase_key ?? "—")}</td>
      <td class="hash">${esc((e.run_id ?? "—").slice(0, 8))}</td>
      <td><span class="pill ${e.status === "delivered" ? "ok" : "warn"}">${esc(e.status)}</span></td>
      <td class="dim">${esc((e.created_at ?? "").replace("T", " ").slice(0, 19))}</td></tr>`).join("")
    : `<tr><td colspan="5" class="dim">No events yet — run a phase to populate the evidence ledger.</td></tr>`;

  const govTools = GOVERNANCE_TOOL_SCHEMAS.map((t) => `<code>${esc(t.name)}</code>`).join(" ");
  const legacyTools = TOOL_SCHEMAS.map((t) => `<code>${esc(t.name)}</code>`).join(" ");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Governance MCP Server — Status</title>
<style>
  :root { --bg:#0b0f0e; --panel:#111816; --line:#1f2b27; --ink:#d7e4de; --dim:#6d827a;
          --acc:#3ddc97; --amber:#e8b339; --red:#e05252; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--ink);
         font:14px/1.6 ui-monospace,"JetBrains Mono","Cascadia Code",Menlo,monospace;
         padding:48px 24px; }
  .wrap { max-width:980px; margin:0 auto; }
  header { border-left:3px solid var(--acc); padding-left:20px; margin-bottom:40px; }
  h1 { font-size:22px; letter-spacing:.5px; font-weight:600; }
  h1 .v { color:var(--dim); font-size:13px; font-weight:400; }
  header p { color:var(--dim); margin-top:6px; max-width:70ch; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:36px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px 18px; }
  .card .k { color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:1.5px; }
  .card .val { font-size:16px; margin-top:6px; display:flex; align-items:center; gap:8px; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; }
  .dot.up { background:var(--acc); box-shadow:0 0 8px var(--acc); }
  .dot.down { background:var(--red); box-shadow:0 0 8px var(--red); }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:2px; color:var(--acc);
       margin:36px 0 14px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:8px; overflow:hidden; }
  th { text-align:left; padding:10px 14px; color:var(--dim); font-size:11px;
       text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--line); }
  td { padding:9px 14px; border-bottom:1px solid var(--line); }
  tr:last-child td { border-bottom:none; }
  td.num { color:var(--acc); width:36px; }
  td.hash, .dim { color:var(--dim); }
  code { background:#0d1412; border:1px solid var(--line); border-radius:4px;
         padding:1px 7px; font-size:12.5px; color:#9fe8c8; }
  .pill { border-radius:99px; padding:1px 10px; font-size:11.5px; }
  .pill.ok { background:rgba(61,220,151,.12); color:var(--acc); border:1px solid rgba(61,220,151,.35); }
  .pill.warn { background:rgba(232,179,57,.12); color:var(--amber); border:1px solid rgba(232,179,57,.35); }
  .tools { background:var(--panel); border:1px solid var(--line); border-radius:8px;
           padding:14px 18px; line-height:2.3; }
  pre { background:#0d1412; border:1px solid var(--line); border-radius:8px;
        padding:14px 18px; overflow-x:auto; color:#9fe8c8; font-size:12.5px; }
  a { color:var(--acc); }
  footer { color:var(--dim); margin-top:44px; font-size:12px; border-top:1px solid var(--line); padding-top:16px; }
</style></head><body><div class="wrap">
<header>
  <h1>AI GOVERNANCE MCP SERVER <span class="v">v${esc(version)}</span></h1>
  <p>On-premise compliance orchestration — 9-phase audit pipeline, article-level evidence
  (EU AI Act · GDPR · NIST AI RMF · ISO/IEC 42001 · DPDP Act), W3C Verifiable Credential 2.0
  certification. This is a headless MCP/API system; this console is a read-only status view.</p>
</header>

<div class="grid">
  <div class="card"><div class="k">Orchestrator</div><div class="val">${health ? dot("connected") + "online" : dot("down") + "offline"}</div></div>
  <div class="card"><div class="k">PostgreSQL evidence</div><div class="val">${dot(svc.postgres)}${esc(svc.postgres)}</div></div>
  <div class="card"><div class="k">Neo4j lineage</div><div class="val">${dot(svc.neo4j)}${esc(svc.neo4j)}</div></div>
  <div class="card"><div class="k">Redis fabric</div><div class="val">${dot(svc.redis)}${esc(svc.redis)}</div></div>
  <div class="card"><div class="k">Cert signer</div><div class="val">${dot(svc.certSigner)}${esc(svc.certSigner)}</div></div>
  <div class="card"><div class="k">MCP sessions</div><div class="val">${sessionCount} active · ${TOOL_SCHEMAS.length + GOVERNANCE_TOOL_SCHEMAS.length} tools</div></div>
</div>

<h2>9-Phase Audit Pipeline</h2>
<table><thead><tr><th>#</th><th>Phase</th><th>MCP tool</th></tr></thead><tbody>${phaseRows}
  <tr><td class="num">—</td><td>Reaudit (impact scope → selective re-run → reissue/supersede/revoke)</td><td><code>trigger_reaudit</code></td></tr>
</tbody></table>

<h2>Recent Evidence Events <span class="dim" style="letter-spacing:0">(governance:phase-events → delivery ledger)</span></h2>
<table><thead><tr><th>Event</th><th>Phase</th><th>Run</th><th>Status</th><th>At (UTC)</th></tr></thead>
<tbody>${eventRows}</tbody></table>

<h2>Try It</h2>
<pre># 1. Get a token (governance-admin service account)
curl -s -X POST ${esc(GOVERNANCE_API_URL === "http://localhost:8001" ? "" : GOVERNANCE_API_URL)}/api/v1/auth/token \\
  -H 'Content-Type: application/json' \\
  -d '{"clientId":"governance-admin","clientSecret":"govern-admin-secret-dev"}'

# 2. Run Phase 1 (Intake) — then scope, risk, … certification, monitoring
curl -s -X POST /api/v1/phases/intake -H "Authorization: Bearer $TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"modelId":"demo-model-1","modelVersion":"1.0.0","deploymentContext":{"sector":"employment","regions":["EU"],"autonomyLevel":"supervised"},"processingActivities":[{"name":"screening","purpose":"cv ranking"}],"datasets":[{"datasetId":"ds-1","containsPersonalData":true}]}'

# 3. Verify an issued certificate (public, offline-verifiable Ed25519 proof)
curl -s /api/v1/certificates/&lt;certificateId&gt;/verify</pre>

<h2>Governance Tools (11)</h2>
<div class="tools">${govTools}</div>
<h2>Standalone Audit Tools (17)</h2>
<div class="tools">${legacyTools}</div>

<footer>Docs: ARCHITECTURE.md · AUDIT_PIPELINE.md · GOVERNANCE_AND_COMPLIANCE.md ·
schemas/w3c_audit_credential.jsonld — MCP endpoint: <code>POST /mcp</code> · Health:
<a href="/health">/health</a> · <a href="/api/v1/health">/api/v1/health</a>.
Zero data egress: all services inside the deployment boundary.</footer>
</div></body></html>`;
}
