// SPDX-License-Identifier: Apache-2.0
// Auditor Workbench — client-side SPA served from Express on port 3000.
// Air-gapped: no CDN, no external fetch. All JS+CSS inlined.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// The client-side JS + CSS live in a sibling directory so we don't have to
// escape 30 KB of template strings inside a .ts file. They are read once at
// startup and served from memory.
const UI_ASSET_DIR = resolve(__dirname, "../ui");

let cachedJs: string | null = null;
let cachedCss: string | null = null;

function readAsset(name: string): string {
  return readFileSync(resolve(UI_ASSET_DIR, name), "utf8");
}

export function getWorkbenchJs(): string {
  if (cachedJs === null) cachedJs = readAsset("workbench.js");
  return cachedJs;
}

export function getWorkbenchCss(): string {
  if (cachedCss === null) cachedCss = readAsset("workbench.css");
  return cachedCss;
}

export function renderWorkbenchShell(version: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>AI Governance — Auditor Workbench</title>
<link rel="stylesheet" href="/assets/workbench.css">
</head>
<body>
<div id="app" data-version="${version}">
  <div class="boot-splash">
    <div class="boot-splash-inner">
      <div class="boot-mark">◉</div>
      <div class="boot-txt">Loading Auditor Workbench…</div>
    </div>
  </div>
</div>
<script src="/assets/workbench.js" type="module"></script>
</body>
</html>`;
}
