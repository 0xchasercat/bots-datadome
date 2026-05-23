#!/usr/bin/env node
/**
 * recon.mjs — find DataDome's tag on a target page and report its version.
 *
 * Loads a target URL with Playwright, logs every JS response, flags chunks
 * matching js.datadome.co/tags.js or captcha-delivery.com/c.js. Reports
 * the bundle version (extracted from the banner comment).
 *
 * Usage: node recon.mjs [target-url]
 *   default target: https://datadome.co/blog/
 */

import { chromium } from "playwright";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

const TARGET = process.argv[2] || "https://datadome.co/blog/";

const userDataDir = mkdtempSync(join(tmpdir(), "dd-recon-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
  viewport: { width: 1366, height: 900 },
});
const page = await ctx.newPage();

const jsResponses = [];
let tagsBody = null;
let tagsUrl = null;

page.on("response", async (resp) => {
  const u = resp.url();
  const ct = resp.headers()["content-type"] || "";
  if (/javascript|application\/json/.test(ct) || /\.js(\?|$)/.test(u)) {
    jsResponses.push({ url: u, status: resp.status(), bytes: parseInt(resp.headers()["content-length"] || "0") });
  }
  if (/js\.datadome\.co\/tags\.js/.test(u) && !tagsBody) {
    try {
      tagsBody = (await resp.body()).toString("utf8");
      tagsUrl = u;
    } catch {}
  }
});

console.log(`recon: loading ${TARGET}`);
const r = await page.goto(TARGET, { waitUntil: "load", timeout: 30000 }).catch((e) => ({ status: () => "err", _err: e.message }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

await page.waitForTimeout(5000);

const matches = jsResponses.filter((j) =>
  /datadome|captcha-delivery|datado\.me/.test(j.url));

console.log(`\nDataDome-related responses (${matches.length}):`);
matches.forEach((j) => console.log(`  ${j.status}  ${j.url}`));

let bundleInfo = null;
if (tagsBody) {
  const banner = tagsBody.match(/\/\*\*\s*(DataDome[^*]+)\*\//);
  const versionMatch = tagsBody.match(/version\s+(\d+\.\d+\.\d+)/i);
  const vnt = /function v\(n,t\)\{var c,e;/.test(tagsBody);
  const xorshift = /n\^=n<<13;n\^=n>>17;n\^=n<<5/.test(tagsBody);
  bundleInfo = {
    url: tagsUrl,
    bytes: tagsBody.length,
    banner: banner ? banner[1].trim() : null,
    version: versionMatch ? versionMatch[1] : null,
    chokepoint_vnt_present: vnt,
    xorshift_prng_present: xorshift,
  };
  console.log(`\ntags.js bundle:`);
  console.log(`  url:        ${tagsUrl}`);
  console.log(`  size:       ${tagsBody.length} bytes`);
  console.log(`  banner:     ${bundleInfo.banner || "(stripped)"}`);
  console.log(`  version:    ${bundleInfo.version || "(not in banner)"}`);
  console.log(`  v(n,t):     ${vnt ? "PRESENT ✓" : "ABSENT — patch will not work, regex needs update"}`);
  console.log(`  xorshift:   ${xorshift ? "PRESENT ✓ (cipher matches DataDome.md)" : "ABSENT — cipher may have changed"}`);
} else {
  console.log(`\ntags.js NOT loaded on this URL — the target may not be DataDome-protected, or the bundle URL has changed.`);
}

writeFileSync(join(OUT, "recon.json"), JSON.stringify({
  target: TARGET,
  finalStatus: r.status?.() ?? null,
  jsResponseCount: jsResponses.length,
  ddRelated: matches,
  bundle: bundleInfo,
  capturedAt: new Date().toISOString(),
}, null, 2));

await ctx.close();
console.log(`\n  artifacts → ${OUT}/recon.json`);
