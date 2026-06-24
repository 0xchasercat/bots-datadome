#!/usr/bin/env node
/**
 * mitm.mjs — passive capture for DataDome's tag.
 *
 * Pure passive capture — no route interception, no init scripts.
 * DataDome 5.7+ detects ANY in-flight tampering.
 *
 * Captures:
 *  - tags.js response (version detection)
 *  - interstitial POST body (plaintext payload)
 *  - All DataDome-related network traffic
 *
 * Usage: node mitm.mjs [target-url]
 *   default target: https://www.g2.com/products/playwright/reviews
 */

import { chromium } from "patchright";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

const TARGET =
  process.argv[2] || "https://www.g2.com/products/playwright/reviews";

const userDataDir = mkdtempSync(join(tmpdir(), "dd-mitm-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
});

const page = await ctx.newPage();
const network = [];
const capturedPayloads = [];
let tagsInfo = null;

page.on("response", (resp) => {
  const u = resp.url();
  if (/datadome|captcha-delivery|datado\.me/.test(u)) {
    network.push({ url: u, status: resp.status(), method: resp.request().method() });
  }
});

page.on("request", (req) => {
  if (/interstitial/.test(req.url()) && req.method() === "POST") {
    const postData = req.postData();
    if (postData) {
      console.log(`[capture] interstitial POST: ${postData.length} bytes`);
      capturedPayloads.push({ url: req.url(), body: postData, timestamp: Date.now() });
    }
  }
});

page.on("response", async (resp) => {
  if (/tags\.js/.test(resp.url())) {
    try {
      const body = (await resp.body()).toString("utf8");
      const versionMatch = body.match(/version\s+(\d+\.\d+\.\d+)/i);
      tagsInfo = { url: resp.url(), size: body.length, version: versionMatch?.[1] || "unknown" };
      console.log(`[tags] ${resp.url()}  ${body.length}B  v${tagsInfo.version}`);
    } catch {}
  }
});

console.log(`mitm: loading ${TARGET}`);
const r = await page
  .goto(TARGET, { waitUntil: "load", timeout: 45000 })
  .catch((e) => ({ status: () => "err" }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

await page.waitForTimeout(7000);

console.log("\n=== RESULT ===");
console.log(`  tags:        ${tagsInfo ? `v${tagsInfo.version} (${tagsInfo.size}B)` : "not captured"}`);
console.log(`  payloads:    ${capturedPayloads.length}`);
console.log(`  dd traffic:  ${network.length} requests`);

writeFileSync(
  join(OUT, "mitm.json"),
  JSON.stringify({
    target: TARGET,
    status: r.status?.() ?? null,
    tagsInfo,
    capturedPayloads,
    ddTraffic: network,
    capturedAt: new Date().toISOString(),
  }, null, 2),
);

await ctx.close();
console.log(`\n  artifacts → ${OUT}/mitm.json`);
