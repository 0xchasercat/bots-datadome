#!/usr/bin/env node
/**
 * recon.mjs — find DataDome's tag on a target page and report its version.
 *
 * Loads a target URL with Patchright (stealth Playwright), logs every JS
 * response, flags chunks matching tags.js or captcha-delivery.com/i.js.
 * Reports the bundle version (extracted from the banner comment).
 *
 * Supports DataDome 4.x (tags.js on js.datadome.co) and 5.x
 * (tags.js on dd.<domain>/tags.js, i.js on ct.captcha-delivery.com).
 *
 * Usage: node recon.mjs [target-url]
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
    jsResponses.push({
      url: u,
      status: resp.status(),
      bytes: parseInt(resp.headers()["content-length"] || "0"),
    });
  }
  // Capture tags.js from any subdomain (dd.g2.com, js.datadome.co, etc.)
  // Prioritize tags.js over i.js since i.js is just the loader
  if (/tags\.js/.test(u)) {
    try {
      tagsBody = (await resp.body()).toString("utf8");
      tagsUrl = u;
    } catch {}
  } else if (/captcha-delivery\.com\/i\.js/.test(u) && !tagsBody) {
    // fallback: capture i.js only if tags.js hasn't been seen yet
    try {
      tagsBody = (await resp.body()).toString("utf8");
      tagsUrl = u;
    } catch {}
  }
});

console.log(`recon: loading ${TARGET}`);
const r = await page
  .goto(TARGET, { waitUntil: "load", timeout: 30000 })
  .catch((e) => ({ status: () => "err", _err: e.message }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

await page.waitForTimeout(5000);

const matches = jsResponses.filter((j) =>
  /datadome|captcha-delivery|datado\.me|tags\.js/.test(j.url),
);

console.log(`\nDataDome-related responses (${matches.length}):`);
matches.forEach((j) => console.log(`  ${j.status}  ${j.url}`));

let bundleInfo = null;
if (tagsBody) {
  const banner = tagsBody.match(/\/\*\*\s*(DataDome[^*]+)\*\//);
  const versionMatch = tagsBody.match(/version\s+(\d+\.\d+\.\d+)/i);

  // 4.x patterns
  const vnt = /function v\(n,t\)\{var c,e;/.test(tagsBody);
  const xorshift_old = /n\^=n<<13;n\^=n>>17;n\^=n<<5/.test(tagsBody);

  // 5.7.0+ patterns
  const xorshift_new = /\(n\^=n<<13\)\^n>>17\)^n<<5/.test(tagsBody);
  const prng_V = /return q=function/.test(tagsBody);
  const custom_b64 = /QSdCN\/3956tpzwLMoDFxrVh/.test(tagsBody);
  const seed_constant = /11027890091/.test(tagsBody);
  const final_xor = /1809053797/.test(tagsBody);

  const version = versionMatch ? versionMatch[1] : null;
  const isV5 = version && version.startsWith("5.");
  const isV570Plus = version && (() => {
    const [maj, min, pat] = version.split(".").map(Number);
    return maj > 5 || (maj === 5 && min > 7) || (maj === 5 && min === 7 && pat >= 0);
  })();

  bundleInfo = {
    url: tagsUrl,
    bytes: tagsBody.length,
    banner: banner ? banner[1].trim() : null,
    version,
    // 4.x indicators
    chokepoint_vnt_present: vnt,
    xorshift_prng_present: xorshift_old,
    // 5.7.0+ indicators
    xorshift_570: xorshift_new,
    prng_V_present: prng_V,
    custom_base64: custom_b64,
    seed_constant_present: seed_constant,
    final_xor_present: final_xor,
  };

  console.log(`\ntags.js bundle:`);
  console.log(`  url:        ${tagsUrl}`);
  console.log(`  size:       ${tagsBody.length} bytes`);
  console.log(`  banner:     ${bundleInfo.banner || "(stripped)"}`);
  console.log(`  version:    ${version || "(not in banner)"}`);

  if (isV570Plus) {
    console.log(`\n  [5.7.0+ cipher detected]`);
    console.log(`  xorshift:   ${xorshift_new ? "PRESENT ✓" : "ABSENT"}`);
    console.log(`  V(n,t) PRNG: ${prng_V ? "PRESENT ✓" : "ABSENT"}`);
    console.log(`  custom b64: ${custom_b64 ? "PRESENT ✓" : "ABSENT"}`);
    console.log(`  seed const: ${seed_constant ? "PRESENT ✓ (11027890091)" : "ABSENT"}`);
    console.log(`  final XOR:  ${final_xor ? "PRESENT ✓ (1809053797)" : "ABSENT"}`);
    console.log(`\n  → Use decrypt_v570.mjs for this bundle`);
  } else if (vnt) {
    console.log(`\n  [4.x cipher detected]`);
    console.log(`  v(n,t):     PRESENT ✓`);
    console.log(`  xorshift:   ${xorshift_old ? "PRESENT ✓" : "ABSENT"}`);
    console.log(`\n  → Use decrypt.mjs for this bundle`);
  } else {
    console.log(`\n  [Unknown cipher version]`);
    console.log(`  v(n,t):     ${vnt ? "PRESENT" : "ABSENT"}`);
    console.log(`  xorshift:   ${xorshift_old || xorshift_new ? "PRESENT" : "ABSENT"}`);
  }
} else {
  console.log(
    `\nDataDome JS bundle NOT loaded — the target may not be DataDome-protected, or the bundle URL has changed.`,
  );
}

writeFileSync(
  join(OUT, "recon.json"),
  JSON.stringify(
    {
      target: TARGET,
      finalStatus: r.status?.() ?? null,
      jsResponseCount: jsResponses.length,
      ddRelated: matches,
      bundle: bundleInfo,
      capturedAt: new Date().toISOString(),
    },
    null,
    2,
  ),
);

await ctx.close();
console.log(`\n  artifacts → ${OUT}/recon.json`);
