#!/usr/bin/env node
/**
 * bypass.mjs — DataDome challenge bypass + plaintext payload capture.
 *
 * Pipeline:
 *  1. Launch Chrome (headed) — direct or through $PROXY if set.
 *  2. Phase-1: invisible Proxy wraps on JSON.stringify / btoa (init script).
 *  3. Phase-4: in-flight patch on tags.js — inject tap collector at the
 *     main collection function entry point.
 *  4. Warm reputation on target with humanlike mouse/scroll.
 *  5. Wait for the JS tag's POST to the DataDome API (verdict).
 *  6. Dump HTML + plaintext payload + verdict + screenshot + network log.
 *
 * Usage:
 *   node bypass.mjs                              # direct, default target
 *   node bypass.mjs https://target.com/page      # direct, custom target
 *   PROXY=socks5://user:pass@host:port node bypass.mjs  # via proxy
 *   PROXY=http://user:pass@host:port node bypass.mjs     # via proxy
 */

import { chromium } from "patchright";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

// ── Proxy config ────────────────────────────────────────────
// Set PROXY env var to use a proxy. Supports:
//   PROXY=http://host:port
//   PROXY=http://user:pass@host:port
//   PROXY=socks5://host:port
//   PROXY=socks5://user:pass@host:port
// If unset, connects directly (no proxy).

function parseProxy(proxyStr) {
  if (!proxyStr) return undefined;
  try {
    const url = new URL(proxyStr);
    const proxy = { server: `${url.protocol}//${url.hostname}:${url.port}` };
    if (url.username) proxy.username = decodeURIComponent(url.username);
    if (url.password) proxy.password = decodeURIComponent(url.password);
    return proxy;
  } catch (e) {
    console.error(`[proxy] invalid PROXY value: ${proxyStr}`);
    console.error(`         expected format: http://host:port or socks5://user:pass@host:port`);
    process.exit(1);
  }
}

const PROXY = parseProxy(process.env.PROXY);
if (PROXY) {
  console.log(`[proxy] ${PROXY.server}  user=${PROXY.username ? PROXY.username.slice(0, 20) + "…" : "(none)"}`);
} else {
  console.log(`[proxy] none — connecting directly`);
}

// ── Target ──────────────────────────────────────────────────
const TARGET = process.argv[2] || "https://www.g2.com/products/playwright/reviews";

// ── Phase-1 init script ─────────────────────────────────────
// Sets up tap array for signal collection. No Proxy wrapping —
// DataDome detects that. Payload is captured from network instead.
function initScript() {
  return `(() => {
    if (window.__ddInitInstalled) return;
    window.__ddInitInstalled = true;
    window.__ddTap = [];
    window.__ddDump = () => ({
      tap: window.__ddTap || [],
      selfTest: null,
    });
  })();`;
}

// ── Phase-4 bundle patch ────────────────────────────────────
// Detects 4.x (v(n,t)) and 5.7.0+ (q function) and patches accordingly.
function patchTagsJs(raw) {
  // 4.x: function v(n,t){var c,e;
  const re4x = /function v\(n,t\)\{var c,e;/;
  const m4 = raw.match(re4x);
  if (m4) {
    const injection = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
    const headEnd = m4.index + m4[0].length;
    return { patched: raw.slice(0, headEnd) + injection + raw.slice(headEnd), version: "4.x" };
  }

  // 5.7.0+: look for the main collection entry — return q=function(n,t){
  const re570 = /return q=function\s*\(\s*n\s*,\s*t\s*\)\s*\{/;
  const m5 = raw.match(re570);
  if (m5) {
    // Inject at the start of the q function body
    const bodyStart = m5.index + m5[0].length;
    const injection = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
    return { patched: raw.slice(0, bodyStart) + injection + raw.slice(bodyStart), version: "5.7.0+" };
  }

  return { error: "no known chokepoint pattern found" };
}

// ── Humanlike interaction ───────────────────────────────────
async function wander(page, ms) {
  const end = Date.now() + ms;
  let x = 300 + Math.random() * 500, y = 300 + Math.random() * 300;
  while (Date.now() < end) {
    x = Math.max(50, Math.min(1300, x + (x > 680 ? -1 : 1) * (Math.random() * 40 + 20)));
    y = Math.max(50, Math.min(800, y + (Math.random() - 0.5) * 60));
    await page.mouse.move(x, y, { steps: 6 + Math.floor(Math.random() * 8) });
    await page.waitForTimeout(140 + Math.random() * 220);
  }
}
async function scroll(page, n) {
  for (let i = 0; i < n; i++) {
    await page.mouse.wheel(0, 200 + Math.random() * 400);
    await page.waitForTimeout(500 + Math.random() * 700);
  }
}

// ── Main ────────────────────────────────────────────────────
const userDataDir = mkdtempSync(join(tmpdir(), "dd-bypass-"));
const launchOpts = {
  headless: false,
  channel: "chrome",
  viewport: { width: 1366, height: 900 },
  locale: "en-US",
  timezoneId: "America/Chicago",
};
if (PROXY) launchOpts.proxy = PROXY;

const ctx = await chromium.launchPersistentContext(userDataDir, launchOpts);
await ctx.addInitScript(initScript());

const page = await ctx.newPage();
const network = [];
const consoleMsgs = [];
const capturedPayloads = [];
page.on("console", (m) => consoleMsgs.push(`[${m.type()}] ${m.text()}`));
page.on("response", (resp) => {
  const u = resp.url();
  if (/datadome|captcha-delivery|datado\.me/.test(u)) {
    network.push({ url: u, status: resp.status(), method: resp.request().method() });
  }
});

// Capture interstitial POST body (contains the plaintext payload)
// Do NOT intercept tags.js — route.fetch() makes a second request that DataDome detects
await page.route(/interstitial/, async (route) => {
  const req = route.request();
  if (req.method() === "POST") {
    const postData = req.postData();
    if (postData) {
      console.log(`[capture] interstitial POST: ${postData.length} bytes`);
      capturedPayloads.push({ url: req.url(), body: postData, timestamp: Date.now() });
    }
  }
  await route.continue();
});

// Capture tags.js response for version detection (passive, no second request)
let tagsInfo = null;
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

// Step 0: check exit IP
console.log("\nstep 0: check exit IP");
let ipInfo = "{}";
try {
  await page.goto("https://api.ipify.org?format=json", { timeout: 15000 });
  ipInfo = await page.evaluate(() => document.body.innerText);
  const ip = JSON.parse(ipInfo);
  console.log(`  IP: ${ip.ip}`);
} catch {
  console.log("  (could not determine IP)");
}

// Step 1: warm reputation on target
console.log(`\nstep 1: warm rep on ${TARGET}`);
const r1 = await page.goto(TARGET, { waitUntil: "domcontentloaded", timeout: 30000 });
console.log(`  HTTP ${r1.status()}  title="${(await page.title()).slice(0, 60)}"`);
await wander(page, 2200);
await scroll(page, 3);
await wander(page, 1400);

// Capture datadome cookie if present
const cookies = await ctx.cookies();
const ddCookie1 = cookies.find((c) => c.name === "datadome");
console.log(`  cookie: ${ddCookie1 ? ddCookie1.value.slice(0, 40) + "…" : "(none)"}`);

// Step 2: wait for DD verdict POST
console.log(`\nstep 2: waiting for DataDome verdict...`);
const ddPostPromise = page.waitForResponse(
  (r) => /api-js\.datadome\.co\/js|captcha-delivery\.com/.test(r.url()),
  { timeout: 20000 }
).catch(() => null);

await wander(page, 2000);
await scroll(page, 3);

const ddPost = await ddPostPromise;
if (ddPost) console.log(`  verdict: ${ddPost.url().slice(0, 80)} → HTTP ${ddPost.status()}`);

// Check if page loaded successfully
const finalTitle = await page.title();
const finalUrl = page.url();
const finalHtml = await page.content();
const bodyText = await page.evaluate(() => document.body.innerText.replace(/\s+/g, " "));
const blocked = /you have been blocked/i.test(bodyText) || /verification required/i.test(bodyText);
const solved = !blocked && finalHtml.length > 10000;

// Save artifacts
const slug = TARGET.replace(/^https?:\/\/[^/]+\//, "").replace(/\/+$/, "").replace(/[^a-zA-Z0-9]/g, "_").slice(0, 40) || "target";
writeFileSync(join(OUT, `bypass-${slug}.html`), finalHtml);
await page.screenshot({ path: join(OUT, `bypass-${slug}.png`), fullPage: false });

const dump = await page.evaluate(() => (window.__ddDump ? window.__ddDump() : null));

console.log("\n=== VERDICT ===");
console.log(`  target:      ${TARGET}`);
console.log(`  IP:          ${JSON.parse(ipInfo).ip || "?"}`);
console.log(`  status:      ${r1.status()}`);
console.log(`  finalURL:    ${finalUrl}`);
console.log(`  title:       ${finalTitle}`);
console.log(`  size:        ${finalHtml.length} bytes`);
console.log(`  passed?      ${solved ? "YES ✓" : "NO"}`);
console.log(`  blocked?     ${blocked ? "YES" : "no"}`);
console.log(`  tap signals: ${dump?.tap?.length ?? "?"}`);
console.log(`  self-test:   ${JSON.stringify(dump?.selfTest)}`);
console.log(`  tags:        ${tagsInfo ? `v${tagsInfo.version} (${tagsInfo.size}B)` : "not captured"}`);

const ddCookie2 = (await ctx.cookies()).find((c) => c.name === "datadome");

const verdict = {
  target: TARGET,
  exitIp: JSON.parse(ipInfo).ip,
  initialStatus: r1.status(),
  finalUrl,
  finalTitle,
  bytes: finalHtml.length,
  solved,
  blocked,
  cookieBefore: ddCookie1?.value || null,
  cookieAfter: ddCookie2?.value || null,
  tapLen: dump?.tap?.length ?? null,
  selfTest: dump?.selfTest ?? null,
  tagsInfo,
  capturedAt: new Date().toISOString(),
};
writeFileSync(join(OUT, "bypass.json"), JSON.stringify(verdict, null, 2));

const plaintext = {
  target: TARGET,
  capturedAt: verdict.capturedAt,
  tagsInfo,
  signalCount: dump?.tap?.length ?? 0,
  signals: (dump?.tap || []).map(([name, value, t]) => ({ name, value, t_ms: t })),
};
writeFileSync(join(OUT, "bypass-plaintext.json"), JSON.stringify(plaintext, null, 2));
writeFileSync(join(OUT, "bypass-network.json"), JSON.stringify(network, null, 2));
writeFileSync(join(OUT, "bypass-console.txt"), consoleMsgs.join("\n"));
writeFileSync(join(OUT, "bypass-payloads.json"), JSON.stringify(capturedPayloads, null, 2));

await ctx.close();
console.log(`\n  artifacts → ${OUT}/bypass*`);
