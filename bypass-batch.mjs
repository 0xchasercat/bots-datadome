#!/usr/bin/env node
/**
 * bypass-batch.mjs — multi-article POC. Pull N DataDome-gated pages in
 * one run through a single browser session.
 *
 * Pipeline (reuses bypass.mjs's logic, batched):
 *  1. Launch Chrome (headed) — direct or through $PROXY if set.
 *  2. Phase-1 + Phase-4 MITM hooks installed.
 *  3. Visit target to warm reputation and harvest URLs.
 *  4. For each of the first N URLs, navigate, wait for solve,
 *     capture HTML + plaintext payload + verdict.
 *  5. Write per-page files + a batch summary.
 *
 * Usage:
 *   node bypass-batch.mjs [N]                          # direct, default 5
 *   node bypass-batch.mjs 10 https://target.com        # custom count + URL
 *   PROXY=socks5://user:pass@host:port node bypass-batch.mjs  # via proxy
 */

import { chromium } from "patchright";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results", "batch");
mkdirSync(OUT, { recursive: true });

// ── Parse args ──────────────────────────────────────────────
const args = process.argv.slice(2).filter(a => !a.includes("="));
let N = 5;
let baseUrl = "https://www.g2.com/products/playwright/reviews";

for (const arg of args) {
  if (/^\d+$/.test(arg)) {
    N = Math.min(15, parseInt(arg));
  } else if (arg.startsWith("http")) {
    baseUrl = arg;
  }
}

// ── Proxy config ────────────────────────────────────────────
function parseProxy(proxyStr) {
  if (!proxyStr) return undefined;
  try {
    const url = new URL(proxyStr);
    const proxy = { server: `${url.protocol}//${url.hostname}:${url.port}` };
    if (url.username) proxy.username = decodeURIComponent(url.username);
    if (url.password) proxy.password = decodeURIComponent(url.password);
    return proxy;
  } catch (e) {
    console.error(`[proxy] invalid PROXY: ${proxyStr}`);
    process.exit(1);
  }
}

const PROXY = parseProxy(process.env.PROXY);
if (PROXY) {
  console.log(`[proxy] ${PROXY.server}  user=${PROXY.username ? PROXY.username.slice(0, 20) + "…" : "(none)"}`);
} else {
  console.log(`[proxy] none — connecting directly`);
}

console.log(`[batch] target: ${N} pages from ${baseUrl}\n`);

// ── Init script + tag patch ────────────────────────────────
function initScript() {
  return `(() => {
    if (window.__ddInitInstalled) return;
    window.__ddInitInstalled = true;
    window.__ddTap = [];
    window.__ddResetTap = () => { window.__ddTap = []; };
    window.__ddDump = () => ({ tap: window.__ddTap || [] });
  })();`;
}

function patchTagsJs(raw) {
  // 4.x
  const re4x = /function v\(n,t\)\{var c,e;/;
  const m4 = raw.match(re4x);
  if (m4) {
    const inj = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
    const end = m4.index + m4[0].length;
    return { patched: raw.slice(0, end) + inj + raw.slice(end), version: "4.x" };
  }
  // 5.7.0+
  const re570 = /return q=function\s*\(\s*n\s*,\s*t\s*\)\s*\{/;
  const m5 = raw.match(re570);
  if (m5) {
    const inj = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
    const end = m5.index + m5[0].length;
    return { patched: raw.slice(0, end) + inj + raw.slice(end), version: "5.7.0+" };
  }
  return { error: "no known chokepoint found" };
}

async function wander(page, ms) {
  const end = Date.now() + ms;
  let x = 300 + Math.random() * 500, y = 300 + Math.random() * 300;
  while (Date.now() < end) {
    x = Math.max(50, Math.min(1300, x + (Math.random() - 0.5) * 80));
    y = Math.max(50, Math.min(800, y + (Math.random() - 0.5) * 60));
    await page.mouse.move(x, y, { steps: 6 + Math.floor(Math.random() * 8) });
    await page.waitForTimeout(140 + Math.random() * 220);
  }
}
async function scroll(page, n) {
  for (let i = 0; i < n; i++) {
    await page.mouse.wheel(0, 200 + Math.random() * 400);
    await page.waitForTimeout(400 + Math.random() * 600);
  }
}

// ── Main ────────────────────────────────────────────────────
const userDataDir = mkdtempSync(join(tmpdir(), "dd-batch-"));
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

// Capture tags.js response passively (no interception)
let lastTagsInfo = null;
page.on("response", async (resp) => {
  if (/tags\.js/.test(resp.url())) {
    try {
      const body = (await resp.body()).toString("utf8");
      const versionMatch = body.match(/version\s+(\d+\.\d+\.\d+)/i);
      lastTagsInfo = { url: resp.url(), size: body.length, version: versionMatch?.[1] || "unknown" };
    } catch {}
  }
});

// Check exit IP
let exitIp = "?";
try {
  await page.goto("https://api.ipify.org?format=json", { timeout: 15000 });
  exitIp = (await page.evaluate(() => document.body.innerText)).replace(/"/g, "");
  console.log(`[batch] exit IP: ${exitIp}`);
} catch {
  console.log(`[batch] could not determine IP`);
}

// Harvest links from base URL
console.log(`[batch] loading ${baseUrl} to harvest links`);
await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
await wander(page, 1500);
await scroll(page, 3);

const links = await page.$$eval("a[href]", (as) =>
  [...new Set(as.map((a) => a.href).filter((h) => h.startsWith("http")))]
);
console.log(`[batch] found ${links.length} links; taking first ${N}`);

const targets = links.slice(0, N);
targets.forEach((u, i) => console.log(`    ${i + 1}. ${u}`));

const summary = {
  exitIp,
  baseUrl,
  started: new Date().toISOString(),
  patchInfo: null,
  pages: [],
};

for (let i = 0; i < targets.length; i++) {
  const url = targets[i];
  const slug = url.replace(/^https?:\/\/[^/]+\//, "").replace(/\/+$/, "").replace(/[^a-zA-Z0-9]/g, "_").slice(0, 40) || `page_${i}`;
  const tag = `[${i + 1}/${targets.length}]`;
  console.log(`\n${tag} ${url}`);

  await page.evaluate(() => window.__ddResetTap?.());

  const ddPostPromise = page.waitForResponse(
    (r) => /api-js\.datadome\.co\/js|captcha-delivery\.com/.test(r.url()),
    { timeout: 20000 }
  ).catch(() => null);

  let r;
  try {
    r = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
  } catch (e) {
    console.log(`  nav error: ${e.message}`);
    summary.pages.push({ url, slug, error: e.message });
    continue;
  }
  console.log(`  HTTP ${r.status()}`);

  await wander(page, 1200);
  const ddPost = await ddPostPromise;
  if (ddPost) console.log(`  DD POST: ${ddPost.status()}`);
  await wander(page, 1000);
  await scroll(page, 2);

  const finalTitle = await page.title();
  const finalHtml = await page.content();
  const bodyText = await page.evaluate(() => document.body.innerText.replace(/\s+/g, " "));
  const blocked = /you have been blocked/i.test(bodyText) || /verification required/i.test(bodyText);
  const solved = !blocked && finalHtml.length > 10000;

  writeFileSync(join(OUT, `${slug}.html`), finalHtml);
  const dump = await page.evaluate(() => window.__ddDump ? window.__ddDump() : { tap: [] });
  writeFileSync(join(OUT, `${slug}.plaintext.json`), JSON.stringify({
    target: url, capturedAt: new Date().toISOString(),
    signalCount: dump.tap.length,
    signals: dump.tap.map(([name, value, t]) => ({ name, value, t_ms: t })),
  }, null, 2));

  const verdict = {
    url, slug,
    status: r.status(), finalTitle,
    bytes: finalHtml.length,
    solved, blocked,
    signalCount: dump.tap.length,
  };
  summary.pages.push(verdict);
  summary.tagsInfo = lastTagsInfo;
  console.log(`  ${solved ? "✓" : "✗"}  ${finalHtml.length}B  signals=${dump.tap.length}  "${finalTitle.slice(0, 60)}"`);

  await page.waitForTimeout(2000 + Math.random() * 2000);
}

summary.finished = new Date().toISOString();
summary.totalPassed = summary.pages.filter((p) => p.solved).length;

writeFileSync(join(OUT, "summary.json"), JSON.stringify(summary, null, 2));

console.log(`\n=== BATCH SUMMARY ===`);
console.log(`  exit IP:        ${exitIp}`);
console.log(`  tags:           ${summary.tagsInfo ? `v${summary.tagsInfo.version}` : "not captured"}`);
console.log(`  pages requested: ${targets.length}`);
console.log(`  pages passed:    ${summary.totalPassed} ✓ / ${targets.length - summary.totalPassed} blocked`);
console.log(`\n  artifacts → ${OUT}/`);

await ctx.close();
