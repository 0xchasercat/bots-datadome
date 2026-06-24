#!/usr/bin/env node
/**
 * bypass-batch.mjs — multi-article POC. Pull N DataDome-gated articles in
 * one run through a single SOAX mobile session.
 *
 * Pipeline (reuses bypass.mjs's logic, batched):
 *  1. SOAX mobile creds from ~/Dev/soax.txt (or $SOAX_CONFIG).
 *  2. Single persistent real-Chrome context through the proxy.
 *  3. Phase-1 + Phase-4 MITM hooks installed.
 *  4. Visit /blog/ to warm reputation and harvest article URLs.
 *  5. For each of the first N article URLs, navigate, wait for solve,
 *     capture HTML + plaintext payload + verdict.
 *  6. Write per-article files + a batch summary.
 *
 * Usage: node bypass-batch.mjs [N]    (default N=5; max 15)
 *
 * Pace: ~30-60 sec per article including humanlike behavior. Respects
 * SOAX session length (300s mobile) — if you ask for many articles
 * you may exceed it; the script will keep going through any
 * intermediate failures.
 */

import { chromium } from "playwright";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results", "batch");
mkdirSync(OUT, { recursive: true });

const N = Math.min(15, parseInt(process.argv[2] || "5"));

// ── SOAX ──────────────────────────────────────────────────
const SOAX_PATH = process.env.SOAX_CONFIG || join(homedir(), "Dev", "soax.txt");
if (!existsSync(SOAX_PATH)) {
  console.error(`[batch] no SOAX config at ${SOAX_PATH}`);
  process.exit(1);
}
const SOAX = readFileSync(SOAX_PATH, "utf8");
const mobileLine = SOAX.split("\n").find((l) => l.startsWith("MOBILE:"));
const m = mobileLine.match(/-x (\S+):(\S+)@(\S+):(\d+)/);
const PROXY = { server: `http://${m[3]}:${m[4]}`, username: m[1], password: m[2] };
console.log(`[soax] ${PROXY.server}  user=${PROXY.username.slice(0, 24)}…`);
console.log(`[batch] target: ${N} articles\n`);

// ── Init script + tag patch (same as bypass.mjs) ─────────
function initScript() {
  return `(() => {
    if (window.__ddInitInstalled) return;
    window.__ddInitInstalled = true;
    window.__ddTap = [];
    window.__ddResetTap = () => { window.__ddTap = []; };
    const wrap = (orig) => new Proxy(orig, { apply: (t, th, a) => Reflect.apply(t, th, a) });
    try { JSON.stringify = wrap(JSON.stringify); } catch {}
    try { window.btoa = wrap(window.btoa); } catch {}
    window.__ddDump = () => ({ tap: window.__ddTap || [] });
  })();`;
}

function patchTagsJs(raw) {
  const re = /function v\(n,t\)\{var c,e;/;
  const m = raw.match(re);
  if (!m) return { error: "v(n,t) header not found" };
  const inj = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
  const end = m.index + m[0].length;
  return { patched: raw.slice(0, end) + inj + raw.slice(end) };
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

// ── Main ──────────────────────────────────────────────────
const userDataDir = mkdtempSync(join(tmpdir(), "dd-batch-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
  args: ["--disable-blink-features=AutomationControlled"],
  viewport: { width: 1366, height: 900 },
  locale: "en-US",
  timezoneId: "America/Chicago",
  proxy: PROXY,
});
await ctx.addInitScript(initScript());

let lastPatch = { patched: false };
await ctx.route(/https:\/\/js\.datadome\.co\/tags\.js/, async (route) => {
  try {
    const resp = await route.fetch();
    const raw = (await resp.body()).toString("utf8");
    const r = patchTagsJs(raw);
    if (r.error) {
      lastPatch = { patched: false, error: r.error };
      await route.fulfill({ response: resp, body: raw });
    } else {
      lastPatch = { patched: true, delta: r.patched.length - raw.length };
      await route.fulfill({
        status: resp.status(),
        headers: resp.headers(),
        contentType: resp.headers()["content-type"] || "application/javascript",
        body: r.patched,
      });
    }
  } catch {
    try { await route.continue(); } catch {}
  }
});

const page = await ctx.newPage();

// Smoke check
await page.goto("https://checker.soax.com/api/ipinfo", { timeout: 30000 });
const ipInfo = await page.evaluate(() => document.body.innerText);
const exitIp = ipInfo.match(/"ip":"([^"]+)"/)?.[1];
const carrier = ipInfo.match(/"carrier":"([^"]+)"/)?.[1];
console.log(`[batch] exit: ${exitIp} (${carrier})`);

// Harvest article URLs from /blog/
console.log(`[batch] loading /blog/ to harvest URLs`);
await page.goto("https://www.g2.com/products/playwright/reviews", { waitUntil: "domcontentloaded", timeout: 30000 });
await wander(page, 1500);
await scroll(page, 3);

const articleUrls = await page.$$eval(
  'a[href*="datadome.co/"]',
  (as) => [...new Set(
    as.map((a) => a.href)
      .filter((h) => /datadome\.co\/(threat-research|learning-center|bot-management-protection|agent-trust-management|guides)\/[a-z0-9-]+\/?$/.test(h))
  )]
);
console.log(`[batch] found ${articleUrls.length} candidate URLs; taking first ${N}`);

if (articleUrls.length < N) {
  console.log(`[batch] only ${articleUrls.length} URLs found; continuing with what we have`);
}

const targets = articleUrls.slice(0, N);
targets.forEach((u, i) => console.log(`    ${i + 1}. ${u}`));

const summary = {
  exitIp, carrier,
  started: new Date().toISOString(),
  patchInfo: null,
  articles: [],
};

for (let i = 0; i < targets.length; i++) {
  const url = targets[i];
  const slug = url.replace(/^https?:\/\/[^/]+\//, "").replace(/\/+$/, "").replace(/\//g, "_");
  const tag = `[${i + 1}/${targets.length}]`;
  console.log(`\n${tag} ${url}`);

  // Reset the tap so each article's plaintext is isolated
  await page.evaluate(() => window.__ddResetTap?.());

  const ddPostPromise = page.waitForResponse(
    (r) => /api-js\.datadome\.co\/js/.test(r.url()),
    { timeout: 25000 }
  ).catch(() => null);

  let r;
  try {
    r = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
  } catch (e) {
    console.log(`  ${tag} nav error: ${e.message}`);
    summary.articles.push({ url, slug, error: e.message });
    continue;
  }
  console.log(`  ${tag} initial HTTP ${r.status()}`);

  await wander(page, 1200);
  const ddPost = await ddPostPromise;
  if (ddPost) console.log(`  ${tag} JS POST: ${ddPost.status()}`);
  await wander(page, 1000);
  await scroll(page, 2);

  let solved = false;
  try {
    await page.waitForFunction(() => {
      const t = document.title.toLowerCase();
      if (t === "datadome.co" || t.includes("blocked")) return false;
      const h1 = document.querySelector("h1");
      return h1 && h1.innerText.length > 12;
    }, { timeout: 10000 });
    solved = true;
  } catch {}

  const finalTitle = await page.title();
  const finalHtml = await page.content();
  const articleH1 = await page.evaluate(() => document.querySelector("h1")?.innerText || "");
  const bodyText = await page.evaluate(() => document.body.innerText.replace(/\s+/g, " "));
  const blocked = /you have been blocked/i.test(bodyText);

  writeFileSync(join(OUT, `${slug}.html`), finalHtml);
  const dump = await page.evaluate(() => window.__ddDump ? window.__ddDump() : { tap: [] });
  writeFileSync(join(OUT, `${slug}.plaintext.json`), JSON.stringify({
    target: url, capturedAt: new Date().toISOString(),
    signalCount: dump.tap.length,
    signals: dump.tap.map(([name, value, t]) => ({ name, value, t_ms: t })),
  }, null, 2));

  const verdict = {
    url, slug,
    status: r.status(), finalTitle, articleH1,
    bytes: finalHtml.length,
    solved, blocked,
    signalCount: dump.tap.length,
  };
  summary.articles.push(verdict);
  summary.patchInfo = lastPatch;
  console.log(`  ${tag} ${solved ? "✓" : "✗"}  ${finalHtml.length}B  signals=${dump.tap.length}  "${articleH1.slice(0, 60)}"`);

  // Pause between articles to look human and stay under rate limits
  await page.waitForTimeout(2000 + Math.random() * 2000);
}

summary.finished = new Date().toISOString();
summary.totalFetched = summary.articles.filter((a) => a.solved).length;

writeFileSync(join(OUT, "summary.json"), JSON.stringify(summary, null, 2));

console.log(`\n=== BATCH SUMMARY ===`);
console.log(`  exit IP / carrier:  ${exitIp} / ${carrier}`);
console.log(`  patch:              ${summary.patchInfo?.patched ? "OK" : "FAILED"}`);
console.log(`  articles requested: ${targets.length}`);
console.log(`  articles fetched:   ${summary.totalFetched} ✓ / ${targets.length - summary.totalFetched} blocked`);
console.log(`\n  artifacts → ${OUT}/`);

await ctx.close();
