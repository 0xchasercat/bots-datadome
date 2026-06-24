#!/usr/bin/env node
/**
 * bypass.mjs — end-to-end DataDome gate bypass + plaintext payload capture.
 *
 * Pipeline:
 *  1. SOAX mobile proxy creds from ~/Dev/soax.txt (or $SOAX_CONFIG).
 *  2. Real Chrome (channel:'chrome', headed) launched through the proxy.
 *  3. Phase-1: invisible Proxy wraps on JSON.stringify / btoa (init script).
 *  4. Phase-4: in-flight patch on https://js.datadome.co/tags.js — inject
 *     try{(window.__ddTap=...).push([n,t,perf])}catch(_){} at the entry of
 *     `function v(n,t){var c,e;`. +82 bytes, the bundle still runs.
 *  5. Warm reputation on /blog/ (not DD-gated) with humanlike mouse/scroll.
 *  6. Click-through to a /threat-research/ article.
 *  7. Wait for the JS tag's POST to api-js.datadome.co/js/.
 *  8. Dump HTML + plaintext payload + verdict + screenshot + network log.
 *
 * Expected on clean mobile IP: HTTP 200 invisible-pass, ~200 signals.
 */

import { chromium } from "playwright";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

// ── SOAX creds ──────────────────────────────────────────────
const SOAX_PATH = process.env.SOAX_CONFIG || join(homedir(), "Dev", "soax.txt");
if (!existsSync(SOAX_PATH)) {
  console.error(`[bypass] no SOAX config at ${SOAX_PATH} — set $SOAX_CONFIG or create the file`);
  console.error(`         expected format: one line per pool, e.g.`);
  console.error(`         MOBILE: curl -k -x package-X-sessionid-Y-sessionlength-300:PASS@proxy.soax.com:5000 -L URL`);
  process.exit(1);
}
const SOAX = readFileSync(SOAX_PATH, "utf8");
const mobileLine = SOAX.split("\n").find((l) => l.startsWith("MOBILE:"));
if (!mobileLine) {
  console.error(`[bypass] no MOBILE: line in ${SOAX_PATH}`);
  process.exit(1);
}
const m = mobileLine.match(/-x (\S+):(\S+)@(\S+):(\d+)/);
const PROXY = {
  server: `http://${m[3]}:${m[4]}`,
  username: m[1],
  password: m[2],
};
console.log(`[soax] ${PROXY.server}  user=${PROXY.username.slice(0, 24)}…`);

// ── Target article ───────────────────────────────────────────
const TARGET = process.argv[2] ||
  "https://datadome.co/threat-research/inside-kimwolf-traffic-residential-proxies-fuel-credential-stuffing-web-scraping-fraud/";

// ── Phase-1 init script ─────────────────────────────────────
function initScript() {
  return `(() => {
    if (window.__ddInitInstalled) return;
    window.__ddInitInstalled = true;
    window.__ddTap = [];
    const wrap = (orig) => new Proxy(orig, { apply: (t, th, a) => Reflect.apply(t, th, a) });
    try { JSON.stringify = wrap(JSON.stringify); } catch {}
    try { window.btoa = wrap(window.btoa); } catch {}
    window.__ddSelfTest = () => ({
      jsonStringifyNative: Function.prototype.toString.call(JSON.stringify).includes("[native code]"),
      btoaNative: Function.prototype.toString.call(window.btoa).includes("[native code]"),
    });
    window.__ddDump = () => ({
      tap: window.__ddTap || [],
      selfTest: typeof window.__ddSelfTest === "function" ? window.__ddSelfTest() : null,
    });
  })();`;
}

// ── Phase-4 bundle patch ────────────────────────────────────
function patchTagsJs(raw) {
  const re = /function v\(n,t\)\{var c,e;/;
  const m = raw.match(re);
  if (!m) return { error: "v(n,t) header not found" };
  const injection = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
  const headEnd = m.index + m[0].length;
  return { patched: raw.slice(0, headEnd) + injection + raw.slice(headEnd) };
}

// ── Humanlike interaction ───────────────────────────────────
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
    await page.waitForTimeout(500 + Math.random() * 700);
  }
}

// ── Main ────────────────────────────────────────────────────
const userDataDir = mkdtempSync(join(tmpdir(), "dd-bypass-"));
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

let patchInfo = { patched: false };
await ctx.route(/https:\/\/js\.datadome\.co\/tags\.js/, async (route) => {
  try {
    const resp = await route.fetch();
    const raw = (await resp.body()).toString("utf8");
    const r = patchTagsJs(raw);
    if (r.error) {
      patchInfo = { patched: false, error: r.error, len: raw.length };
      console.log(`[patch] FAILED: ${r.error} — bundle may have changed; re-run recon.mjs`);
      await route.fulfill({ response: resp, body: raw });
    } else {
      patchInfo = { patched: true, rawLen: raw.length, patchedLen: r.patched.length };
      console.log(`[patch] tags.js  ${raw.length}B → ${r.patched.length}B`);
      await route.fulfill({
        status: resp.status(),
        headers: resp.headers(),
        contentType: resp.headers()["content-type"] || "application/javascript",
        body: r.patched,
      });
    }
  } catch (e) {
    console.log(`[patch] error: ${e.message}`);
    try { await route.continue(); } catch {}
  }
});

const page = await ctx.newPage();
const network = [];
const consoleMsgs = [];
page.on("console", (m) => consoleMsgs.push(`[${m.type()}] ${m.text()}`));
page.on("response", (resp) => {
  const u = resp.url();
  if (/datadome|captcha-delivery|datado\.me/.test(u)) {
    network.push({ url: u, status: resp.status(), method: resp.request().method() });
  }
});

console.log("\nstep 0: smoke check exit IP");
await page.goto("https://checker.soax.com/api/ipinfo", { timeout: 30000 });
const ipInfo = await page.evaluate(() => document.body.innerText);
console.log("  " + ipInfo.slice(0, 200));

console.log("\nstep 1: warm rep on /blog/");
const r1 = await page.goto("https://www.g2.com/products/playwright/reviews", { waitUntil: "domcontentloaded", timeout: 30000 });
console.log(`  HTTP ${r1.status()}  title="${(await page.title()).slice(0, 50)}"`);
await wander(page, 2200);
await scroll(page, 3);
await wander(page, 1400);

const ddCookie1 = (await ctx.cookies("https://datadome.co/")).find((c) => c.name === "datadome");
console.log(`  cookie after warm-up: ${ddCookie1 ? ddCookie1.value.slice(0, 40) + "…" : "(none)"}`);

console.log(`\nstep 2: navigate to article ${TARGET}`);
const ddPostPromise = page.waitForResponse(
  (r) => /api-js\.datadome\.co\/js/.test(r.url()),
  { timeout: 25000 }
).catch(() => null);

const r2 = await page.goto(TARGET, { waitUntil: "domcontentloaded", timeout: 45000 });
console.log(`  initial HTTP ${r2.status()}  title="${(await page.title()).slice(0, 60)}"`);

await wander(page, 1500);
const ddPost = await ddPostPromise;
if (ddPost) console.log(`  JS tag POST: ${ddPost.url()} → HTTP ${ddPost.status()}`);

await wander(page, 1500);
await scroll(page, 4);

let solved = false;
try {
  await page.waitForFunction(() => {
    const t = document.title.toLowerCase();
    if (t === "datadome.co" || t.includes("blocked")) return false;
    const h1 = document.querySelector("h1");
    return h1 && h1.innerText.length > 12;
  }, { timeout: 12000 });
  solved = true;
} catch {}

const finalTitle = await page.title();
const finalUrl = page.url();
const finalHtml = await page.content();
const bodyText = await page.evaluate(() => document.body.innerText.replace(/\s+/g, " "));
const articleH1 = await page.evaluate(() => document.querySelector("h1")?.innerText || "");
const blocked = /you have been blocked/i.test(bodyText) || /please enable js/i.test(bodyText);

const slug = TARGET.replace(/^https?:\/\/[^/]+\//, "").replace(/\/+$/, "").replace(/\//g, "_") || "article";
writeFileSync(join(OUT, `bypass-${slug}.html`), finalHtml);
await page.screenshot({ path: join(OUT, `bypass-${slug}.png`), fullPage: false });

const dump = await page.evaluate(() => (window.__ddDump ? window.__ddDump() : null));

console.log("\n=== VERDICT ===");
console.log(`  exit IP:     ${ipInfo.match(/"ip":"([^"]+)"/)?.[1] || "?"}`);
console.log(`  carrier:     ${ipInfo.match(/"carrier":"([^"]+)"/)?.[1] || "?"}`);
console.log(`  status:      ${r2.status()}`);
console.log(`  finalURL:    ${finalUrl}`);
console.log(`  title:       ${finalTitle}`);
console.log(`  h1:          ${articleH1.slice(0, 80)}`);
console.log(`  size:        ${finalHtml.length} bytes`);
console.log(`  solved?      ${solved ? "YES ✓" : "NO"}`);
console.log(`  blocked?     ${blocked ? "YES" : "no"}`);
console.log(`  tap signals: ${dump?.tap?.length ?? "?"}`);
console.log(`  self-test:   ${JSON.stringify(dump?.selfTest)}`);

const ddCookie2 = (await ctx.cookies("https://datadome.co/")).find((c) => c.name === "datadome");

const verdict = {
  target: TARGET,
  exitIp: ipInfo.match(/"ip":"([^"]+)"/)?.[1],
  carrier: ipInfo.match(/"carrier":"([^"]+)"/)?.[1],
  initialStatus: r2.status(),
  finalUrl,
  finalTitle,
  articleH1,
  bytes: finalHtml.length,
  solved,
  blocked,
  cookieBeforeNav: ddCookie1?.value || null,
  cookieAfterNav: ddCookie2?.value || null,
  tapLen: dump?.tap?.length ?? null,
  selfTest: dump?.selfTest ?? null,
  patchInfo,
  capturedAt: new Date().toISOString(),
};
writeFileSync(join(OUT, "bypass.json"), JSON.stringify(verdict, null, 2));

const plaintext = {
  target: TARGET,
  capturedAt: verdict.capturedAt,
  bundleVersion: "5.6.6",
  chokepoint: "v(n,t) at tags.beautified.js:2127",
  signalCount: dump?.tap?.length ?? 0,
  signals: (dump?.tap || []).map(([name, value, t]) => ({ name, value, t_ms: t })),
};
writeFileSync(join(OUT, "bypass-plaintext.json"), JSON.stringify(plaintext, null, 2));
writeFileSync(join(OUT, "bypass-network.json"), JSON.stringify(network, null, 2));
writeFileSync(join(OUT, "bypass-console.txt"), consoleMsgs.join("\n"));

await ctx.close();
console.log(`\n  artifacts → ${OUT}/bypass*`);
