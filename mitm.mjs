#!/usr/bin/env node
/**
 * mitm.mjs — generic MITM capture for DataDome's tag.
 *
 * Same Phase-1 native hooks + Phase-4 v(n,t) bundle patch as bypass.mjs,
 * but without the SOAX proxy + warm-up + article click-through. Use this
 * for a quick local capture when you already have a clean IP, or to
 * compare a direct-network run against a proxied run for the diff.mjs.
 *
 * Usage: node mitm.mjs [target-url]
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

function patchTagsJs(raw) {
  const re = /function v\(n,t\)\{var c,e;/;
  const m = raw.match(re);
  if (!m) return { error: "v(n,t) header not found — bundle may have changed; re-run recon.mjs" };
  const injection = `try{(window.__ddTap=window.__ddTap||[]).push([n,t,performance.now()|0])}catch(_){}`;
  const headEnd = m.index + m[0].length;
  return { patched: raw.slice(0, headEnd) + injection + raw.slice(headEnd) };
}

const userDataDir = mkdtempSync(join(tmpdir(), "dd-mitm-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
  args: ["--disable-blink-features=AutomationControlled"],
  viewport: { width: 1366, height: 900 },
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
      console.log(`[patch] FAILED: ${r.error}`);
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

console.log(`mitm: loading ${TARGET}`);
const r = await page.goto(TARGET, { waitUntil: "load", timeout: 45000 }).catch((e) => ({ status: () => "err" }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

await page.waitForTimeout(7000);
try { await page.mouse.move(420, 300, { steps: 5 }); } catch {}
await page.waitForTimeout(3000);

const dump = await page.evaluate(() => (window.__ddDump ? window.__ddDump() : null));

console.log("\n=== RESULT ===");
console.log(`  patch:       ${patchInfo.patched ? `OK (+${patchInfo.patchedLen - patchInfo.rawLen}B)` : "FAILED"}`);
console.log(`  self-test:   ${JSON.stringify(dump?.selfTest)}`);
console.log(`  tap signals: ${dump?.tap?.length ?? "?"}`);

writeFileSync(join(OUT, "mitm.json"), JSON.stringify({
  target: TARGET,
  status: r.status?.() ?? null,
  patchInfo,
  selfTest: dump?.selfTest,
  signalCount: dump?.tap?.length ?? 0,
  signals: (dump?.tap || []).map(([name, value, t]) => ({ name, value, t_ms: t })),
  capturedAt: new Date().toISOString(),
}, null, 2));

await ctx.close();
console.log(`\n  artifacts → ${OUT}/mitm.json`);
