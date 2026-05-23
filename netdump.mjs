#!/usr/bin/env node
/**
 * netdump.mjs — full network log of DataDome traffic on a target.
 *
 * Captures every request/response touching:
 *   - datadome.co
 *   - captcha-delivery.com
 *   - datado.me
 *   - api-js.datadome.co
 *
 * Body capture for *.datadome.co + captcha-delivery.com only (we don't
 * grab the target site's main-page HTML).
 *
 * Saves to results/netdump.json (the index) and results/netdump-bodies/.
 *
 * Usage: node netdump.mjs [target-url]
 *   default target: https://datadome.co/blog/
 */

import { chromium } from "playwright";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
const BODIES = join(OUT, "netdump-bodies");
mkdirSync(OUT, { recursive: true });
mkdirSync(BODIES, { recursive: true });

const TARGET = process.argv[2] || "https://datadome.co/blog/";

const DD_HOST_RE = /datadome\.co|captcha-delivery\.com|datado\.me/;

const userDataDir = mkdtempSync(join(tmpdir(), "dd-netdump-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
  viewport: { width: 1366, height: 900 },
});
const page = await ctx.newPage();

let seq = 0;
const events = [];

page.on("request", (req) => {
  if (!DD_HOST_RE.test(req.url())) return;
  events.push({
    id: ++seq,
    phase: "request",
    url: req.url(),
    method: req.method(),
    headers: req.headers(),
    postData: req.postData() || null,
    ts: Date.now(),
  });
});

page.on("response", async (resp) => {
  const u = resp.url();
  if (!DD_HOST_RE.test(u)) return;
  const id = ++seq;
  const evt = {
    id,
    phase: "response",
    url: u,
    status: resp.status(),
    headers: resp.headers(),
    ts: Date.now(),
    bodyFile: null,
  };
  try {
    const body = await resp.body();
    const ext = /javascript|json/.test(resp.headers()["content-type"] || "")
      ? (/json/.test(resp.headers()["content-type"] || "") ? "json" : "js")
      : "bin";
    const filename = `${id}-${resp.status()}-${u.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9.]/g, "_").slice(0, 80)}.${ext}`;
    writeFileSync(join(BODIES, filename), body);
    evt.bodyFile = filename;
    evt.bodyBytes = body.length;
  } catch (e) {
    evt.bodyError = e.message;
  }
  events.push(evt);
});

console.log(`netdump: loading ${TARGET}`);
const r = await page.goto(TARGET, { waitUntil: "load", timeout: 45000 }).catch((e) => ({ status: () => "err" }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

await page.waitForTimeout(7000);

// Snapshot cookies + the page HTML for context.
const cookies = await ctx.cookies(TARGET);
const ddCookie = cookies.find((c) => c.name === "datadome");

const summary = {
  target: TARGET,
  status: r.status?.() ?? null,
  title: await page.title(),
  eventCount: events.length,
  events,
  cookies: cookies.filter((c) => c.domain.includes("datadome")),
  ddCookie: ddCookie?.value || null,
  capturedAt: new Date().toISOString(),
};

writeFileSync(join(OUT, "netdump.json"), JSON.stringify(summary, null, 2));

console.log(`\n  total DD events:  ${events.length}`);
console.log(`  bodies captured:  ${events.filter((e) => e.bodyFile).length}`);
console.log(`  datadome cookie:  ${ddCookie ? ddCookie.value.slice(0, 32) + "…" : "(none)"}`);

// Highlight the api-js POST if present
const apiPost = events.find((e) => e.phase === "request" && /api-js\.datadome\.co\/js/.test(e.url) && e.method === "POST");
if (apiPost) {
  console.log(`\n  api-js POST detected:`);
  console.log(`    url:       ${apiPost.url}`);
  console.log(`    body size: ${apiPost.postData?.length ?? 0} bytes`);
  console.log(`    body[..200]: ${(apiPost.postData || "").slice(0, 200)}`);
}

await ctx.close();
console.log(`\n  artifacts → ${OUT}/netdump.json + ${BODIES}/`);
