#!/usr/bin/env node
/**
 * tamper.mjs — verify DataDome's signed-envelope architecture.
 *
 * When DataDome serves a 403 challenge page, the inline <script> contains
 * an object like:
 *   var dd = { 'rt':'c', 't':'fe', 's':44330, 'e':'...HEX64...', 'cookie':'...', 'host':'geo.captcha-delivery.com', 'hash':'...DDJSKEY...' };
 * Then loads an <iframe src="https://geo.captcha-delivery.com/captcha/?...&t=fe&...&e=...&s=...&...">.
 *
 * The 'e' field is a 256-bit HMAC over (at least) t/s/cid/hash. If the
 * client flips t='fe' to t='d' without re-signing e, the captcha endpoint
 * detects the tamper.
 *
 * We test by fetching the challenge page (or accepting one as input),
 * extracting the iframe URL, and issuing two requests:
 *   1. original t=fe
 *   2. tampered t=d (same e)
 * If both return identical bytes → tamper caught (or you're not flagged).
 *
 * Usage: node tamper.mjs [challenge-html-path]
 *   no arg: tries to trigger a fresh challenge by hammering /threat-research/
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

async function fetchChallenge() {
  // Try to provoke a 403 challenge from a likely-gated path. If we're
  // already flagged, this returns the challenge HTML directly.
  const url = "https://datadome.co/threat-research/how-datadome-stopped-a-2-billion-request-ddos-attack/";
  const resp = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
      "Accept": "text/html",
    },
  });
  const body = await resp.text();
  return { status: resp.status, body };
}

let challengeHtml;
const arg = process.argv[2];
if (arg && existsSync(arg)) {
  challengeHtml = readFileSync(arg, "utf8");
  console.log(`tamper: loaded challenge HTML from ${arg}`);
} else {
  console.log("tamper: requesting a fresh challenge from datadome.co");
  const r = await fetchChallenge();
  console.log(`  HTTP ${r.status}  ${r.body.length} bytes`);
  if (r.status !== 403 || !/datadome|captcha/i.test(r.body)) {
    console.log("  → did NOT get a challenge page. Your IP isn't flagged.");
    console.log("    Pass a saved challenge HTML as the first arg, or run from a flagged IP.");
    process.exit(0);
  }
  challengeHtml = r.body;
}

const iframeMatch = challengeHtml.match(/https:\/\/geo\.captcha-delivery\.com\/captcha\/\?[^"]+/);
if (!iframeMatch) {
  console.log("tamper: no captcha iframe URL found — input may not be a DD challenge page");
  process.exit(1);
}
const original = iframeMatch[0].replace(/&amp;/g, "&");
const t_match = original.match(/[?&]t=([^&]+)/);
const e_match = original.match(/[?&]e=([0-9a-f]{64})/);
const s_match = original.match(/[?&]s=(\d+)/);

if (!t_match || !e_match) {
  console.log("tamper: required envelope fields t/e missing from iframe URL");
  process.exit(1);
}
console.log(`\nenvelope:`);
console.log(`  t = ${t_match[1]}`);
console.log(`  s = ${s_match?.[1] ?? "(absent)"}`);
console.log(`  e = ${e_match[1].slice(0, 16)}…${e_match[1].slice(-16)} (256-bit HMAC)`);

const tampered = original.replace(/([?&]t=)[^&]+/, "$1d");
console.log(`\noriginal URL:\n  ${original.slice(0, 200)}…`);
console.log(`tampered URL (t=${t_match[1]} → t=d):\n  ${tampered.slice(0, 200)}…`);

console.log(`\n=== probing both ===`);
const referer = "https://datadome.co/threat-research/";
const headers = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
  "Referer": referer,
};

const a = await fetch(original, { headers });
const aBody = await a.text();
const b = await fetch(tampered, { headers });
const bBody = await b.text();

const aTitle = aBody.match(/<title>([^<]+)<\/title>/)?.[1] || "(no title)";
const bTitle = bBody.match(/<title>([^<]+)<\/title>/)?.[1] || "(no title)";
const identical = aBody === bBody;

console.log(`\n  original:  HTTP ${a.status}  ${aBody.length}B  title="${aTitle}"`);
console.log(`  tampered:  HTTP ${b.status}  ${bBody.length}B  title="${bTitle}"`);
console.log(`  identical: ${identical ? "YES (HMAC caught the tamper, or we're hard-blocked)" : "NO — server honored the t-flip"}`);

if (identical && /blocked/i.test(aTitle)) {
  console.log(`\n  Verdict: SIGNED-ENVELOPE TAMPER DETECTED OR PRE-BLOCKED.`);
  console.log(`           The captcha endpoint returned an identical "blocked" page for both t=fe`);
  console.log(`           and t=d. Either the 'e' HMAC validated against the original t and the`);
  console.log(`           tampered request was rejected (silent fall-back), OR we're in hard_block`);
  console.log(`           state and no challenge tier matters. See DataDome.md §3 envelope arch.`);
} else if (!identical) {
  console.log(`\n  Verdict: UNEXPECTED — server returned different responses. Worth investigating;`);
  console.log(`           DataDome may not be validating 'e' against 't' on this endpoint.`);
}

writeFileSync(join(OUT, "tamper.json"), JSON.stringify({
  original_url: original,
  tampered_url: tampered,
  envelope: { t: t_match[1], s: s_match?.[1] ?? null, e_prefix: e_match[1].slice(0, 16), e_suffix: e_match[1].slice(-16) },
  original: { status: a.status, bytes: aBody.length, title: aTitle },
  tampered: { status: b.status, bytes: bBody.length, title: bTitle },
  identical,
  verdict: identical ? "tamper-caught-or-blocked" : "server-honored-flip",
  capturedAt: new Date().toISOString(),
}, null, 2));

writeFileSync(join(OUT, "tamper-original-body.html"), aBody);
writeFileSync(join(OUT, "tamper-tampered-body.html"), bBody);

console.log(`\n  artifacts → ${OUT}/tamper*`);
