#!/usr/bin/env node
/**
 * recon-chaser.mjs — passive recon on a remote Chaser CDP session.
 *
 * Connects to Chaser's cloud browser, loads a DataDome-protected page,
 * and captures the same data as recon.mjs — but on their patched
 * Chrome APK running in redroid. Use with diff.mjs to compare
 * payloads against a native local run.
 *
 * Usage:
 *   CHASER_KEY=xxx node recon-chaser.mjs [target-url]
 *   default target: https://www.g2.com/products/playwright/reviews
 */

import { chromium } from "patchright";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

const TARGET =
  process.argv[2] || "https://www.g2.com/products/playwright/reviews";

const CHASER_KEY = process.env.CHASER_KEY;
if (!CHASER_KEY) {
  console.error("[chaser] set CHASER_KEY env var to your API key");
  process.exit(1);
}

// Create Chaser session
console.log("[chaser] creating session...");
const sessionRes = await fetch("https://api.chaser.sh/v1/sessions", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${CHASER_KEY}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ ttl_seconds: 120 }),
});

if (!sessionRes.ok) {
  console.error(`[chaser] session creation failed: ${sessionRes.status}`);
  process.exit(1);
}

const { cdp_url, id: session_id } = await sessionRes.json();
console.log(`[chaser] session: ${session_id}`);

// Connect via CDP
let browser;
try {
  browser = await chromium.connectOverCDP({ endpointURL: cdp_url });
  const context = browser.contexts()[0];
  const page = context.pages()[0] ?? await context.newPage();

  // Passive capture — same as recon.mjs
  const jsResponses = [];
  let tagsBody = null;
  let tagsUrl = null;
  const capturedPayloads = [];
  let iJsBody = null;
  let interstitialResponse = null;

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
    // Capture i.js body — this is where fingerprint collection happens
    if (/captcha-delivery\.com\/i\.js/.test(u)) {
      try {
        iJsBody = (await resp.body()).toString("utf8");
        console.log(`[i.js] captured ${iJsBody.length} bytes`);
      } catch {}
    }
    if (/tags\.js/.test(u) && !tagsBody) {
      try {
        tagsBody = (await resp.body()).toString("utf8");
        tagsUrl = u;
      } catch {}
    }
    // Capture interstitial response (the verdict before tags.js)
    if (/interstitial/.test(u) && resp.request().method() === "POST") {
      try {
        interstitialResponse = {
          status: resp.status(),
          body: (await resp.text()).substring(0, 1000),
        };
      } catch {}
    }
  });

  page.on("request", (req) => {
    if (/interstitial/.test(req.url()) && req.method() === "POST") {
      const postData = req.postData();
      if (postData) {
        console.log(`[capture] interstitial POST: ${postData.length} bytes`);
        capturedPayloads.push({
          url: req.url(),
          body: postData,
          timestamp: Date.now(),
        });
      }
    }
  });

  // Load target
  console.log(`\nrecon-chaser: loading ${TARGET}`);
  const r = await page
    .goto(TARGET, { waitUntil: "load", timeout: 45000 })
    .catch((e) => ({ status: () => "err", _err: e.message }));
  console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

  await page.waitForTimeout(8000);

  // Analyze
  const ddRelated = jsResponses.filter((j) =>
    /datadome|captcha-delivery|datado\.me|tags\.js/.test(j.url),
  );

  console.log(`\nDataDome-related responses (${ddRelated.length}):`);
  ddRelated.forEach((j) => console.log(`  ${j.status}  ${j.url}`));

  let bundleInfo = null;
  if (tagsBody) {
    const banner = tagsBody.match(/\/\*\*\s*(DataDome[^*]+)\*\//);
    const versionMatch = tagsBody.match(/version\s+(\d+\.\d+\.\d+)/i);

    // 5.7.0+ patterns
    const xorshift_new = /\(n\^=n<<13\)\^n>>17\)^n<<5/.test(tagsBody);
    const prng_V = /return q=function/.test(tagsBody);
    const custom_b64 = /QSdCN\/3956tpzwLMoDFxrVh/.test(tagsBody);
    const seed_constant = /11027890091/.test(tagsBody);
    const final_xor = /1809053797/.test(tagsBody);

    // 4.x patterns
    const vnt = /function v\(n,t\)\{var c,e;/.test(tagsBody);
    const xorshift_old = /n\^=n<<13;n\^=n>>17;n\^=n<<5/.test(tagsBody);

    bundleInfo = {
      url: tagsUrl,
      bytes: tagsBody.length,
      banner: banner ? banner[1].trim() : null,
      version: versionMatch ? versionMatch[1] : null,
      chokepoint_vnt_present: vnt,
      xorshift_prng_present: xorshift_old,
      xorshift_570: xorshift_new,
      prng_V_present: prng_V,
      custom_base64: custom_b64,
      seed_constant_present: seed_constant,
      final_xor_present: final_xor,
    };

    console.log(`\ntags.js bundle:`);
    console.log(`  url:     ${tagsUrl}`);
    console.log(`  size:    ${tagsBody.length} bytes`);
    console.log(`  version: ${bundleInfo.version || "?"}`);
    console.log(`  5.7.0+:  ${prng_V ? "yes" : "no"}`);
    console.log(`  4.x:     ${vnt ? "yes" : "no"}`);
  }

  // Save results
  const result = {
    target: TARGET,
    finalStatus: r.status?.() ?? null,
    jsResponseCount: jsResponses.length,
    ddRelated,
    bundle: bundleInfo,
    capturedPayloads,
    interstitialResponse,
    hasITagJs: !!iJsBody,
    iJsSize: iJsBody?.length || 0,
    capturedAt: new Date().toISOString(),
  };

  writeFileSync(join(OUT, "recon-chaser.json"), JSON.stringify(result, null, 2));

  // Save i.js for analysis
  if (iJsBody) {
    writeFileSync(join(OUT, "recon-chaser-ijs.js"), iJsBody);
  }

  // Also save the tags.js bundle for diff
  if (tagsBody) {
    writeFileSync(join(OUT, "recon-chaser-tags.js"), tagsBody);
  }

  // Save interstitial payloads for comparison
  if (capturedPayloads.length > 0) {
    writeFileSync(
      join(OUT, "recon-chaser-payloads.json"),
      JSON.stringify(capturedPayloads, null, 2),
    );
  }

  // Take screenshot
  await page.screenshot({ path: join(OUT, "recon-chaser.png"), fullPage: false });

  console.log(`\n  artifacts → ${OUT}/recon-chaser*`);

} finally {
  if (browser) await browser.close();

  // Delete Chaser session
  await fetch(`https://api.chaser.sh/v1/sessions/${session_id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${CHASER_KEY}` },
  });
  console.log(`[chaser] session ${session_id} deleted`);
}
