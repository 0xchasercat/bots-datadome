#!/usr/bin/env node
/**
 * mitm-chaser.mjs — full network capture on a remote Chaser CDP session.
 *
 * Same as mitm.mjs but connects to Chaser's cloud browser.
 * Captures everything DataDome sees for comparison against local.
 *
 * Usage: CHASER_KEY=xxx node mitm-chaser.mjs [target-url]
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
  console.error("[chaser] set CHASER_KEY env var");
  process.exit(1);
}

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
  console.error(`[chaser] session failed: ${sessionRes.status}`);
  process.exit(1);
}

const { cdp_url, id: session_id } = await sessionRes.json();
console.log(`[chaser] session: ${session_id}`);

let browser;
try {
  browser = await chromium.connectOverCDP({ endpointURL: cdp_url });
  const context = browser.contexts()[0];
  const page = context.pages()[0] ?? await context.newPage();

  // Enable CDP for full network capture
  const client = await context.newCDPSession(page);
  await client.send("Network.enable", {
    maxResourceBufferSize: 10 * 1024 * 1024,
    maxPostDataSize: 10 * 1024 * 1024,
  });

  const allRequests = {};
  const ddTraffic = [];
  const timeline = [];

  client.on("Network.requestWillBeSent", (params) => {
    const { requestId, request, timestamp } = params;
    allRequests[requestId] = {
      url: request.url,
      method: request.method,
      headers: request.headers,
      postData: request.postData || null,
      timestamp,
      isDD: /datadome|captcha-delivery|datado\.me/.test(request.url),
    };

    if (allRequests[requestId].isDD) {
      console.log(`[req] ${request.method} ${request.url.substring(0, 100)}`);
      timeline.push({ type: "request", url: request.url, method: request.method, timestamp });
    }
  });

  client.on("Network.responseReceived", (params) => {
    const { requestId, response, timestamp } = params;
    if (allRequests[requestId]) {
      allRequests[requestId].response = {
        status: response.status,
        headers: response.headers,
        timestamp,
        protocol: response.protocol,
        securityState: response.securityState,
        securityDetails: response.securityDetails,
      };

      if (allRequests[requestId].isDD) {
        console.log(`[res] ${response.status} ${response.url?.substring(0, 100)}`);
        console.log(`      protocol: ${response.protocol}  security: ${response.securityState}`);
        if (response.securityDetails) {
          console.log(`      TLS: ${response.securityDetails.protocol} ${response.securityDetails.cipher} ${response.securityDetails.subjectName}`);
        }
        timeline.push({
          type: "response",
          url: response.url,
          status: response.status,
          protocol: response.protocol,
          securityState: response.securityState,
          securityDetails: response.securityDetails,
          timestamp,
        });
      }
    }
  });

  client.on("Network.loadingFinished", async (params) => {
    const { requestId } = params;
    const req = allRequests[requestId];
    if (req?.isDD && req.response) {
      try {
        const { body, base64Encoded } = await client.send("Network.getResponseBody", { requestId });
        req.response.body = base64Encoded ? Buffer.from(body, "base64").toString("utf8") : body;
        req.response.bodySize = body.length;
      } catch {}
    }
  });

  client.on("Network.loadingFailed", (params) => {
    const { requestId, errorText, canceled } = params;
    const req = allRequests[requestId];
    if (req?.isDD) {
      console.log(`[fail] ${req.url.substring(0, 100)}  error: ${errorText}`);
      req.response = { error: errorText, canceled };
    }
  });

  console.log(`\nmitm-chaser: loading ${TARGET}`);
  const r = await page
    .goto(TARGET, { waitUntil: "load", timeout: 45000 })
    .catch((e) => ({ status: () => "err" }));
  console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

  await page.waitForTimeout(10000);

  // Collect DD traffic
  for (const [id, req] of Object.entries(allRequests)) {
    if (req.isDD) {
      ddTraffic.push({
        requestId: id,
        url: req.url,
        method: req.method,
        requestHeaders: req.headers,
        postData: req.postData,
        timestamp: req.timestamp,
        response: req.response || null,
      });
    }
  }

  ddTraffic.sort((a, b) => a.timestamp - b.timestamp);

  console.log(`\n=== CAPTURE SUMMARY ===`);
  console.log(`  total requests: ${Object.keys(allRequests).length}`);
  console.log(`  DD requests:    ${ddTraffic.length}`);

  console.log(`\nDD traffic flow:`);
  ddTraffic.forEach((t, i) => {
    const status = t.response?.status || t.response?.error || "?";
    console.log(`  ${i + 1}. ${t.method} ${t.url.substring(0, 80)}  → ${status}`);
    if (t.response?.securityDetails) {
      const sd = t.response.securityDetails;
      console.log(`     TLS: ${sd.protocol} ${sd.cipher} ${sd.subjectName}`);
    }
  });

  // Save full capture
  writeFileSync(join(OUT, "mitm-chaser-full.json"), JSON.stringify({
    target: TARGET,
    status: r.status?.() ?? null,
    totalRequests: Object.keys(allRequests).length,
    ddTrafficCount: ddTraffic.length,
    ddTraffic,
    timeline,
    capturedAt: new Date().toISOString(),
  }, null, 2));

  // Save headers for diff
  const headerDump = ddTraffic.map(t => ({
    url: t.url,
    method: t.method,
    requestHeaders: t.requestHeaders,
    responseHeaders: t.response?.headers || {},
    securityDetails: t.response?.securityDetails || null,
    protocol: t.response?.protocol || null,
  }));
  writeFileSync(join(OUT, "mitm-chaser-headers.json"), JSON.stringify(headerDump, null, 2));

  // Save bodies
  const bodies = ddTraffic
    .filter(t => t.response?.body)
    .map(t => ({
      url: t.url,
      status: t.response.status,
      body: t.response.body,
      bodySize: t.response.bodySize,
    }));
  writeFileSync(join(OUT, "mitm-chaser-bodies.json"), JSON.stringify(bodies, null, 2));

} finally {
  if (browser) await browser.close();
  await fetch(`https://api.chaser.sh/v1/sessions/${session_id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${CHASER_KEY}` },
  });
  console.log(`\n  artifacts → ${OUT}/mitm-chaser-*`);
}
