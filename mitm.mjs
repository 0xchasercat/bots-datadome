#!/usr/bin/env node
/**
 * mitm.mjs — full network capture for DataDome traffic analysis.
 *
 * Captures EVERYTHING DataDome sees: request headers, response headers,
 * TLS info, timing, and full bodies for DD-related traffic. Use with
 * the Chaser equivalent to diff at the network layer.
 *
 * Usage: node mitm.mjs [target-url]
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

const userDataDir = mkdtempSync(join(tmpdir(), "dd-mitm-"));
const ctx = await chromium.launchPersistentContext(userDataDir, {
  headless: false,
  channel: "chrome",
});

const page = ctx.pages()[0] ?? await ctx.newPage();

// Enable CDP for network details (TLS, security, etc.)
const client = await page.context().newCDPSession(page);
await client.send("Network.enable", {
  maxResourceBufferSize: 10 * 1024 * 1024,
  maxPostDataSize: 10 * 1024 * 1024,
});

const allRequests = {};
const ddTraffic = [];
const timeline = [];

// Capture full request details via CDP
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

// Capture response details via CDP
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

// Capture response bodies for DD traffic
client.on("Network.loadingFinished", async (params) => {
  const { requestId, timestamp } = params;
  const req = allRequests[requestId];
  if (req?.isDD && req.response) {
    try {
      const { body, base64Encoded } = await client.send("Network.getResponseBody", { requestId });
      req.response.body = base64Encoded ? Buffer.from(body, "base64").toString("utf8") : body;
      req.response.bodySize = body.length;
    } catch {}
  }
});

// Capture loadingFailed for errors
client.on("Network.loadingFailed", (params) => {
  const { requestId, errorText, canceled } = params;
  const req = allRequests[requestId];
  if (req?.isDD) {
    console.log(`[fail] ${req.url.substring(0, 100)}  error: ${errorText}  canceled: ${canceled}`);
    req.response = { error: errorText, canceled };
  }
});

console.log(`mitm: loading ${TARGET}`);
const r = await page
  .goto(TARGET, { waitUntil: "load", timeout: 45000 })
  .catch((e) => ({ status: () => "err" }));
console.log(`  HTTP ${r.status()}  title="${await page.title()}"`);

// Wait for all network activity to settle
await page.waitForTimeout(10000);

// Collect all DD traffic
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

// Sort by timestamp
ddTraffic.sort((a, b) => a.timestamp - b.timestamp);

// Extract interstitial payloads
const payloads = ddTraffic
  .filter(t => /interstitial/.test(t.url) && t.method === "POST" && t.postData)
  .map(t => ({ url: t.url, body: t.postData, timestamp: t.timestamp }));

// Summary
console.log(`\n=== CAPTURE SUMMARY ===`);
console.log(`  total requests: ${Object.keys(allRequests).length}`);
console.log(`  DD requests:    ${ddTraffic.length}`);
console.log(`  payloads:       ${payloads.length}`);

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
writeFileSync(join(OUT, "mitm-full.json"), JSON.stringify({
  target: TARGET,
  exitIp: null,
  status: r.status?.() ?? null,
  totalRequests: Object.keys(allRequests).length,
  ddTrafficCount: ddTraffic.length,
  ddTraffic,
  timeline,
  capturedAt: new Date().toISOString(),
}, null, 2));

// Save just the request headers for easy diff
const headerDump = ddTraffic.map(t => ({
  url: t.url,
  method: t.method,
  requestHeaders: t.requestHeaders,
  responseHeaders: t.response?.headers || {},
  securityDetails: t.response?.securityDetails || null,
  protocol: t.response?.protocol || null,
}));
writeFileSync(join(OUT, "mitm-headers.json"), JSON.stringify(headerDump, null, 2));

// Save bodies for DD traffic
const bodies = ddTraffic
  .filter(t => t.response?.body)
  .map(t => ({
    url: t.url,
    status: t.response.status,
    body: t.response.body,
    bodySize: t.response.bodySize,
  }));
writeFileSync(join(OUT, "mitm-bodies.json"), JSON.stringify(bodies, null, 2));

// Save payloads
writeFileSync(join(OUT, "mitm-payloads.json"), JSON.stringify(payloads, null, 2));
if (payloads.length > 0) {
  console.log(`\n  interstitial payload: ${payloads[0].body.length} bytes`);
}

await ctx.close();
console.log(`\n  artifacts → ${OUT}/mitm-*`);
