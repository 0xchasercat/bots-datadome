#!/usr/bin/env node
/**
 * compare-chaser.mjs — compare local vs Chaser interstitial payloads.
 *
 * Extracts key fields from both payloads to identify what DataDome's
 * i.js fingerprint detects differently between environments.
 *
 * Usage: node compare-chaser.mjs
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");

function loadPayload(file) {
  try {
    const raw = readFileSync(join(OUT, file), "utf8");
    const data = JSON.parse(raw);
    return data[0]?.body || null;
  } catch (e) {
    console.error(`  [!] could not load ${file}: ${e.message}`);
    return null;
  }
}

function parseForm(body) {
  const params = {};
  for (const part of body.split("&")) {
    const [key, ...rest] = part.split("=");
    params[decodeURIComponent(key)] = decodeURIComponent(rest.join("="));
  }
  return params;
}

console.log("=== Local vs Chaser Payload Comparison ===\n");

const localBody = loadPayload("bypass-payloads.json");
const chaserBody = loadPayload("recon-chaser-payloads.json");

if (!localBody) {
  console.error("No local payload found. Run bypass.mjs first.");
  process.exit(1);
}
if (!chaserBody) {
  console.error("No Chaser payload found. Run recon-chaser.mjs first.");
  process.exit(1);
}

const local = parseForm(localBody);
const chaser = parseForm(chaserBody);

const fields = [
  "cid", "hash", "referer", "url", "s", "b", "dm",
  "env", "userEnv", "seed", "ddMessageFormat", "plv3", "ps",
];

console.log("Field-by-field comparison:\n");
for (const field of fields) {
  const lv = local[field] || "(missing)";
  const cv = chaser[field] || "(missing)";
  const same = lv === cv;
  const marker = same ? "=" : "≠";

  console.log(`  ${field}:`);
  if (field === "payload") {
    console.log(`    local:   ${lv.length} bytes`);
    console.log(`    chaser:  ${cv.length} bytes`);
  } else if (field === "env" || field === "userEnv" || field === "plv3") {
    console.log(`    local:   ${lv.substring(0, 80)}...`);
    console.log(`    chaser:  ${cv.substring(0, 80)}...`);
    console.log(`    ${marker} ${same ? "SAME" : "DIFFERENT"}`);
  } else {
    console.log(`    local:   ${lv}`);
    console.log(`    chaser:  ${cv}`);
    console.log(`    ${marker} ${same ? "SAME" : "DIFFERENT"}`);
  }
  console.log();
}

// Decode and compare env fingerprints
console.log("\n=== Fingerprint Analysis ===\n");

try {
  const localEnv = JSON.parse(local.env);
  const chaserEnv = JSON.parse(chaser.env);
  console.log("env (decoded):");
  console.log("  local keys: ", Object.keys(localEnv).sort().join(", "));
  console.log("  chaser keys:", Object.keys(chaserEnv).sort().join(", "));
  console.log();

  for (const key of Object.keys(localEnv)) {
    const lv = JSON.stringify(localEnv[key]);
    const cv = JSON.stringify(chaserEnv[key] || "(missing)");
    const same = lv === cv;
    if (!same) {
      console.log(`  ${key}:`);
      console.log(`    local:  ${lv.substring(0, 120)}`);
      console.log(`    chaser: ${cv.substring(0, 120)}`);
    }
  }
} catch {
  console.log("env field is not JSON — comparing raw values");
  console.log(`  local:  ${local.env?.substring(0, 200)}`);
  console.log(`  chaser: ${chaser.env?.substring(0, 200)}`);
}

try {
  const localUserEnv = JSON.parse(local.userEnv);
  const chaserUserEnv = JSON.parse(chaser.userEnv);
  console.log("\nuserEnv (decoded):");
  console.log("  local keys: ", Object.keys(localUserEnv).sort().join(", "));
  console.log("  chaser keys:", Object.keys(chaserUserEnv).sort().join(", "));
  console.log();

  for (const key of Object.keys(localUserEnv)) {
    const lv = JSON.stringify(localUserEnv[key]);
    const cv = JSON.stringify(chaserUserEnv[key] || "(missing)");
    const same = lv === cv;
    if (!same) {
      console.log(`  ${key}:`);
      console.log(`    local:  ${lv.substring(0, 120)}`);
      console.log(`    chaser: ${cv.substring(0, 120)}`);
    }
  }
} catch {
  console.log("\nuserEnv field is not JSON — comparing raw values");
  console.log(`  local:  ${local.userEnv?.substring(0, 200)}`);
  console.log(`  chaser: ${chaser.userEnv?.substring(0, 200)}`);
}

// Compare payload sizes
console.log("\n=== Payload Size ===\n");
console.log(`  local:  ${local.payload?.length || 0} bytes`);
console.log(`  chaser: ${chaser.payload?.length || 0} bytes`);
console.log(`  diff:   ${(chaser.payload?.length || 0) - (local.payload?.length || 0)} bytes`);
