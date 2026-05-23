#!/usr/bin/env node
/**
 * signals.mjs — derive a clean inventory of every signal name DataDome's
 * tag collects, with one example value per name.
 *
 * Takes one or more plaintext-payload JSON files (the kind bypass.mjs /
 * mitm.mjs / bypass-batch.mjs produce) and merges them into a single
 * deduped inventory keyed by signal name.
 *
 * Output: signal-name → { count_across_captures, example_value,
 * value_type, first_seen_t_ms, also_seen_with_value_count }.
 *
 * Usage:
 *   node signals.mjs <plaintext1.json> [plaintext2.json ...]
 *
 *   With no args: builds inventory from the bundled reference captures
 *   in examples/ — useful as the "what does DD collect" reference doc.
 *
 *   Writes results/signals-inventory.json and prints a markdown table
 *   of the top fields to stdout.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });

let inputs = process.argv.slice(2);
if (inputs.length === 0) {
  const ex = join(__dirname, "examples");
  inputs = ["hard-blocked-plaintext.json", "clean-tmobile-plaintext.json"]
    .map((f) => join(ex, f))
    .filter(existsSync);
  if (inputs.length === 0) {
    console.error(`signals: no input files; pass one or more plaintext JSON paths.`);
    process.exit(1);
  }
  console.log(`signals: using bundled examples → ${inputs.map((f) => f.replace(__dirname + "/", "")).join(", ")}`);
}

const inventory = new Map();
let totalCaptures = 0;

for (const f of inputs) {
  const data = JSON.parse(readFileSync(f, "utf8"));
  totalCaptures++;
  for (const s of data.signals || []) {
    const cur = inventory.get(s.name) || {
      name: s.name,
      capture_count: 0,
      example_value: s.value,
      value_type: typeof s.value,
      first_seen_t_ms: s.t_ms,
      distinct_value_count: 0,
      sample_values: new Set(),
    };
    cur.capture_count++;
    cur.sample_values.add(JSON.stringify(s.value) ?? "null");
    inventory.set(s.name, cur);
  }
}

const sorted = [...inventory.values()].sort((a, b) => a.name.localeCompare(b.name));
sorted.forEach((s) => {
  s.distinct_value_count = s.sample_values.size;
  s.sample_values = [...s.sample_values].slice(0, 3).map((v) => {
    let parsed;
    try { parsed = JSON.parse(v); } catch { return v; }
    return typeof parsed === "string" && parsed.length > 80 ? parsed.slice(0, 80) + "…" : parsed;
  });
});

// Categorize by name prefix / known role
function bucketFor(name) {
  if (name.startsWith("nt_"))       return "network-timing";
  if (name.startsWith("m_") || name === "nid" || name === "crt") return "behavioral";
  if (name.startsWith("k_"))        return "keyboard-dynamics";
  if (name.startsWith("p_"))        return "pointer-events";
  if (name.startsWith("es_"))       return "stroke-statistics";
  if (name.startsWith("ccs") || name.startsWith("iccs")) return "self-stack-integrity";
  if (name.startsWith("css") || name === "fph") return "canvas-css-fingerprint";
  if (name.startsWith("sg"))        return "stroke-generator-hash";
  if (name.startsWith("ars_") || name.startsWith("br_") || name.startsWith("rs_") || name === "trrd") return "viewport";
  if (name === "bchk")              return "composite-device-id";
  if (name === "stqe" || name === "stqu") return "storage-quota";
  if (name === "k_lytk")            return "keyboard-layout";
  if (name === "wdifpnh")           return "iframe-parentNode";
  if (name === "cld" || name === "sgb" || name === "gai" || name === "sqt") return "ai-agent-detector";
  if (name === "wwl" || name === "wwlrv" || name === "lgs") return "language";
  if (name === "cfpfe" || name === "stcfp") return "host-page-extract";
  if (name === "ua" || name === "uagent" || name === "platform") return "navigator";
  if (name === "nhi")               return "ua-client-hints";
  if (name === "tz" || name === "tzo") return "timezone";
  if (name === "jset")              return "page-session";
  return "other";
}

const byBucket = new Map();
for (const s of sorted) {
  const b = bucketFor(s.name);
  if (!byBucket.has(b)) byBucket.set(b, []);
  byBucket.get(b).push(s);
  s.bucket = b;
}

const outFile = join(OUT, "signals-inventory.json");
writeFileSync(outFile, JSON.stringify({
  source_files: inputs.map((f) => f.replace(__dirname + "/", "")),
  total_captures: totalCaptures,
  unique_signal_count: inventory.size,
  bucket_summary: Object.fromEntries([...byBucket].map(([b, ss]) => [b, ss.length])),
  signals: sorted,
  capturedAt: new Date().toISOString(),
}, null, 2));

console.log(`\nDataDome signal inventory across ${totalCaptures} capture(s)`);
console.log(`unique signal names: ${inventory.size}`);
console.log(`\nby bucket:`);
for (const [b, ss] of [...byBucket].sort((a, b) => b[1].length - a[1].length)) {
  console.log(`  ${b.padEnd(28)} ${ss.length}`);
}

console.log(`\n────────────────────────────────────────`);
console.log(`signals by bucket (name → distinct values seen, example):`);
for (const [b, ss] of [...byBucket].sort((a, b) => b[1].length - a[1].length)) {
  console.log(`\n[${b}]  (${ss.length} signal${ss.length === 1 ? "" : "s"})`);
  for (const s of ss) {
    const sample = JSON.stringify(s.sample_values[0]);
    const sampleStr = sample.length > 60 ? sample.slice(0, 60) + "…" : sample;
    console.log(`  ${s.name.padEnd(22)} (${s.value_type}, ${s.distinct_value_count}× distinct)  e.g. ${sampleStr}`);
  }
}

console.log(`\n  full inventory → ${outFile}`);
