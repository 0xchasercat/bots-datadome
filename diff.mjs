#!/usr/bin/env node
/**
 * diff.mjs — compare two plaintext-payload JSON files.
 *
 * Pass two files (the kind bypass.mjs / mitm.mjs produce). Prints:
 *   - total signal counts
 *   - signals present in only one side
 *   - signals with different values (sorted alphabetically)
 *   - "verdict-relevant deltas" — nt_* (network timing), lgs/wwl (lang),
 *     nid/crt (behavior). These are the cells most likely to flip a
 *     verdict between hard_block and clean-pass per the diff we ran on
 *     2026-05-23.
 *
 * Usage:
 *   node diff.mjs <plaintext-A.json> <plaintext-B.json>
 *
 *   examples/ ships with two reference captures you can diff against:
 *     - examples/hard-blocked-plaintext.json   (202 signals, hard_block)
 *     - examples/clean-tmobile-plaintext.json  (201 signals, t='d' pass)
 */

import { readFileSync } from "node:fs";

if (process.argv.length < 4) {
  console.log(`usage: node diff.mjs <plaintext-A.json> <plaintext-B.json>

  Each file should be the format that bypass.mjs / mitm.mjs produces:
    { signalCount: N, signals: [{ name, value, t_ms }, ...], ... }

  Tip: use the bundled reference captures for a known-good comparison:
    node diff.mjs examples/hard-blocked-plaintext.json examples/clean-tmobile-plaintext.json`);
  process.exit(1);
}

const A = JSON.parse(readFileSync(process.argv[2], "utf8"));
const B = JSON.parse(readFileSync(process.argv[3], "utf8"));

const toMap = (payload) => {
  const m = new Map();
  for (const s of payload.signals || []) {
    if (!m.has(s.name)) m.set(s.name, s.value);
  }
  return m;
};

const aMap = toMap(A);
const bMap = toMap(B);

const aOnly = [], bOnly = [], same = [], differ = [];
for (const [k, v] of aMap) {
  if (!bMap.has(k)) aOnly.push([k, v]);
  else if (JSON.stringify(v) === JSON.stringify(bMap.get(k))) same.push([k, v]);
  else differ.push([k, v, bMap.get(k)]);
}
for (const [k, v] of bMap) {
  if (!aMap.has(k)) bOnly.push([k, v]);
}

console.log(`A (${process.argv[2]}):  ${aMap.size} signals`);
console.log(`B (${process.argv[3]}):  ${bMap.size} signals`);
console.log(`same:    ${same.length}`);
console.log(`differ:  ${differ.length}`);
console.log(`A-only:  ${aOnly.length}`);
console.log(`B-only:  ${bOnly.length}`);

function trunc(v) {
  return JSON.stringify(v).slice(0, 60);
}

if (aOnly.length) {
  console.log(`\n=== A-only (present in ${process.argv[2]}, absent from B) ===`);
  aOnly.forEach(([k, v]) => console.log(`  ${k.padEnd(22)}  ${trunc(v)}`));
}
if (bOnly.length) {
  console.log(`\n=== B-only (present in ${process.argv[3]}, absent from A) ===`);
  bOnly.forEach(([k, v]) => console.log(`  ${k.padEnd(22)}  ${trunc(v)}`));
}

if (differ.length) {
  console.log(`\n=== DIFFERENT VALUES (${differ.length}) ===`);
  differ.sort((a, b) => a[0].localeCompare(b[0]));
  for (const [k, av, bv] of differ) {
    console.log(`  ${k.padEnd(22)}  A: ${trunc(av).padEnd(62)}  B: ${trunc(bv)}`);
  }
}

// Highlight the verdict-relevant deltas
console.log(`\n=== VERDICT-RELEVANT DELTAS ===`);
const buckets = {
  "Network timing (proxy fingerprint)": /^nt_/,
  "Language / accept-language (lgs/wwl/wwlrv)":                /^(lgs|wwl|wwlrv)$/,
  "Behavioral (nid = noise interaction density, crt)":         /^(nid|crt|m_[mcs]_c|m_[cm]m_r)$/,
  "Self-stack-integrity (bundle revision)":                    /^(ccsT|ccsB|ccsH|iccsH|iccsV)$/,
  "Viewport (launch-config, not IP)":                          /^(ars_h|br_h|br_ih|br_oh|rs_h)$/,
};
for (const [label, re] of Object.entries(buckets)) {
  const hits = differ.filter(([k]) => re.test(k));
  if (!hits.length) continue;
  console.log(`\n  ${label}`);
  for (const [k, av, bv] of hits) {
    console.log(`    ${k.padEnd(22)}  A: ${trunc(av).padEnd(36)}  B: ${trunc(bv)}`);
  }
}

console.log(`\n  (full diff written to results/diff.json)`);
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "diff.json"), JSON.stringify({
  A_file: process.argv[2],
  B_file: process.argv[3],
  A_count: aMap.size,
  B_count: bMap.size,
  same_count: same.length,
  differ_count: differ.length,
  a_only: aOnly.map(([k, v]) => ({ name: k, value: v })),
  b_only: bOnly.map(([k, v]) => ({ name: k, value: v })),
  differ: differ.map(([k, a, b]) => ({ name: k, A: a, B: b })),
  capturedAt: new Date().toISOString(),
}, null, 2));
