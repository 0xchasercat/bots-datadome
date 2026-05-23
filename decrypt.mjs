#!/usr/bin/env node
/**
 * decrypt.mjs — offline decoder for DataDome's jspl payload field.
 *
 * Cipher: pure-JS XOR keystream from a Marsaglia xorshift PRNG
 * (n ^= n << 13; n ^= n >> 17; n ^= n << 5), seeded from
 * (Date.now() >> 3) ^ 11027890091 and a hash of the customer's ddjskey.
 * Output is mapped through the custom base64-like alphabet:
 *   H1DAxCvrj7IaPRL8GSJZKX3f62e9d0VTilFEOWgUB=/t+QmMwuskNnhpb4oyq5Yzc
 *
 * No HMAC. No AEAD. Knowing the ddjskey (public, in page source) plus the
 * approximate request timestamp is enough to decrypt — and to forge.
 *
 * Usage:
 *   node decrypt.mjs --ddjskey <KEY> --jspl <BASE64URL> [--ts <MS>]
 *
 * If --ts is omitted, we sweep a ±5-second window around Date.now() looking
 * for printable plaintext.
 *
 * Status: SKELETON. The exact cipher reconstruction below matches the
 * static reverse-engineered description in DataDome.md §3.3, but the
 * specific bit-mix order and the second-seed derivation from ddjskey may
 * drift across bundle versions. If decryption produces garbage, copy the
 * a(), w(), and l() functions from a freshly-fetched tags.beautified.js
 * (lines ~2080–2220 in v5.6.6) and replace the corresponding helpers below.
 */

const ALPHABET = "H1DAxCvrj7IaPRL8GSJZKX3f62e9d0VTilFEOWgUB=/t+QmMwuskNnhpb4oyq5Yzc";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, arr) => {
    if (cur.startsWith("--") && arr[i + 1] && !arr[i + 1].startsWith("--")) {
      acc.push([cur.slice(2), arr[i + 1]]);
    }
    return acc;
  }, [])
);

if (!args.ddjskey || !args.jspl) {
  console.log(`usage: node decrypt.mjs --ddjskey <KEY> --jspl <BASE64URL> [--ts <MS>]

  --ddjskey  the customer's DataDome client key (visible in the page HTML as window.ddjskey)
  --jspl     the base64url-encoded ciphertext from the POST body's jspl field
  --ts       request timestamp in milliseconds (default: Date.now(), with ±5s sweep)

  Example:
    node decrypt.mjs \\
      --ddjskey 14D062F60A4BDE8CE8647DFC720349 \\
      --jspl   $(jq -r .signals[0].value results/bypass-plaintext.json)`);
  process.exit(1);
}

function decodeCustomB64(s) {
  const map = new Map();
  for (let i = 0; i < ALPHABET.length; i++) map.set(ALPHABET[i], i);
  const out = [];
  let buf = 0, bits = 0;
  for (const ch of s) {
    if (!map.has(ch)) continue;
    buf = (buf << 6) | map.get(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

function stringHash(s) {
  // l(n) in tags.beautified.js — simple polynomial hash, used as the
  // second seed mixed with ddjskey. Recreate from the static reverse.
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

function* keystream(seed) {
  // Marsaglia xorshift32. Generates one byte per yield (LSB).
  let n = seed | 0;
  if (n === 0) n = 1;
  while (true) {
    n ^= n << 13;
    n ^= n >>> 17;
    n ^= n << 5;
    yield n & 0xff;
  }
}

function deriveSeed(tsMs, ddjskey) {
  return ((tsMs >>> 3) ^ 11027890091 ^ stringHash(ddjskey)) | 0;
}

function tryDecrypt(ciphertext, seed) {
  const ks = keystream(seed);
  const out = new Uint8Array(ciphertext.length);
  for (let i = 0; i < ciphertext.length; i++) {
    out[i] = ciphertext[i] ^ ks.next().value;
  }
  return out;
}

function scorePrintable(bytes) {
  let n = 0;
  for (const b of bytes) {
    if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) n++;
  }
  return n / bytes.length;
}

console.log(`decrypt: ddjskey=${args.ddjskey}  jspl=${args.jspl.length} chars`);

const cipher = decodeCustomB64(args.jspl);
console.log(`  decoded ${cipher.length} bytes from custom-alphabet base64`);

const targetTs = args.ts ? parseInt(args.ts) : Date.now();
const window = args.ts ? 0 : 5000; // ±5s sweep when ts not provided

let best = { score: 0, seed: 0, plaintext: null, tsOffset: 0 };
for (let offset = -window; offset <= window; offset += 8) {
  const ts = targetTs + offset;
  const seed = deriveSeed(ts, args.ddjskey);
  const plaintext = tryDecrypt(cipher, seed);
  const score = scorePrintable(plaintext);
  if (score > best.score) {
    best = { score, seed, plaintext, tsOffset: offset };
  }
}

const text = new TextDecoder("latin1").decode(best.plaintext);
console.log(`\nbest decode (score ${(best.score * 100).toFixed(1)}% printable):`);
console.log(`  seed:      0x${best.seed.toString(16)}`);
console.log(`  ts offset: ${best.tsOffset >= 0 ? "+" : ""}${best.tsOffset}ms`);
console.log(`  preview:   ${JSON.stringify(text.slice(0, 200))}`);

if (best.score < 0.85) {
  console.log(`\n  ⚠ low printable score — cipher may have drifted. If you have a freshly`);
  console.log(`    fetched tags.beautified.js, replace the deriveSeed / keystream helpers`);
  console.log(`    with the bundle's current a() / l() / w() implementations.`);
}

import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "results");
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, "decrypt.json"), JSON.stringify({
  ddjskey: args.ddjskey,
  jspl_len: args.jspl.length,
  cipher_bytes: cipher.length,
  seed: `0x${best.seed.toString(16)}`,
  ts_offset_ms: best.tsOffset,
  printable_score: best.score,
  plaintext_preview: text.slice(0, 500),
  capturedAt: new Date().toISOString(),
}, null, 2));
writeFileSync(join(OUT, "decrypt.bin"), Buffer.from(best.plaintext));
console.log(`\n  artifacts → ${OUT}/decrypt.{json,bin}`);
