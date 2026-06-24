#!/usr/bin/env node
/**
 * decrypt_v570.mjs — offline decoder for DataDome 5.7.0+ plaintext payloads.
 *
 * DataDome 5.7.0 replaced the old v(n,t) chokepoint with a new cipher:
 *   - FNV-1a hash (d) for input hashing
 *   - Xorshift PRNG (f) for state transformation (same as 4.x)
 *   - New PRNG constructor V(n,t) that extracts bytes from xorshift state
 *   - Custom base64 alphabet for encoding
 *   - Double XOR: once with PRNG during collection, once with second PRNG at serialization
 *
 * Usage:
 *   node decrypt_v570.mjs <captured_plaintext_file>
 *   node decrypt_v570.mjs --from-string "jsData=..."
 *
 * The plaintext payload is the URL-encoded form data captured from the
 * interstitial POST (the "payload" field) or the ch/le fields.
 *
 * Reference: DataDome.md §5.7.0 cipher analysis
 */

import { readFileSync } from "node:fs";

// ─── 5.7.0 Cipher Components ─────────────────────────────────────────

const CUSTOM_B64_ALPHABET = "QSdCN/3956tpzwLMoDFxrVh=u2RfWI0gTOZUnYPilqAKaBkE+cse1mX4v8yjGJH7b";

/**
 * FNV-1a hash — DataDome 5.7.0 d(n) function
 * Same hash as 4.x, used for input hashing before encryption.
 */
function fnv1a(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash;
}

/**
 * Xorshift — DataDome 5.7.0 f(n) function
 * Same as 4.x: (n ^= n << 13) ^ n >> 17) ^ n << 5
 */
function xorshift(n) {
  return ((n = (n ^= n << 13) ^ (n >>> 17)) ^ (n << 5)) | 0;
}

/**
 * PRNG constructor — DataDome 5.7.0 V(n, t) function
 * Creates a PRNG that extracts bytes from xorshift state.
 * Every 3 calls, the state is transformed with xorshift.
 * Output: 255 & ((state >> (16 - 8*counter)) ^ (flag ? --offset : 0))
 */
function createPRNG(state, seed, useSeed = true) {
  let s = state;
  let counter = -1;
  let offset = seed;
  const flag = useSeed;

  return function getNext(peek = false) {
    let result;
    if (counter > 2) {
      s = xorshift(s);
      counter = 0;
    }
    counter++;
    result = (s >>> (16 - 8 * counter)) & 0xff;
    if (flag) {
      offset--;
      result = (result ^ offset) & 0xff;
    }
    return result;
  };
}

/**
 * Custom base64 decode — DataDome 5.7.0 alphabet
 */
function customB64Decode(encoded) {
  const clean = encoded.replace(/[^A-Za-z0-9+/=]/g, "");
  let result = "";

  for (let i = 0; i < clean.length; i += 4) {
    const a = CUSTOM_B64_ALPHABET.indexOf(clean[i]);
    const b = CUSTOM_B64_ALPHABET.indexOf(clean[i + 1]);
    const c = CUSTOM_B64_ALPHABET.indexOf(clean[i + 2]);
    const d = CUSTOM_B64_ALPHABET.indexOf(clean[i + 3]);

    const triple = (a << 2) | (b >> 4);
    result += String.fromCharCode(triple);

    if (c !== 64) {
      const second = ((b & 15) << 4) | (c >> 2);
      result += String.fromCharCode(second);
    }
    if (d !== 64) {
      const third = ((c & 3) << 6) | d;
      result += String.fromCharCode(third);
    }
  }

  return result;
}

/**
 * Decode a DataDome 5.7.0 payload.
 *
 * The encoding flow is:
 *   1. XOR each byte with PRNG (during collection)
 *   2. XOR entire buffer with second PRNG (at serialization)
 *   3. Encode with custom base64
 *
 * So decoding is:
 *   1. Custom base64 decode
 *   2. XOR with second PRNG to undo step 2
 *   3. XOR with first PRNG to undo step 1
 *
 * However, without the exact seed values (which depend on the session),
 * we can only do structural analysis. The seeds are:
 *   - a = f(f(Date.now() >> 3 ^ 11027890091) * e)  (session seed)
 *   - n = e ^ d(n) ^ t  (input hash XORed with keys)
 *
 * For offline analysis, we decode the structure and show raw bytes.
 */
function decodePayload(encoded) {
  const decoded = customB64Decode(encoded);
  const bytes = [];
  for (let i = 0; i < decoded.length; i++) {
    bytes.push(decoded.charCodeAt(i) & 0xff);
  }
  return bytes;
}

/**
 * Parse key-value pairs from raw payload bytes.
 * The format is: [marker] [key_bytes] [separator] [value_bytes] ...
 * Marker: s() ^ (h.length ? 44 : 123)
 * Separator: 58 ^ s()
 */
function parsePayloadStructure(bytes) {
  const pairs = [];
  let i = 0;

  while (i < bytes.length) {
    // Look for patterns that might be key-value separators
    // The actual parsing requires knowing the PRNG state,
    // so we do best-effort structural analysis
    if (i + 4 < bytes.length) {
      // Try to find "jsData" or other known key patterns
      const chunk = bytes.slice(i, i + 20).map(b => String.fromCharCode(b)).join("");
      if (chunk.includes("jsData") || chunk.includes("jsType") || chunk.includes("cid")) {
        pairs.push({ offset: i, preview: chunk.replace(/[^\x20-\x7e]/g, "?") });
      }
    }
    i++;
  }

  return pairs;
}

// ─── Main ─────────────────────────────────────────────────────────────

const input = process.argv[2];
let rawPayload = "";

if (input === "--from-string") {
  rawPayload = process.argv[3] || "";
} else if (input) {
  rawPayload = readFileSync(input, "utf8").trim();
} else {
  console.error("Usage: node decrypt_v570.mjs <file> | --from-string \"payload\"");
  process.exit(1);
}

// URL-decode if needed
if (rawPayload.includes("%")) {
  try {
    rawPayload = decodeURIComponent(rawPayload);
  } catch {}
}

// Parse form-encoded data
const params = new URLSearchParams(rawPayload);
const hasFormStructure = params.has("jsData") || params.has("jsType") || params.has("cid");

if (hasFormStructure) {
  console.log("=== DataDome 5.7.0 Payload (form-encoded) ===\n");
  console.log(`Fields: ${[...params.keys()].join(", ")}\n`);

  for (const [key, value] of params) {
    if (key === "jsData") {
      console.log(`--- ${key} ---`);
      try {
        const jsData = JSON.parse(value);
        console.log(JSON.stringify(jsData, null, 2));
      } catch {
        console.log(value);
      }
      console.log();
    } else if (key === "eventCounters") {
      console.log(`--- ${key} ---`);
      try {
        const events = JSON.parse(value);
        console.log(JSON.stringify(events, null, 2));
      } catch {
        console.log(value);
      }
      console.log();
    } else {
      console.log(`${key}: ${value.substring(0, 200)}${value.length > 200 ? "..." : ""}`);
    }
  }
} else {
  // Raw encoded payload — try to decode
  console.log("=== DataDome 5.7.0 Raw Payload ===\n");
  console.log(`Input length: ${rawPayload.length} chars\n`);

  const bytes = decodePayload(rawPayload);
  console.log(`Decoded bytes: ${bytes.length}\n`);

  // Show hex dump of first 200 bytes
  console.log("Hex dump (first 200 bytes):");
  for (let i = 0; i < Math.min(200, bytes.length); i += 16) {
    const hex = bytes.slice(i, i + 16).map(b => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = bytes.slice(i, i + 16).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    console.log(`  ${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${ascii}`);
  }

  // Try to find readable strings
  console.log("\nReadable strings found:");
  let current = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 32 && b < 127) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= 4) {
        console.log(`  offset ${i - current.length}: "${current}"`);
      }
      current = "";
    }
  }
  if (current.length >= 4) {
    console.log(`  offset ${bytes.length - current.length}: "${current}"`);
  }

  // Structural analysis
  const pairs = parsePayloadStructure(bytes);
  if (pairs.length > 0) {
    console.log("\nPotential key-value structures:");
    pairs.forEach(p => console.log(`  offset ${p.offset}: ${p.preview}`));
  }
}

console.log("\n=== Cipher Reference (5.7.0) ===");
console.log("Hash:    d(n) = FNV-1a — (i << 5) - i + charCode");
console.log("Xorshift: f(n) = ((n ^= n << 13) ^ (n >>> 17)) ^ (n << 5)");
console.log("PRNG:    V(n,t) — extracts bytes from xorshift state every 3 calls");
console.log("Seed:    a = f(f(Date.now() >> 3 ^ 11027890091) * e)");
console.log("Final:   V(1809053797 ^ d(n), a)");
console.log("Alphabet: QSdCN/3956tpzwLMoDFxrVh=u2RfWI0gTOZUnYPilqAKaBkE+cse1mX4v8yjGJH7b");
