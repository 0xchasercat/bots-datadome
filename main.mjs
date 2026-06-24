#!/usr/bin/env node
// Interactive launcher for datadome-attack-bot.
// Arrow-key menu over all scripts; descriptions render below the list.
// Children inherit stdio so live output streams through.

import prompts from "prompts";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCRIPTS = [
  {
    file: "bypass.mjs",
    title: "★ bypass       — SOAX mobile + MITM + article fetch (THE HEADLINER)",
    desc:
      "Reads SOAX mobile creds from ~/Dev/soax.txt (or $SOAX_CONFIG). " +
      "Launches real Chrome via SOAX proxy, installs Phase-1 native-API " +
      "hooks + Phase-4 v(n,t) bundle patch, warms reputation on /blog/ " +
      "with humanlike behavior, click-throughs to a /threat-research/ " +
      "article. Saves the article HTML + the captured plaintext payload " +
      "+ the verdict JSON to results/. Expected on clean mobile IP: " +
      "HTTP 200 invisible-pass, ~200 plaintext signals. ~2 min.",
  },
  {
    file: "bypass-batch.mjs",
    title: "★ batch        — pull N articles in one SOAX session (multi-article POC)",
    desc:
      "Same harness as bypass.mjs but loops over N articles harvested from " +
      "/blog/. One persistent Chrome context, one SOAX session, humanlike " +
      "behavior + pause between articles. Defaults N=5, max 15. Writes " +
      "per-article HTML + plaintext + summary.json to results/batch/. " +
      "~3-6 min depending on N.",
  },
  {
    file: "signals.mjs",
    title: "  signals      — dump every signal name DataDome collects",
    desc:
      "Builds a clean inventory from one or more plaintext capture files: " +
      "every signal name DD's v(n,t) chokepoint sees, with one example " +
      "value each, bucketed by role (network-timing, behavioral, " +
      "keyboard-dynamics, ai-agent-detector, etc.). With no args, uses the " +
      "bundled examples/ payloads — useful as the 'what does DD collect' " +
      "reference. ~3 sec.",
  },
  {
    file: "recon.mjs",
    title: "  recon        — find tags.js on a DataDome-protected page",
    desc:
      "Loads a target URL with local Chrome, logs every JS response, " +
      "flags chunks matching tags.js or captcha-delivery.com/i.js. " +
      "Reports the bundle version from the banner comment. Run first " +
      "to confirm which version is deployed. ~1 min.",
  },
  {
    file: "recon-chaser.mjs",
    title: "  recon-chaser — same recon but on a remote Chaser CDP session",
    desc:
      "Connects to Chaser's cloud browser (patched Chrome APK on redroid), " +
      "loads a DataDome-protected page, captures tags.js + interstitial " +
      "POST. Use with diff.mjs to compare payloads against local native " +
      "Chrome run. Requires CHASER_KEY env var. ~1 min.",
  },
  {
    file: "mitm.mjs",
    title: "  mitm         — full network capture with CDP (TLS, headers, bodies)",
    desc:
      "Captures ALL DataDome-related traffic via CDP: request headers, " +
      "response headers, TLS/security details, protocol, and full bodies. " +
      "Use mitm-chaser.mjs for remote comparison. ~1 min.",
  },
  {
    file: "mitm-chaser.mjs",
    title: "  mitm-chaser  — same full capture on a remote Chaser session",
    desc:
      "Connects to Chaser's cloud browser, captures full DD network traffic " +
      "via CDP. Diff mitm-headers.json vs mitm-chaser-headers.json to find " +
      "what DataDome sees differently at the network layer. Requires CHASER_KEY.",
  },
  {
    file: "tamper.mjs",
    title: "  tamper       — signed-envelope tamper test (t=fe → t=d)",
    desc:
      "Extracts the challenge envelope (the inline dd object with " +
      "t / s / e fields) from a DataDome 403 response, then issues two " +
      "requests to geo.captcha-delivery.com/captcha/: original (t=fe) " +
      "and tampered (t=d). Compares responses byte-by-byte. The e field " +
      "is a 256-bit HMAC over the envelope — tamper is caught, both " +
      "return identical 'You have been blocked'. Confirms the signed " +
      "verdict architecture. ~30 sec.",
  },
  {
    file: "decrypt.mjs",
    title: "  decrypt      — offline XOR-keystream decoder for captured jspl (4.x)",
    desc:
      "Given (ddjskey, jspl_base64url, request_timestamp_ms): reverses " +
      "the custom base64-like alphabet, runs the Marsaglia-xorshift PRNG " +
      "with the right seed, XORs the keystream, and prints the TLV " +
      "plaintext bytes. Use to verify the cipher reversal against a " +
      "known bypass capture. Pure offline — no browser. ~5 sec.",
  },
  {
    file: "decrypt_v570.mjs",
    title: "  decrypt570   — offline decoder for DataDome 5.7.0+ payloads",
    desc:
      "Decodes DataDome 5.7.0+ payloads using the new V(n,t) PRNG cipher " +
      "with FNV-1a hash, custom base64 alphabet, and double-XOR encoding. " +
      "Supports both raw encoded payloads and form-encoded data (jsData, " +
      "eventCounters, etc.). Pure offline — no browser. ~5 sec.",
  },
  {
    file: "netdump.mjs",
    title: "  netdump      — full network log of DataDome traffic on a target",
    desc:
      "Captures every request/response touching datadome.co, " +
      "captcha-delivery.com, datado.me, api-js.datadome.co. Includes " +
      "bodies for *.datadome.co. Saves to results/netdump.json + " +
      "results/netdump-bodies/. Use to inspect the cookie-rotation JSON " +
      "response and the inline dd envelope on 403 challenge pages. ~1 min.",
  },
  {
    file: "diff.mjs",
    title: "  diff         — diff two plaintext payload JSON files",
    desc:
      "Pass two plaintext-payload JSON files (the kind bypass / mitm " +
      "produce). Prints total counts, signals present in only one, " +
      "signals with different values, and a 'verdict-relevant deltas' " +
      "section calling out nt_* (network timing), lgs/wwl (language), " +
      "and nid/crt (behavioral) deltas. Use to compare hard-block vs " +
      "clean-verdict runs, or A/B network identities. ~5 sec.",
  },
];

const QUIT = { title: "  quit", value: "__quit__" };

function renderTitle() {
  return [
    "datadome-attack-bot  —  DataDome reverse-engineering harness",
    "See README.md for context · DataDome.md for the full writeup",
    "",
  ].join("\n");
}

async function runOne(scriptFile, extraArgs) {
  return new Promise((resolve) => {
    const child = spawn("node", [path.join(__dirname, scriptFile), ...(extraArgs || [])], {
      stdio: "inherit",
      cwd: __dirname,
    });
    child.on("close", (code) => resolve(code ?? 0));
  });
}

async function menu() {
  console.log(renderTitle());
  while (true) {
    const choices = SCRIPTS.map((s) => ({
      title: s.title,
      value: s.file,
      description: s.desc,
    }));
    choices.push(QUIT);
    const { pick } = await prompts({
      type: "select",
      name: "pick",
      message: "pick a script",
      choices,
      hint: "arrow keys to navigate · enter to run · esc/ctrl-c to quit",
    });
    if (!pick || pick === "__quit__") {
      console.log("\nbye.");
      break;
    }
    const exit = await runOne(pick);
    console.log(`\n[${pick}] exited with code ${exit}.\n`);
  }
}

menu().catch((e) => {
  console.error(e);
  process.exit(1);
});
