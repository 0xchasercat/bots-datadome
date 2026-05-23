# datadome-attack-bot

Reverse-engineering harness for [DataDome](https://datadome.co)'s
bot-detection tag (`tags.js` v5.6.6, captured 2026-05-23). Demonstrates
end-to-end bypass of DataDome's challenge gate through a clean
residential-mobile network identity, with full plaintext fingerprint
payload captured via in-flight bundle patching.

Companion writeup: **[DataDome.md](DataDome.md)** — full methodology,
every collector lambda walked, the XOR-keystream cipher reversed,
nine documented bypass surfaces, comparison vs Castle and FingerprintJS.

> **Scope.** Defensive / red-team research. Demonstrates one bot
> producing a clean-verdict pageview on a DataDome-protected article
> via a SOAX residential mobile proxy, and captures the in-flight
> fingerprint payload via a small bundle patch. Does not submit
> credentials, does not attempt to defeat post-gate authentication,
> does not exfiltrate any user data. Intended audience: DataDome's
> own research team, and argus / fingerprinting practitioners
> studying production hardening.

---

## Quick start

```bash
git clone <this-repo> datadome-attack-bot
cd datadome-attack-bot
npm install                # installs playwright + downloads real Chrome channel
npm start                  # interactive menu — pick a script with arrow keys
```

You'll see an arrow-key menu of 9 scripts with descriptions below the
highlighted item:

```
datadome-attack-bot  —  DataDome reverse-engineering harness
See README.md for context · DataDome.md for the full writeup

? pick a script › arrow keys to navigate · enter to run · esc/ctrl-c to quit
❯ ★ bypass       — SOAX mobile + MITM + article fetch (THE HEADLINER)
  ★ batch        — pull N articles in one SOAX session (multi-article POC)
    signals      — dump every signal name DataDome collects
    recon        — find tags.js on a DataDome-protected page
    mitm         — Phase-1 native hooks + Phase-4 v(n,t) plaintext capture
    tamper       — signed-envelope tamper test (t=fe → t=d)
    decrypt      — offline XOR-keystream decoder for captured jspl blobs
    netdump      — full network log of DataDome traffic on a target
    diff         — diff two plaintext payload JSON files (verdict-relevant deltas)
    quit
```

Pick **bypass** for the headline demo (~2 min). After each script
finishes you're returned to the menu.

### Power-user shortcuts

Every script has a direct npm-run shortcut:

```bash
npm run bypass        # same as picking bypass from the menu
npm run batch -- 5    # fetch 5 articles in one SOAX session
npm run signals       # dump signal inventory from bundled examples
npm run recon
npm run mitm
npm run tamper
npm run decrypt
npm run netdump
npm run diff
```

### SOAX credentials

The `bypass.mjs` script needs HTTP-proxy credentials. By default it
reads `$HOME/Dev/soax.txt` (one line per pool in the format
`POOL: curl -k -x USER:PASS@HOST:PORT -L URL`). Override with
`SOAX_CONFIG=/path/to/creds.txt` if your file lives elsewhere.

If you don't have SOAX, any HTTP proxy with a residential or mobile
exit IP will work — just edit the proxy block in `bypass.mjs`. The
gate is on TLS/JA4/IP, not on which proxy vendor.

---

## What each script does

All scripts are standalone — run any in any order. They write JSON
to `results/<name>.json` and most print a short summary to stdout.

### `bypass.mjs` ★ THE HEADLINER

End-to-end gate bypass + plaintext capture in one run. Pipeline:

1. Read SOAX mobile creds from `~/Dev/soax.txt` (or
   `$SOAX_CONFIG`).
2. Launch vanilla Playwright real Chrome (`channel: 'chrome'`,
   headed, with `--disable-blink-features=AutomationControlled`) via
   the SOAX HTTP proxy.
3. Install Phase-1 native-API MITM init script — invisible
   `Proxy`-wrapped `JSON.stringify` / `btoa`. Self-test confirms
   `Function.prototype.toString` still returns `[native code]` for
   the wrapped APIs.
4. Install Phase-4 route patch on `https://js.datadome.co/tags.js`:
   inject `try{(window.__ddTap=...).push([n,t,perf])}catch(_){}` at
   the entry of `function v(n,t){var c,e;`. Patch adds +82 bytes; the
   bundle still runs cleanly.
5. Visit `https://datadome.co/blog/` (not gated; warms up the cookie
   jar and runs humanlike mouse-wander + scroll).
6. Click-through to a `/threat-research/` article URL.
7. Wait for the JS tag to POST to `api-js.datadome.co/js/` (the
   verdict).
8. Dump the article HTML, the captured plaintext signal list,
   the verdict JSON, screenshot, full network log.

Result on a clean mobile identity: HTTP 200 on the article, ~200
plaintext signals captured. ~2 min.

### `bypass-batch.mjs` ★ MULTI-ARTICLE POC

Same harness as `bypass.mjs`, but loops over N articles harvested
from `/blog/` in one persistent Chrome session through a single SOAX
mobile pool. One init, one cookie warm-up on `/blog/`, then sequential
visits to N article URLs with humanlike behavior + a 2-4 second pause
between each.

Per-article output to `results/batch/`:

- `<slug>.html` — the article body fetched directly from datadome.co
- `<slug>.plaintext.json` — the per-article plaintext signal payload
- `summary.json` — verdict for every article in the run (status, size,
  H1, signal count, blocked/solved flag)

Usage: `node bypass-batch.mjs [N]`  (default 5, max 15). ~30-60 sec per
article including humanlike behavior. ~3-6 min total for the default
N=5.

### `signals.mjs`

Builds a clean inventory from one or more plaintext-payload JSON files.
For each unique signal name DataDome's `v(n,t)` chokepoint sees, the
inventory records:

- the value type (number / string / boolean)
- a sample value (first observed; truncated if long)
- how many distinct values were observed across captures
- the bucket (network-timing / behavioral / keyboard-dynamics /
  ai-agent-detector / canvas-css-fingerprint / etc.)

Usage:
- `node signals.mjs` — with no args, uses the bundled `examples/*.json`
  reference captures (hard-blocked + clean-mobile). Useful as the
  "what does DD collect" reference doc.
- `node signals.mjs results/bypass-plaintext.json` — inventory from
  one fresh capture.
- `node signals.mjs file1.json file2.json ...` — merged inventory
  across multiple captures (catches signals that only fire under
  certain conditions).

Output: `results/signals-inventory.json` + a stdout dump bucketed by
role. Bundled inventory at `examples/signals-inventory.json` covers
~203 unique signal names from two reference sessions.

### `recon.mjs`

Loads a target URL with Playwright, logs every JS response, flags
chunks matching `js.datadome.co/tags.js` or
`captcha-delivery.com/c.js`. Reports the bundle version (it's in the
banner comment — `/** DataDome ... version X.Y.Z */`). Run first to
confirm which version is deployed. ~1 min.

### `mitm.mjs`

Phase-1 native-API hooks + Phase-4 bundle patch in a generic form
(no SOAX, runs against any target). Captures the plaintext payload
in `results/mitm.json`. Use this for a quick local capture; use
`bypass.mjs` when you need to bypass the gate too. ~1 min.

### `tamper.mjs`

Extracts the challenge envelope from a DataDome 403 response (the
`dd` object with `t / s / e` fields), then makes two requests to
`geo.captcha-delivery.com/captcha/`:

1. Original — `t=fe` (force end-user CAPTCHA).
2. Tampered — `t=d` (request the invisible device check instead).

Compares responses. The `e` field is a 256-bit HMAC over the
envelope; both requests return identical "You have been blocked"
pages (or both succeed if you're not flagged). Confirms the signed
envelope catches client-side tampering. ~30 sec.

### `decrypt.mjs`

Offline decoder for the `jspl` field of a captured POST body. Given
`(ddjskey, jspl_base64url, request_timestamp_ms)`:

1. Reverses the custom base64-like alphabet
   (`H1DAxCvrj7IaPRL8GSJZKX3f62e9d0VTilFEOWgUB=/t+QmMwuskNnhpb4oyq5Yzc`).
2. Runs the Marsaglia-xorshift PRNG with seed
   `Date.now() >> 3 ^ 11027890091` and second seed from
   `hash(ddjskey)`.
3. XORs the keystream out.
4. Prints the TLV plaintext byte-for-byte.

Use this to verify the cipher reversal against a known capture from
`bypass.mjs`. ~5 sec.

### `netdump.mjs`

Full request/response log of every URL touching `datadome.co`,
`captcha-delivery.com`, `datado.me`, `api-js.datadome.co`. Body
capture for `*.datadome.co` only. Saves to `results/netdump.json`
and `results/netdump-bodies/`. Use to inspect the cookie-rotation
JSON response and any inline `dd` object on a 403 challenge page.
~1 min.

### `diff.mjs`

Given two plaintext-payload JSON files (the kind `bypass.mjs` and
`mitm.mjs` produce), prints:

- Total signal counts in each
- Signals present in only one
- Signals with different values (sorted alphabetically)
- A short "verdict-relevant deltas" section identifying the
  network-timing (`nt_*`), language (`lgs / wwl`), and behavioral
  (`nid / crt`) deltas

Use to compare a hard-blocked run vs a clean-verdict run, or to
A/B different network identities. ~5 sec.

---

## File layout

```
datadome-attack-bot/
├── README.md            ← this file
├── DataDome.md          ← the full reverse-engineering writeup
├── package.json
├── main.mjs             ← arrow-key menu launcher
├── recon.mjs
├── mitm.mjs
├── bypass.mjs           ★ the headliner
├── tamper.mjs
├── decrypt.mjs
├── netdump.mjs
├── diff.mjs
├── examples/            ← reference captures for diff / decrypt
│   ├── hard-blocked-plaintext.json   (202 signals, server verdict: hard_block)
│   └── clean-tmobile-plaintext.json  (201 signals, server verdict: t='d')
└── results/             ← created by scripts (.gitignored)
    ├── bypass.json
    ├── mitm.json
    ├── ...
```

## Known limitations

- **DataDome rolls `tags.js` periodically.** The v(n,t) chokepoint
  regex in `mitm.mjs` / `bypass.mjs` matches the v5.6.6 / v5.6.7
  bundle layout. If they refactor, the patch fails closed (script
  reports "v(n,t) header not found" and continues without the tap —
  the rest still works). Re-run `recon.mjs` after a hash drift to
  find the new entry point.
- **The bypass uses a residential mobile IP.** If you run from a
  data-center or already-flagged IP, you'll get `t='fe'` (interactive
  CAPTCHA) or `hard_block`. The harness reports the verdict but
  doesn't solve the CAPTCHA — that's a different problem.
- **Real Chrome required.** `channel: 'chrome'` not Chromium. The
  download happens automatically via `postinstall`. If it fails,
  run `npx playwright install chrome` manually.
- **No credential submission.** The bypass demos navigation only.
  Any post-gate auth would be a different threat model.

## Companion documents

- **[DataDome.md](DataDome.md)** — the methodology + findings
  writeup (the v5.6.6 reverse, every collector, the cipher, the
  Worker realm, the signed envelope, nine bypass surfaces).
- `~/Dev/DD-TO-ARGUS.md` — what to steal from DataDome for the
  argus stack: signals to adopt, detection patterns, hardening
  lessons.
- `~/Dev/CASTLE-TO-ARGUS.md` + `~/Dev/bots-x-castle/X.Castle.md` —
  the Castle parallel.
- `~/Dev/reading-list/datadome/` — 486 archived DataDome blog
  posts (via Wayback) for further reading.
