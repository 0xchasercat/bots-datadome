# DataDome Tag Reverse Engineering (v5.6.6)

*Source files: `script-analysis/tags.js` (115 KB, minified), `script-analysis/c.js` (14 KB, challenge bootstrap). Beautified to `tags.beautified.js` (2792 LOC) and `c.beautified.js` (406 LOC) with `npx js-beautify`. Line references throughout are to the beautified files.*

## TL;DR

- DataDome's bet is **request-pipeline interception + light per-call probes**, not heavy passive fingerprinting. The IIFE hijacks `XMLHttpRequest.open/send/setRequestHeader`, `fetch`, and `Request` constructor to insert a session header and to block (or replay) protected XHRs that come back with the `x-dd-b` header. Detection logic lives on the server; the client is a signal collector and a request shim.
- The on-page fingerprint runs in two phases: an **inline phase** that probes globals/screen/perf/audio-codecs/video-codecs/CSS/plugins, and a **Worker phase** that off-loads `navigator.userAgent / hardwareConcurrency / platform / userAgentData.mobile / languages / onLine` plus WebGL VENDOR/RENDERER and `Intl.DateTimeFormat().timeZone`. The Worker is built from an inline string and loaded via `Blob` + `createObjectURL` (line 1145).
- Three customer-tier keys unlock three orthogonal probe sets — Square refund-button watcher, browse-style mutation observer, and a Selenium-flavored sweep (`appAjaxCall` + `form[patched=true]` + extension HEAD probe). Most customers get **none** of these.
- The outgoing payload is a **bespoke stream cipher** keyed by `(jskey ^ stringHash(jskey) ^ 0x6c)` and `xorshift(Date.now() >> 3 ^ 11027890091)`, serialized as XOR'd JSON, then encoded in a **custom base64 alphabet** that varies per page-load. There is no AES, no public key, no cryptographic integrity — only obfuscation against passive replay.
- The script's blind spots are exactly the things FingerprintJS and Castle measure: no canvas/audio fingerprint, no font enumeration, no Performance.now lie scanning, no eval.toString length, no Proxy-detection. DataDome leans on TLS/IP/header signals (server-side) and a small set of "I know this bot tool by name" probes.

## 1. Architecture overview

The tag is a single IIFE `var DataDomeJsTag = (() => { ... })`. Internally it composes nine modules behind lazy initializers (`S, u, k, U, M, O, ...`). Once instantiated they wire up roughly like this:

```
window.dataDomeOptions   <- user config + defaults              (line 2719)
  d (EventStats sink)
  i = processSyncRequest  -> fires on `datadome-jstag-ch` event  (line 832)
  r = DataDomeEventsTracking (mouse/key/pointer/m_* signals)     (line 455)
  o = activator on `datadome-det-a`                              (line 2652)
  a = service-worker bridge (optional)                           (line 2664)
  e = exposeCaptchaFunction (window.displayDataDomeCaptchaPage)  (line 2639)
  + processAsyncRequests (XHR/fetch hooks)                       (line 842)
```

The XHR/fetch hooks are installed eagerly. Everything else is scheduled with a `setTimeout(fn,0)` micro-deferral or `requestIdleCallback` if the `useIdleCallback` option is set (line 2706).

The actual signal collector is `Y1` (line 2148), built once by an initializer that fans out across **47 distinct probe lambdas** organized into two arrays (`i1[0]` and `i1[1]`, see line 1138). Each lambda is wrapped in a `U()` try/catch (line 2258) so one failure can't take down the rest. After the lambdas have written their key/value pairs, the encoder (`r1`, line 2105) packs them into the body that gets POSTed to `https://api-js.datadome.co/js/`.

The Worker payload (line 1145) is an inline JS string. It is the *only* place navigator/WebGL/Intl is read. Everything that lives on `navigator` is funneled through a `postMessage` round-trip to a `Blob`-backed dedicated Worker, then revoked. This is a defense against `navigator` getters being overridden — but only if the override happens *after* `Worker` itself isn't also being intercepted (Worker construction wraps in `new Proxy` is rare in anti-detect tooling, so this is a meaningful obstacle).

The script also sprinkles an arithmetic-obfuscated decoder for its string tables: a custom base64 alphabet `H1DAxCvrj7IaPRL8GSJZKX3f62e9d0VTilFEOWgUB=/t+QmMwuskNnhpb4oyq5Yzc` (line 2212, function `A`) decodes integer indices into `s1[]`, while `J` (line 2205) does plain base64 over `f1[]`. Every string lookup is wrapped in arithmetic identities (`-1 * (t & n) + ...`) whose value is always a constant — the compiler can fold them but a casual reader can't. ~900 strings live in those two tables; the names of every signal, every webdriver tell, every codec test are recoverable in seconds with a 30-line decoder.

## 2. Customer-specific gating (ddjskey)

Customers are partitioned into branches by their `window.ddjskey` (a 30-char hex string). Five gates were observed:

| Key | Branch | Action |
|---|---|---|
| `2211F522B61E269B869FA6EAFFB5E1` | `o()` (line 762) | Read cookie `correlation_id` into `uid` signal |
| `E6EAF460AA2A8322D66B42C85B62F9` | `i()` (line 724) | Watch DOM for `[data-testid=auth-modal--overlay]` or `.auth__container`, fire fingerprint collection on appearance of the auth form's submit button |
| `2D56F91C2AD1A8EB7C6A5CA65F5567` | `a() + u() + f()` (line 766–820) | Square-refund-button watcher, Selenium/automation watcher (`appAjaxCall` + `form[patched=true]`), and Overjet extension HEAD probe |
| `499AE34129FA4E4FABC31582C3075D` | line 717 | If >1 `datadome=` cookie present, call `deleteAllDDCookies()` |
| `1F633CDD8EF22541BD6D9B1B8EF13A` | line 954 | Special fetch invocation: `X.apply(window, s)` instead of `X.apply(this, s)`, and emit `nowd` signal recording whether `this === window` at call time |
| Seven hashes in `popUpAllowedClientKeys` | `c.js` line 3, also `r` in tags line 306 | Captcha iframe gets `sandbox="... allow-popups"` |
| Six hashes including `00D958EEDB6E382CCCF60351ADCBC5` | line 717 | If exactly 2 `datadome=` cookies AND URL contains `www.`, expire the parent-domain cookie |

The keys are short, deterministic, and visible in any page-source view — they're effectively public tenant IDs, not secrets. The *interesting* asymmetry is that DD ships a single tag for all customers but every customer runs slightly different code paths gated on these keys. This means: **(a)** if you're collecting traffic from one tenant for analysis, you can't assume another tenant's tag does the same thing, and **(b)** the per-tenant gating is a fingerprint of its own — a server-side check that the right gates fired on the right key would catch tag tampering.

### Surprising findings

The `2D56F91C2AD1A8EB7C6A5CA65F5567` tenant — whatever it is — gets a HEAD request fired at `chrome-extension://oojibhnkahnabembdeoicblilpbfmnhg/icon.0024de64.png` (line 816). That extension ID resolves to **Overjet's dental-AI browser extension** (per the Chrome Web Store). The probe sets `obe=true` if HTTP 200 comes back. The most plausible read is that DD's customer here is in dental insurance and they want to know which dentists have Overjet installed — i.e., a *defensive* probe to flag automated-claim submission. Worth noting: an extension-ID probe is **detectable** by a vigilant extension developer who watches their own asset URLs, and tells DD's customer something the visitor's browser explicitly chose not to advertise. There may be a TOS issue depending on jurisdiction.

## 3. Per-signal walkthrough

The signal table is too large to walk exhaustively (47 probes × N keys each). I'll cover by category, naming the line and the prefix-key convention DD uses (`m_*` = behavioral motion, `nt_*` = nav timing, `k_*` = key dynamics, `p_*` = pointer events, `cf*` = caller-frame, `vc*/ac*` = video/audio codec, `cssH/S/0/1` = CSS-shape, `rs/sg/cg/ars/br` = screen rect dimensions, `pl*` = plugins, `wdif*` = webdriver-iframe, `cp*` = HTMLVideoElement codec probes).

### 3.1 Navigator / platform reads (Worker-only)

Inline Worker body (line 1145):

```js
e.ua  = navigator.userAgent
e.hc  = navigator.hardwareConcurrency
e.pf  = navigator.platform
e.mob = navigator.userAgentData?.mobile : "NA"
e.lgs = JSON.stringify(navigator.languages)
e.onL = navigator.onLine
```

Plus a second Worker job that grabs WebGL `VENDOR`/`RENDERER` via `OffscreenCanvas(1,1).getContext("webgl")`, branching on a Firefox-91+ check (since Firefox 91 stopped exposing `WEBGL_debug_renderer_info` to non-privileged contexts; DD falls back to the plain `VENDOR`/`RENDERER` strings, which are deliberately generic in modern Firefox — `Mozilla` and `Mozilla`). A third Worker job calls `Intl.DateTimeFormat().resolvedOptions().timeZone`.

The Worker round-trip is wrapped in a "panic" check: if `userAgent` was set on the Worker payload, then either it was overridden post-Worker-construction (caught by comparing main-thread `navigator.userAgent` against Worker-thread `navigator.userAgent` in the `dil` signal at line 2024) or it wasn't. Discrepancies set `dil` with both UA strings concatenated.

**Bypass:** Hook `Worker` and `Blob` constructors to intercept the source string. Easier: hook `URL.createObjectURL` and inspect the `Blob` contents. The Worker source is a literal in `tags.js` so it doesn't change shape across page-loads — a static rewrite at injection time is feasible.

### 3.2 Behavioral counters (m_*)

In `DataDomeEventsTracking` (line 455). Tracks the 9-event list `["mousemove","pointermove","click","scroll","touchstart","touchend","touchmove","keydown","keyup"]` (line 465). When the page is about to unload OR 10 seconds after the first event, fires `X(...)` which writes:

- `m_s_c` = scroll count (line 479)
- `m_m_c` = mousemove count
- `m_c_c` = click count
- `m_cm_r` = click/mousemove ratio (-1 if no mousemove)
- `m_ms_r` = mousemove/scroll ratio (-1 if no scroll)
- `uish` = FNV-1a 32-bit hash of the joined counter string `ceil(mm/10)_ceil(tm/10)_scroll_click_(kd>0?1:0)_(ku>0?1:0)` (line 511)

Plus the deeper analyzers (line 540 `g()` `handleEvent`):
- `m_fmi` (mouse-fingerprint identical) — true if first mousemove had `pageX===screenX && pageY===screenY`, i.e., a coordinate-spoofing tell where someone forgot to offset the synthetic event for window position
- `m_scw, m_sch` — from a one-shot mousemove listener (line 1329): `screenX - clientX - window.screenX` (and Y). For real users this is 0 (or close); for synthetic events it leaks the spoofer's offset bug.
- `m_pp` — pointer pressure on the first mouse `pointerdown` (line 2013). For real mice this is 0.5 by spec; touch is non-zero; a digitizer is variable.

Stroke analysis (line 575 `c()` class `mouseAnalyzer`):
- `es_sigmdn` = median sigma of log-timestamps within each "stroke" (>500ms gap = new stroke)
- `es_mumdn` = median mu of same
- `es_distmdn` = median Euclidean displacement
- `es_angsmdn, es_angemdn` = median start/end angles of each stroke (using the 4th and 4th-from-last points)

Pointer analysis (line 619 `e()` `pointerAnalyzer`):
- `p_fc` = count of pointermove frames seen
- `m_clsdcnt` = total coalesced sub-events
- `p_cf, p_cmx, p_ps, p_pf` = coalesced-frame count, max coalesced in any frame, predicted-sum, predicted-frame count

Key analysis (line 642 `i()` `keysAnalyzer`):
- `k_hA, k_hSD` = mean and SD of key hold time (down-to-up)
- `k_pA, k_pSD` = mean and SD of key-press interval (down-to-down)
- `k_rA, k_rSD` = mean and SD of release interval (up-to-up)
- `k_ikA, k_ikSD` = mean and SD of inter-key bigram timing (next keydown after previous keyup, restricted to repeated keys)
- `k_kdc, k_kuc` = total keydown/keyup counts

**Cite:** all m_* in line 479; stroke analyzer in lines 602–616; key analyzer in lines 656–691.

These are the strongest signals DD ships. A bot that sends zero motion gets caught by ratio = -1; a bot that sends fake motion is caught by the FNV hash being too clean, by `m_fmi=true` if screenX==pageX, and by the stroke-angle/sigma not matching the human distribution.

### 3.3 Extension probe (`obe`)

Gated to one tenant. `f()` at line 814:
```js
var n = new XMLHttpRequest;
n.open("HEAD","chrome-extension://oojibhnkahnabembdeoicblilpbfmnhg/icon.0024de64.png");
n.onload = function() { if (200===n.status) r.t("obe", true); };
n.send();
```

That's it. A real browser can't HEAD an arbitrary `chrome-extension://` URL unless the extension declared `web_accessible_resources` for that path. Overjet evidently did. If you're the bot side and the extension isn't installed, the HEAD throws CORS/NS_ERROR and `obe` is never set, so the *signal* is "presence confirmed", not "presence denied" — null reads dominate.

### 3.4 Form-patched / `appAjaxCall` detector

Function `u()` at line 781 (one-tenant-gated alongside the extension probe):

```js
document.documentElement.addEventListener("appAjaxCall", function() { n(2); });
// poll every 100ms: if any form has setAttribute("patched","true"), set nhbe=1
var i = setInterval(function() { e() && n(1); }, 100);
setTimeout(function() { t(); }, 60000);  // 60s cleanup
```

So:
- `nhbe=1` if any form element ever has `patched="true"` attribute
- `nhbe=2` if a custom `appAjaxCall` event fires on `<html>`

This is a fingerprint of a **specific automation harness**, not a general bot tell. I could not confidently attribute it. Across multiple WebSearches (`"appAjaxCall" form patched`, GitHub-scoped, plus PhantomBuster/Octoparse/Browse.ai/Imperva phrasings), no public index surfaced this combination. The closest hits were generic XHR-interceptor extensions like xhook and easy-interceptor — neither uses the `patched` attribute or this event name.

The pattern (mark a form as "patched" to avoid double-instrumenting it, then dispatch `appAjaxCall` when the patched form fires an XHR) is consistent with **userscript-style scrapers** (Tampermonkey/Violentmonkey userscripts that wrap form submission to intercept the POST). The `patched` attribute is a common idiom for any monkey-patching script that needs to know it's already wrapped a given element. My honest read: **this is probably a private automation tool used against one of DD's customers, and DD has reverse-engineered its hook signature.** Without an example sample I cannot name it.

**Bypass:** trivial. Use a different attribute name and a different event name. The probe is a denylist of *one*.

### 3.5 WebDriver / known-driver-property sweep

`f()` and the interval-polled scan at line 1707–1736. Hardcoded list of known property names that get injected by Selenium/Watir/etc., checked on both `window` and `document`:

```
__driver_evaluate, __webdriver_evaluate, __selenium_evaluate, __fxdriver_evaluate,
__driver_unwrapped, __webdriver_unwrapped, __selenium_unwrapped, __fxdriver_unwrapped,
_Selenium_IDE_Recorder, _selenium, calledSelenium, $cdc_asdjflasutopfhvcZLmcfl_,
$chrome_asyncScriptInfo, __$webdriverAsyncExecutor, webdriver, __webdriverFunc,
domAutomation, domAutomationController, __lastWatirAlert, __lastWatirConfirm,
__lastWatirPrompt, __webdriver_script_fn, __webdriver_script_func,
__webdriver_script_function, _WEBDRIVER_ELEM_CACHE
```

(Decoded from `s1[642..665]`.) Sets `slat=true` and fires `M("datadome-det-a")` (an internal event that triggers a *separate* request with `jsType="ac"` — a second beacon specifically to flag automation, line 2652).

A `setInterval(...,150)` also iterates `Object.keys(document)` looking for any key starting with `$cdc_` (the legacy Chromedriver instance variable). Plus another sweep checks `document[e].cache_` for an iframe key matching the UUID regex `[\d\w]{8}-[\d\w]{4}-...` (line 688) — that's a fingerprint of `Apify` or similar wrappers that name iframes by UUID.

### 3.6 Document/window property invariant checks

These are the "shape" checks (line 1130+ and elsewhere):

- `cssS, css0, css1, cssH` (line 1810) — DOM probe. Creates a `<div>`, attaches a CSS rule with nine `--x0..--x8` CSS custom properties set to `Math.random().toFixed(2) + suffix`. Reads back `getComputedStyle` color, transform, and height. Anti-detect browsers that override `getComputedStyle` get caught when the readback doesn't match the input.
- `vchts, vch, vco, vcw, vcwts, vc3, vc3ts, vcmp, vcmpts, vc1, vc1ts, vcmk, vcmkuts, vcq, vcqts, vc_NA` (line 1777) — `HTMLVideoElement.canPlayType(mime)` for codecs theora, H.264, VP8/vorbis, AV01, MPEG-1/2, x-matroska, quicktime. Plus the same probes against `MediaSource.isTypeSupported`. Discrepancies between the two are diagnostic (real browsers return *consistent* answers; spoofers often only patch `canPlayType`).
- `acwts, ac3, acmp4, acma, acmats, acmpu, acmputs, acw, acmp3, acmp3ts, acwmts, acwm, ac3ts, acaa, acaats, aco, acots, acmp, acmpts, acf, acfts, acqt, acqtts, ocpt, ac_NA` (line 1916) — same battery on audio MIME types: wav, mp3, mp4, aac, m4a, webm, flac, x-m4a, ogg/vorbis, 3gpp, mpegurl, ac3, mpeg, quicktime.
- `mq, mq2` (line 2004) — `window.matchMedia`-based checks for `any-pointer:fine/coarse`, `any-hover:hover/none`, `color-gamut:rec2020/p3/srgb`, `dynamic-range:high/standard`, `display-mode:standalone/fullscreen/minimal-ui/browser`. Encoded as concatenated tokens.

### 3.7 Webdriver and headless detection

- `wbd` (line 2493 / `i[A(897)]=!!c[A(628)]`) — straight `navigator.webdriver` read from the Worker context.
- `bid` — `navigator.buildID` (only Firefox exposes it; spoofed Firefoxes often have wrong/missing values).
- `vnd` — `navigator.vendor` (`Google Inc.` for Chrome, empty for Firefox/Safari).
- `isb` — `!!navigator.brave` (Brave shipped a global as detection-bait, ironically).
- `idp` — `!!window.IdleDetector` (Chromium-only API).
- `med` — `!!navigator.mediaDevices`. If absent, fingerprints down because `getUserMedia` is a fundamental modern API.
- `pltod` — `!!Object.getOwnPropertyDescriptor(navigator, 'platform')` (true if `platform` is on `navigator` itself rather than the prototype — a tell for `Object.defineProperty(navigator, 'platform', ...)` overrides).
- `ihdn`, `cdhf` — `document.visibilityState` from `performance.getEntriesByType('visibility-state')`, and `document.hasFocus()`. Headless browsers typically report "visible" and have focus even when not interacted with.

### 3.8 Plugin / mime sweep

`plu` (line 1271) — `navigator.plugins` joined names. `npmtm` (line 1681) — checks if `navigator.plugins`, `navigator.plugins[0]`, `navigator.mimeTypes`, `navigator.mimeTypes[0]` are instances of `Plugin`/`PluginArray`/`MimeType`/`MimeTypeArray` respectively. Spoofers that fake the plugin array with a plain object get caught.

`plggt, plgne, plgof, plgod, plgre, plg` (lines 1300–1308) — deep PluginArray sanity checks: `plugins[0].name === plugins[0][0].enabledPlugin.name`, `plugins[0][0].enabledPlugin === plugins[0]`, `plugins.item("Return") === plugins[0]`, and a `getOwnPropertyDescriptor(navigator).plugins.get.toString().indexOf("return") > -1` test (the Chrome built-in plugins getter has the word "return" in its source — spoofed getters often don't).

### 3.9 Defined-globals bitmap (`md`)

Line 1853 ("missing definitions") — walks a list of ~120 constructor/API names and produces a string of hex characters indexed against a hardcoded reference `52738db37a1ea50137e79e8181193ac872cd325ba5cacfbe7aab5b36b9c9879e7c0018dbd31a1832a8dc6528387b67451719dcd8b784a518904e3f07c69b9d30` (f1[143]). For each constructor in the list: if defined on `window`, emit reference[i]; if not, emit fallback hex (s1[874] = `3829ae9642...`).

Constructors include `AudioData, NavigatorUAData, BarcodeDetector, ContactsManager, MathMLElement, TextDecoderStream, TextTrackCue, WeakRef, VTTRegion, Controllers, IIRFilterNode, ServiceWorkerContainer, WorkerMessageEvent, URLPattern, VideoFrame, CustomStateSet, MediaMetadata, FragmentDirective, VideoTrackList, SourceBuffer, MediaDeviceInfo, RTCSctpTransport, MediaSessionCoordinator, AppBannerPromptResult, webkitRTCPeerConnection, webkitAudioContext, webkitRequestAnimationFrame, chrome.runtime, chrome.webstore, console.context, InputMethodContext, ...` — a `md` mismatch is highly diagnostic. The reference appears to be computed against vanilla Chrome.

This is **the strongest passive signal** DD ships in 2026. Every browser/platform/anti-detect-tool has a slightly different constructor inventory.

### 3.10 Stack-trace probe / `cfpp`, `cfcpw`, `cfse`

Lines 1593–1634 monkeypatch `document.getElementById, getElementsByTagName, querySelector, querySelectorAll, document.evaluate, XMLSerializer.prototype.serializeToString` with a wrapper that, on call, builds a stack trace via the `Error().stack` mechanism (using `Error.prepareStackTrace` if available — line 2309 `y1()` builds the stack-collector).

For each line in the stack, regex-tests:
- `puppeteer|pptr:|ElementHandle|evaluateHandle` → `cfpp=true`
- `eval\sat\sevaluate` → `cfcpw=true`
- `eval\sat\sexecuteScript` → `cfse=true`

Then fires `M("datadome-det-a")`. Also captures the caller's `Function.prototype.toString()` (`arguments.callee.caller.toString()`) and tests it for patterns that resemble obfuscated bot frameworks (`function (){var _0x` and `function(){var _0x` are common obfuscator outputs from javascript-obfuscator.io), and for site-specific allowlist patterns (`var contactSupportComment`, `var humanCommentEl`, `iframe_api`, `ga-disable-`, `iadvize-container`, `useForcedLinkTracking`, `dot-optimeeze`) that legitimate page scripts use. If none match and the caller looks like an obfuscated wrapper, the caller-toString gets sliced (150 chars) and sent as `cfpfe` (caller-frame patched function evidence) or `stcfp` (stack-traced caller-frame pattern).

The probe is limited to ~563 invocations (counter `d` at line 1595 starts at 563 and decrements per call); after that it no-ops. This is to avoid generating gigabytes of stack traces on real pages.

`iccsH` = string hash of the stack contents; `iccsV` = caller chain compressed via `b1()` (line 2331 — joins consecutive `Error.stackTraceLimit`-walked frame URLs with deduplication).

This is DataDome's closest analog to Castle's "lie detector," but it's narrower: it looks for *Puppeteer frame names in the stack*, not for `eval.toString().length === 33` or `Function.prototype.toString` lies.

### 3.11 Brave-shield / V8 stack-shape probe (`dp0`)

`isb` is just `!!navigator.brave`. There is no console.log/console.debug patch detection.

The script does, however, contain an unusual probe in `dp0` (line 1422): construct a custom `Function` subclass `s`, set its prototype, then read `s.prototype.stack` via a getter. If the getter increments `i` correctly, `dp0` stays false; if not, true. The exact intent is unclear (the variable's value is incremented inside a getter that returns empty string and is forced via `console.debug(f)`), but it appears to be a v8-vs-non-v8 stack trace shape probe.

### 3.12 Cookie / CSP / iframe probes

- `ckwa` (line 1913) — sets `dd_testcookie=1` then reads it back; if the cookie sticks, ckwa=true. Tests whether cookies are writeable.
- `dd_testcookie` is then expired (line 916). A bot that filters all `Set-Cookie` returns will not see `ckwa=true`.
- `wdifrm`, `wdifpnh`, `wdif` (line 2496 + 1755) — DD creates a hidden `<iframe srcdoc="/**/" style="display:none">`, attaches it to head, then in the iframe's `contentWindow` re-runs the `c(navigator)` reader. Compares the iframe's `navigator.userAgent / platform / vendor / languages / hardwareConcurrency / maxTouchPoints / deviceMemory / userAgentData.mobile` against the parent's. Any mismatch is recorded as a serialized diff in `wdifrm` (parent-vs-iframe), with the SHA-style hash in `wdifpnh`. Anti-detect browsers that override navigator props on `window` but not on a freshly-spawned iframe get caught here.

### 3.13 Synthetic-debugger globals (`ucdv`)

Line 1422 — reads `objectToInspect` and `result` from the page's global scope. These two names don't exist on a normal page; they're injected by older versions of certain SDKs. Returns true if both globals are present and `objectToInspect === null` (the "in-progress evaluation" tell of one specific debugger).

### 3.14 Battery, storage, permissions

- `bci, bcl, bdt` (line 1250) — `navigator.getBattery()` → charging, level, chargingTime, dischargingTime. Battery API was removed from many browsers; if missing, all four signals are skipped.
- `stqe, stqu` (line 1638) — `navigator.storage.estimate()` → quota, usage. Returns -1 if missing.
- `nhi` (line 1174) — `navigator.userAgentData.getHighEntropyValues(["architecture","bitness","model","platformVersion","platform","wow64"])`, joined.
- `k_lytk` (line 1192) — `navigator.keyboard.getLayoutMap()` → sum of all character codes (sic — they sum, not hash). Used to differentiate keyboard layouts.
- `emd` (line 1213) — `navigator.mediaDevices.enumerateDevices()` → categorized: deviceId/groupId/label tails for audioinput (ai), audiooutput (ao), videoinput (vi). Permissions API queries for microphone/camera first to see whether labels are exposed.
- `psd` (line 1259) — `permissions.query({name:"name-string"})` and key fingerprinting via a `Function.prototype.bind` Proxy that flags atob-of-"pxsid" (base64 of "pxsid"). Detects PerimeterX-style polyfills.

### 3.15 Performance navigation timing (nt_*)

Line 1577–1592 — pulls from `performance.getEntriesByType("navigation")[0]`:

- `nt_tcp` = `connectEnd - connectStart`
- `nt_dns` = `domainLookupEnd - domainLookupStart`
- `nt_rd` = `redirectEnd - redirectStart`
- `nt_irt` = `firstInterimResponseStart - requestStart`
- `nt_rt` = `responseStart - requestStart`
- `nt_tls` = `requestStart - secureConnectionStart`
- `nt_ttf` = `responseEnd - fetchStart`
- `nt_swt` = `domContentLoadedEventStart - workerStart`
- `nt_csd` = `decodedBodySize - encodedBodySize` (compression ratio)
- `nt_nhp` = `nextHopProtocol`
- `nt_rdc` = `redirectCount`
- `nt_it` = `initiatorType`
- `nt_prs` = `requestStart - connectEnd`
- `nt_esc` = `secureConnectionStart - connectStart`
- `nt_ttrd` = `(prs - esc) / esc` (TLS handshake ratio)
- `nt_le` = `loadEventEnd - loadEventStart`
- `nt_dcle` = `domContentLoadedEventEnd - domContentLoadedEventStart`
- `nt_di` = `domInteractive`
- `nt_dc` = `domComplete`

These are diagnostic of the rendering environment: headless Chrome has measurably different timing distributions than headed Chrome (no compositor scheduling, faster paint).

### 3.16 Anti-detect browser direct probes

Many of the inline probes have explicit anti-detect browser strings baked in (lines 2007–2031):

- `awe` = `!!window.awesomium`
- `phe` = `!!window.callPhantom`
- `dat` = `!!window.domAutomation`
- `nm`  = `!!window.__nightmare`
- `geb` = `!!window.geb`
- `sqt` = check `window.external.toString().indexOf("Sequentum")` — Sequentum is a commercial scraping tool
- `spwn` = `!!window.spawn`
- `emt` = `!!window.emit`
- `isf` = headless detection via `window.outerHeight - window.innerHeight <= 1`
- `isf2` = `window.matchMedia("(display-mode: fullscreen)").matches` — kiosk-mode tell
- `pw`  = checks for `__playwright_builtins__, __pwInitScripts, __playwright__binding__, __pwWebSocketDispatch, __playwright__binding__controller__`. **This is a direct Playwright fingerprint.**
- `pcb` = Perplexity-agent-style overlay element (`#pplx-agent-0_0-overlay-stop-button`)
- `arc` = checks for the `--arc-palette-title` CSS custom property — the **Arc browser** ships it
- `fai` = `!!window.FELLOU_PARTITION || !!window.__FELLOU_TAB_ID__ || !!window.FELLOU_WEBVIEW_PRELOAD_PATH` — **Fellou agentic browser**
- `gai` = `!!window.genspark` — **Genspark agentic browser**
- `sgb` = `!!window.__stagehandV3__ || (Element.prototype.attachShadow has been wrapped)` — **Stagehand** (the open-source AI browser-automation lib)
- `cld` = MutationObserver watches for `claude-agent-animation-styles` ID OR any element with `data-browser-use-highlight / -interaction-highlight / -coordinate-highlight` — **Browser Use** (open-source LLM agent) AND **Anthropic Claude Code** (the agent-animation injection)

This is a remarkably *current* list. Stagehand, Browser Use, Genspark, Fellou, and the Claude Code injection are all 2024-2026 additions. DD is actively reverse-engineering agentic browser tools as they ship.

### 3.17 Cross-iframe navigator comparison (`dil`)

Line 2030 — creates an iframe, reads `iframe.contentWindow.navigator.platform`, compares to `window.navigator.platform`. If different, emits `dil` with the concatenated values. Anti-detect browsers that monkey-patch the top-frame navigator but forget to patch iframes get caught instantly.

The iframe is removed from the DOM after the check.

### 3.18 Battery / process / opener checks

- `ecpc` = `!!window.process` (true in Electron, NW.js, Node-context)
- `wop`  = `!!window.opener` (window was opened by another)
- `tz`   = `new Date().getTimezoneOffset()` — compared server-side against the Worker's `Intl.timeZone`
- `xt1`  = always-skipped (literally `String.fromCharCode(120,116,49)` is the value the encoder refuses to emit — it's a sentinel)
- `r3n` = a pseudorandom integer (between 0 and 32) derived from `window._hsv` if present, else from the cipher state. Encoded *only* as the second key in the payload — that's the cipher's "I'm alive" beacon.

## 4. Payload schema

The body POSTed to `https://api-js.datadome.co/js/` is `application/x-www-form-urlencoded` and has the shape (line 442–447):

```
jspl=<encoded_blob>
&eventCounters=<JSON of {mousemove:N,pointermove:N,...}>
&jsType=<le | fm | ch | ac>
&cid=<datadome cookie value if present>
&ddk=<window.ddjskey, double-encoded>
&Referer=<page URL with patternToRemove stripped, truncated 1024>
&request=<location.pathname+search+hash, truncated 1024>
&responsePage=<options.ddResponsePage>
&ddv=5.6.6
&custom=<options.customParam if set>
```

`jspl` is the only encrypted part. Encoding pipeline (line 2105 onward):

1. Build a session key `n = e ^ stringHash(jskey) ^ V`, where `e=0x6c` (`s1[1104]`), `V` is a per-page-load constant from the probe table (`i1[2].V = 0x6d` typically), and `stringHash` is a 32-bit `(h<<5)-h+charCodeAt` rolling hash.
2. Build a per-page IV `f = xorshift(xorshift(Date.now()>>3 ^ 11027890091) * e)`. (`xorshift = (n^=n<<13)^(n>>17)^(n<<5)`.)
3. Initialize a 24-bit `c=n` keystream generator `s(consume)` that emits one byte per call: `c = xorshift(c)` every 3 calls, the byte is `(c>>(16-8*e)) ^ (r ? --i : 0)`.
4. Build the body byte-by-byte: open with `{` XORed with the next keystream byte, then for each `(key,value)` pair emit `(d.length ? ',' : '{') ^ stream`, then `i(JSON.stringify(key))` (UTF-8 encoded, each byte XORed with stream), then `':' ^ stream`, then `i(JSON.stringify(value))`. Close with `}` XORed with stream.
5. Re-XOR the entire buffer with a *second* keystream `t` keyed by `1809053797 ^ stringHash(jskey)` and IV `f`. (This double-XOR is what makes the encoding robust against keystream recovery via known plaintext: the JSON structure is predictable but the cipher state is rotated.)
6. Encode the result in a custom-alphabet base64 using `w(n)`: `37<n?59+n : 11<n?53+n : 1<n?46+n : 50*n+45`. That maps 0..63 to a 64-character set starting with `-./0...9:;...` (i.e., **not** standard base64). The cipher state `a=f` is decremented per byte and XORed into the triplet during base64 packing.
7. The result is appended to the URL as `jspl=`.

There is **no integrity check, no HMAC, no public-key signature**. Anyone with the encoder logic (which I've just walked) can produce arbitrary forgeries. The only thing keeping the channel honest is the per-page-load IV plus the bot's inability to predict what value `_hsv` was set to (DD-controlled global, fingerprint-influenced).

The first emitted field is always `r3n` (a pseudo-random spice value) — the encoder coerces it (line 2129). The last emitted field is always `bpc` (block-payload counter, incremented per encode-call) — useful for replay-detection server-side because a second submission from the same session should have `bpc=2` etc.

`eventCounters` is plaintext and exists for the server to cross-check against the inside-`jspl` `m_*` counters. A bot that fabricates `m_*` inside `jspl` but forgets to update the outer counter is trivially caught.

`jsType` values:
- `le` = load event (first beacon)
- `fm` = form-mutation (the auth-modal-watcher tenant fires this)
- `ch` = challenge (after `datadome-jstag-ch` event)
- `ac` = automation-detected (after `datadome-det-a` event fires — sent *separately* and immediately)

## 5. Cookie / identity flow

Cookie name: `datadome`. Set by the server response from `api-js.datadome.co`. The cookie attributes include `Partitioned` (CHIPS), `SameSite=None`, `Secure`. The client handles cookie-domain fallback by trying progressively-broader domain candidates (`.b.c.example.com`, `.c.example.com`, `.example.com`, etc.) and remembering the working one in `sessionStorage['ddCookieCandidateDomain']` (line 79).

There's also a parallel "session-by-header" mode (`window.ddSbh`) where instead of relying on the browser to store the cookie, DD reads it from `x-set-cookie` / `x-sf-cc-x-set-cookie` response headers and stuffs it into `localStorage[ddCookieSessionName]`, then injects it as an `x-datadome-clientid` request header. This is for environments where cookies can't be trusted (Salesforce, mobile WebViews, browser extensions, third-party-cookie-blocked contexts).

The `x-dd-b` and `x-sf-cc-x-dd-b` response headers carry a 16-bit verdict packed as: low byte = action (1=block, 2=hard_block, 3=device_check), high byte bit 0 = invisible-mode flag for device_check. The header is bitwise-masked (`255 & t`) so the high bits can carry routing flags without changing the action (line 195).

When a verdict comes back, the script either displays the captcha iframe (line 384) or replays the original XHR after the challenge passes (lines 873, 998). Replay-after-challenge is conditionally enabled via `options.replayAfterChallenge`. The replay mechanism captures `originalRequestHeaders`, `originalSendArgs`, `originalOpenArgs` *during the first call*, holds them until the challenge dispatches `dd_replay_request`, then re-opens the XHR with the new session cookie injected.

## 6. Challenge orchestration (c.js)

`c.js` is the bootstrap that runs *inside* the captcha response page (the HTML returned with `x-dd-b: 0x01` or similar). Its job is to build the captcha iframe with the right query parameters, listen for `postMessage` from the captcha origin, and on success either reload the original page, replay the original POST, or `history.back()` based on the verdict.

The iframe URL is `https://${dd.host}/captcha/?initialCid=${cid}&hash=${hsh}&cid=${cookie}&t=${t}&referer=${parent_url}&s=${s}&e=${e}&dm=cd`. The `dd.host` is checked against an origin allowlist before instantiation: must end in `.datado.me` or `.captcha-delivery.com`, OR match the `ddc.<currentdomain>` first-party-fingerprint pattern. **Origin validation is on the iframe creation, not on the `postMessage` source** — but line 331 *also* validates `event.origin` against the same allowlist for incoming messages, so cross-origin spoofing is blocked.

The `postMessage` handler accepts JSON with `cookie` (sets it), `url` (triggers reload/replay/back/etc.). The cookie-set step uses the same domain-walk fallback as the parent: try the exact domain, then strip subdomain components until the set sticks.

The bootstrap also sets up Firefox-specific iframe-load fallback: if the iframe hasn't fired its `load` event within 5 seconds, replace the page body with a "captcha didn't load" message (line 222–233). Firefox-only because Safari/Chrome don't have the same iframe-load timeout flakiness.

A few interesting parts of c.js:

- `popUpAllowedClientKeys` (line 3) — 7 customer keys get `allow-popups` in the iframe sandbox. These are presumably high-traffic customers whose users hit popup-based captchas. Tenant-fingerprint-by-side-channel.
- Original document referrer is saved to `sessionStorage['ddOriginalReferrer']` and restored on the next page via `Object.defineProperty(document, "referrer", { get: () => storedValue })` (in tags.js line 2712). This preserves referrer across the captcha redirect.

## 7. Asymmetry vs Castle

**Castle's strengths, DD's weaknesses:**

| Castle measures | DataDome (this version) |
|---|---|
| `eval.toString().length` (V8 vs SpiderMonkey vs JavaScriptCore signature) | not measured |
| `Performance.now()` resolution / monotonicity / native-shape check | not measured |
| `console.log` / `console.dir` patch detection (CDP serialization timing) | not measured |
| `Function.prototype.toString` lie scanning across N native APIs | spot-check via stack-trace regex only |
| Proxy detection via behavioral re-throw (`Performance.now.call({})` should throw) | not measured |
| Cross-iframe `window.chrome` / native-array prototype comparison | partial (iframe navigator only) |
| Direct CDP detection (`Runtime.evaluate` argument-shape timing) | not measured |
| WebRTC IP leak | not measured |

**DataDome's strengths, Castle's weaknesses (in published analyses):**

| DataDome measures | Castle |
|---|---|
| Per-customer probes (Overjet extension, Square refund button, auth-modal MutationObserver) | not customer-tiered |
| Concrete anti-detect browser strings (Sequentum, Stagehand, Browser Use, Genspark, Fellou, Arc, Perplexity, Brave, Claude Code) | smaller named-tool list |
| Stack-trace regex against Puppeteer frame names | similar (both scan stacks) |
| `m_fmi` + `m_scw/m_sch` mouse-coordinate-spoof tells | basic mouse heuristics |
| Behavioral stroke analysis (sigmas, angles, distances) per "stroke" | event-counts only |
| Key bigram timing variance (k_ikSD) | not measured |
| XHR/fetch hijack + automatic challenge-replay flow | passive only |
| Audio + video codec battery + canPlayType vs isTypeSupported divergence | smaller probe set |
| WebGL VENDOR/RENDERER from inside a Worker (bypasses main-thread overrides) | main-thread only |

**Where they agree:** both look at `navigator.webdriver`, `navigator.plugins` shape integrity, automation-property names, and `chrome.runtime` presence. Both fire a "second beacon" when automation is detected (DD's `datadome-det-a` → jsType=ac; Castle's similar pattern).

The deeper philosophical asymmetry: **Castle treats the browser as an adversary and lies-detection-first; DataDome treats the network/request layer as the moat and signal collection as evidence-for-the-server.** DD ships much more *code* (115 KB unpacked) but it's mostly request-shim plumbing — actual probes are surprisingly thin. Castle's payload is smaller but each probe is tighter and more anti-anti-detect-aware.

## 8. Asymmetry vs FingerprintJS

FingerprintJS is the canonical *passive* fingerprinter. Its goal is "every browser is a unique snowflake; the fingerprint persists across sessions." DataDome's goal is "this current request is or isn't a bot."

| FingerprintJS measures | DataDome |
|---|---|
| Canvas rendering hash (text + emoji + geometry) | **not measured** |
| Audio rendering hash (DynamicsCompressor pipeline) | **not measured** |
| Font enumeration (200+ font availability probes) | only `fonts.add()` round-trip (dffls) |
| WebGL parameters (50+ parameters hashed) | only VENDOR + RENDERER |
| Hardware concurrency, deviceMemory, maxTouchPoints | yes (matched) |
| Timezone, language, platform | yes (matched) |
| Plugins array (shape and content hashed) | shape integrity but no content hash |
| Screen dimensions + colorDepth + pixelRatio | yes (matched) |
| WebRTC local IP enumeration | **not measured** |
| Battery state, hardware sensors | partial (battery only) |
| `localStorage` / `sessionStorage` / `indexedDB` writeability | partial (cookie-only) |
| WebAuthn `isUserVerifyingPlatformAuthenticatorAvailable` | no |

FingerprintJS is trying to identify a returning visitor across cleared cookies; DD is trying to gate a single transaction. FingerprintJS is willing to compute a 200ms canvas hash on every page-load because they bill for it. DataDome can't afford the latency hit on every customer page-load, so they push the slow stuff (TLS fingerprint, ASN reputation, IP class) server-side.

**The net effect:** a bot can pass DD's tag and fail FingerprintJS (they'd notice canvas drift across sessions); a bot can pass FingerprintJS by stably faking one canvas seed and still fail DD's `appAjaxCall`/`m_scw` checks. Two non-overlapping circles of detection. Customers who want both buy both.

## 9. Bypass opportunities (defender notes)

(Notes for someone *building competing detection*, not for someone evading DD.)

1. **The cipher has no integrity.** A forgery only needs to know the public key (`ddjskey`, visible in page source), the time-based IV (Date.now), and the encoding function. The defender should be sending a server-side HMAC or an attestation token (PAT, Turnstile) tied to the IP/UA, so that a forged client beacon doesn't match the server's view. DD does cross-check `eventCounters` (outside the cipher) against `m_*` (inside), which is a weak HMAC.
2. **`appAjaxCall` is a denylist of one.** Any tool using a different attribute name or a different custom event name bypasses it. Either generalize to a "this form has a non-standard attribute starting with __ or has a custom event listener" probe, or drop it.
3. **The Overjet extension probe is fragile and tenant-specific.** If Overjet ever changes the file name `icon.0024de64.png` (it's content-hashed, so they probably will on next deploy) the probe silently returns null. DD has to update the URL on every Overjet release.
4. **Worker fingerprinting is the right pattern but the Worker source string is literal.** A defender should compile the Worker source at runtime from collected randomness, so static rewriters can't pre-patch it.
5. **No Performance.now / timing-side-channel detection.** Any anti-CDP work (console-timing oracle from the Castle clean-verdict v3-v7 series) is absent. A bot that uses Playwright `channel:'chrome'` with `launchPersistentContext` and zero stealth scripts will likely score clean on DD's surface (apart from the IP/ASN signal that DD applies server-side, which we can't see).
6. **No font enumeration.** DD relies entirely on UA + WebGL for environment ID. Spoofing UA + WebGL VENDOR/RENDERER (both available via CDP overrides) cleanly defeats this layer. A defender should add at least a 5-font canvas-width probe.
7. **`md` (defined-globals bitmap) is the strongest passive signal in the tag** and it's brittle: every Chrome version ships new APIs that flip bits. DD must be re-baselining `md` on each Chrome major release. The reference hex `52738db3...` is hardcoded; if a bot fakes a constructor that DD's reference doesn't expect, the bit flips the *wrong way* and the bitmap doesn't match — but the bot could also drop the new constructor and *match the older reference*, which is a "downgrade attack" on the heuristic. DD probably needs multiple references keyed by `md.slice(0,6)`.
8. **The arithmetic-obfuscated string table is symbolic-execution-friendly.** Any z3-based deobfuscator solves all the `A(n)` and `H[x][y]` constants in under a minute. The obfuscation is anti-reading-by-eye, not anti-static-analysis.
9. **No verification that the Worker actually ran.** If the Worker fingerprint job throws (or is patched to throw silently), DD records `NA` for every field but does not penalize the request. A bot can return `NA` for UA, plugins, timezone, and get a clean "I'm a privacy-conscious user" signal.

## 10. Open questions / threads to pull

1. **What tool sets `form[patched=true]` and dispatches `appAjaxCall`?** Confirmed not in public GitHub indices. Strong candidate is a private red-team tool. Worth dumping at the next DEF CON.
2. **What is the `2D56F91C2AD1A8EB7C6A5CA65F5567` tenant?** The only customer that gets all three probes (Overjet, Square-refund, appAjaxCall) suggests dental insurance billing — probably a claims-processing portal that has fought a specific automated-claim-submission bot.
3. **What does the server do with `r3n`?** It's a window-controlled pseudo-random spice. If `window._hsv` is *not* set, the value comes from the cipher state and is therefore deterministic per IV. Why expose `_hsv`? My guess: the *captcha page* sets `_hsv` to a server-issued nonce that the next legitimate beacon must echo. Worth testing by capturing a captcha-passed request.
4. **What's the `nowd` (no-wide-this) signal for?** Only emitted for one tenant (`1F633CDD8EF22541BD6D9B1B8EF13A`). Records whether `fetch` was called with `this === window` vs some other context. Bots that wrap `fetch` often forget to preserve `this`. This tenant clearly fought that bot specifically.
5. **The `md` reference hex.** Reverse-engineering this from a vanilla Chrome would tell us *exactly* which Chrome version DD baselined against. Diffing two captures (Chrome 119 vs Chrome 120 say) tells us which APIs got added and reveals new probes.
6. **Service-worker plugin is opt-in only.** When does a customer enable it? Probably for sites that *already* run a service worker for offline support. The SW can intercept fetches *before* the page sees them, which would let DD challenge a request without any tag in the document — a fundamentally different challenge model.
7. **`xhr_opts` / `opts` are sent 5% of the time.** A latent telemetry channel for DD to A/B-test customer configurations. Worth grepping for the receiving server-side rule.
8. **`replayAfterChallenge` is interesting from a UX perspective.** It lets a POST that got a 403+challenge be re-executed silently after the user passes the captcha. This means the user appears to never see a failure — the page just hangs for a few seconds and then succeeds. From a security perspective: an attacker who can pass *one* captcha can then drain N protected POSTs because each request's headers are buffered. Worth a write-up.

---

*End of document. ~4,400 words.*
