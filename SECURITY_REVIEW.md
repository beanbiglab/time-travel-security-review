# Security Review: Time Travel Browser Extension

- **Date:** 2026-09-19
- **Commit reviewed:** `54697c6f16ab54c29941771c8f40d2bbebcbfb3e` (`54697c6 pnpm dedupe`)
- **Package version in tree:** `3.1.0` (`package.json`)
- **Scope:** This repository is a fork of upstream [cpulvermacher/time-travel](https://github.com/cpulvermacher/time-travel). The review covers the extension source **as shipped / as in this tree**, plus runtime and build dependencies. It is a source-and-lockfile review, not a live Chrome Web Store / AMO package hash comparison.
- **Method:** Manifest and source reading, greps for privileged APIs and dynamic code, `pnpm audit` / `pnpm audit --production` against `pnpm-lock.yaml`, inspection of lifecycle scripts and CI. No store package was downloaded. Browser injection behavior that depends on Chrome’s `activeTab` implementation was not dynamically re-verified in a running browser.

---

## Executive summary

**Overall risk: Low** for the extension as this tree implements it (benign, no telemetry, no remote code, no extra host APIs).

Time Travel is a developer debugging tool that spoofs JavaScript `Date`, `Intl.DateTimeFormat`, and `Temporal.Now` in page context. Chrome permissions match a user-gesture, current-tab model. Firefox statically injects a MAIN-world content script on all `http` / `https` / `file` pages so the fake clock can apply at `document_start` after reload — that is a larger install-time grant than Chrome, and store/README wording about “only after clicking” is not accurate for Firefox.

A **compromised or malicious build** is a different question from the current source: Firefox’s always-on MAIN-world script would let an attacker run page-context JavaScript on every website immediately; Chrome’s `activeTab` + `scripting` model still requires the user to invoke the extension on a tab before it can inject.

**Takeaways**

1. No evidence of telemetry, analytics, `eval` / `new Function`, remote script URLs, `web_accessible_resources`, `externally_connectable`, or a custom `update_url` in the extension source.
2. Chrome permissions (`activeTab`, `scripting`, `storage`) are appropriate and not obviously over-privileged for the feature.
3. Firefox is more privileged than the “minimal permissions / click to activate” marketing implies.
4. Page-visible state (`sessionStorage` keys, `window.__timeTravelState`, `window.__timeTravelActive`) is an intentional tradeoff. Hostile pages can detect the extension and lie about / toggle their own fake clock; they cannot reach other origins or extension chrome APIs through this design.
5. Production (`--production`) npm/pnpm audit: **0 vulnerabilities**. Full tree audit: **12** findings (11 high, 1 moderate), all under **devDependency** `web-ext@10.6.0` — not shipped into the extension package.
6. Safe for a careful developer to install from the official stores or a self-built zip of this tree, with the conditions in the verdict.

---

## Threat model

### Intended capability (in scope)

The extension exists to make **the current tab’s JavaScript** believe a different date, time, and/or IANA time zone:

- Replace global `Date` and `Intl.DateTimeFormat`, and patch `Temporal.Now` / `Temporal.Instant.prototype.toLocaleString` when `Temporal` exists.
- Persist that choice across same-origin reloads via `sessionStorage` so a `document_start` script can apply it before page scripts run.
- Optionally stop/resume the fake clock and auto-reload the tab.
- Show an ON badge and a tooltip for the active tab.

It does **not** change the OS clock, HTTP `Date` headers, TLS certificate validation, or non-JavaScript time sources. That limitation is documented in `README.md`.

### What a malicious or compromised build could do

| Capability | Chrome (this manifest) | Firefox (this manifest overlay) |
| --- | --- | --- |
| Run arbitrary JS in a page the user just opened the popup on | Yes (`activeTab` + `scripting.executeScript`, MAIN or ISOLATED) | Yes (same APIs; plus static MAIN-world script already present) |
| Run MAIN-world JS on **every** `http(s)` / `file` page without a click | Not granted at install. After first use the code **registers** session content scripts with `matches: ['<all_urls>']`; Chrome still documents that injection requires host access (`activeTab` is temporary / same-origin until navigation away). Dynamic confirmation of whether Chrome ever injects those session scripts more broadly was **not** performed. | **Yes.** `src/manifest.firefox.json` declares `content_scripts` for `http://*/*`, `https://*/*`, `file://*/*`, `world: MAIN`, `run_at: document_start`, `all_frames: true`. |
| Read cookies / tokens visible to page JS on injected pages | Yes, wherever it can inject MAIN-world script | Yes, on all matching pages from install |
| Extension-level `cookies`, `webRequest`, `identity`, `history`, `debugger` | **No** — not in the manifest; no source use | Same |
| Network exfiltration from the **extension** process | Extension pages are locked by CSP `default-src 'self'`. A compromised build could remove that. | Same |
| Persist small settings via `chrome.storage.sync` | Yes (`storage`) | Yes |
| Auto-update to a further malicious version | Store-default update URL only (no `update_url` in tree). Sideloaded zips do not get CWS/AMO updates unless the user installs from those stores. | AMO-signed updates if installed from AMO |

**Hostile web page (uncompromised extension):** can detect the inject (`window.__timeTravelActive`), read/write the three `sessionStorage` keys, dispatch `timeTravelStateUpdate` / `timeTravelTickUpdate`, and overwrite `window.__timeTravelState`. That only affects **that page / origin / tab session**. The page cannot call `chrome.*` (MAIN-world script does not expose it; no `externally_connectable`).

**Other extensions:** not in `externally_connectable`; `chrome.runtime.onMessage` is same-extension only. Another extension’s content script could still dispatch the same DOM events or write `sessionStorage` on a shared page.

**User of the feature:** spoofing `Date.now()` on a real origin can break or weaken **page-implemented** time checks (JS TOTP display, “session expires at”, cookie-refresh timers). That is the product. It does not bypass server-side time.

---

## Findings

| ID | Severity | Area | Finding | Evidence | Recommendation |
| --- | --- | --- | --- | --- | --- |
| F1 | Medium | Manifest / claims | Firefox is **always-on** MAIN-world injection for all `http`/`https`/`file` pages, including frames and `about:blank`. Store/README text that the extension “only affects current tab **after clicking**” is true for **Date spoofing** (gated on `sessionStorage`) but false for **script presence**. A compromised Firefox build has a much larger blast radius than Chrome. | `src/manifest.firefox.json` lines 21–30; `README.md` line 20; `messages/store_copy_cws.en.md` line 8; `messages/store_copy_amo.en.md` line 9. Chrome `src/manifest.json` has **no** static `content_scripts`. | Disclose Firefox host access in store listings. Prefer Chrome if install-time host access is unacceptable. Upstream could explore Firefox `scripting.registerContentScripts` + user gesture if the platform allows `document_start` without static matches. |
| F2 | Low | Manifest / Chrome | After first successful apply, Chrome **registers** two session content scripts with `matches: ['<all_urls>']` and `persistAcrossSessions: false`. That is broader than “this origin only.” Injection should still require host permission / `activeTab` per Chrome docs; this was not re-tested in-browser. | `src/web-ext/browser.ts` lines 111–131 (`id: '01_replaceDate'`, `'02_sendActive'`). | If Chrome allows it, register the **current origin** (or tab URL pattern) instead of `<all_urls>`. Keep `persistAcrossSessions: false` (already set). |
| F3 | Low | Page context / privacy | The MAIN-world script sets `window.__timeTravelActive = true` even when no fake date is set, and listens for custom events. On Firefox this is a **stable fingerprint on every site**. On Chrome it appears after the session scripts have injected. | `src/content-scripts/replace-date.ts` lines 41–54; `src/globals.d.ts` lines 5–13. | Use a less guessable marker, or only set it when faking is on. Accept that MAIN-world Date replacement is inherently detectable. |
| F4 | Low | Hostile page | State lives in page `sessionStorage` and `window.__timeTravelState`. A page can clear/block storage (mitigated), spoof in-memory state (popup/icon readers trust MAIN-world), or self-enable a fake clock. Documented; not origin-escaping. | `doc/architecture.md`; `src/content-scripts/fake-date/storage.ts`; `src/tab-state/inject.ts`; `src/test/content-scripts/storage-tampering.test.ts`; keys `timeTravelDate`, `timeTravelTimezone`, `timeTravelTickStartTimestamp`; events `timeTravelStateUpdate`, `timeTravelTickUpdate`. | Keep isolated-world writes (already done). Treat popup values as untrusted display data (already sanitized for timezone via `sanitizeTimezone`). Do not grant extra privileges based on page-reported state (today they only drive UI). |
| F5 | Low | Claims vs frames | README/store copy says “Other tabs and origins are not affected.” Cross-origin **iframes in the current tab** **are** written (`allFrames: true`). Other **tabs** are not (per-tab `sessionStorage`). Sandboxed iframes are a documented miss. | `src/tab-state/state.ts` lines 81–83, 91–94, 104–105; `src/web-ext/browser.ts` lines 70–73, 118; `README.md` lines 26, 34; Firefox `all_frames` + `match_about_blank`. | Tighten the wording to “other tabs; frames in the current tab **are** included.” |
| F6 | Low | Build / release | Production builds fetch Inlang plugins from jsDelivr with **floating majors** (`@4`, `@2`). Paraglide output is generated at build (`src/paraglide/` is not in git). A CDN or plugin compromise could poison CI artifacts. | `project.inlang/settings.json` lines 10–12; `@inlang/paraglide-js` `loadProjectFromDirectory` in the Vite plugin. | Pin full versions or vendor the plugin files. Consider committing generated `src/paraglide/` and building translations offline. |
| F7 | Low | CI | Most GitHub Actions are floating majors (`actions/checkout@v6`, `actions/setup-node@v6`, `actions/upload-artifact@v7` / `@v5`). `pnpm/action-setup` is SHA-pinned. A tag move could change CI behavior. | `.github/workflows/*.yml` | Pin actions to commit SHAs (as already done for pnpm). |
| F8 | Low | Dev supply chain | `pnpm audit` reports **12** issues, all through `web-ext@10.6.0` (AMO lint / `web-ext run` / `web-ext sign`). None are in `--production`. Highest practical concern: `adm-zip@0.6.0` symlink overwrite if a developer pointed `web-ext` at a malicious XPI/zip. | `pnpm audit` 2026-09-19; paths under `web-ext>…`. See dependency section. | Upgrade `web-ext` when patched transitives land. Do not run `web-ext` on untrusted archives. CI already runs `pnpm audit --production` and fails on prod vulns. |
| F9 | Info | Dependency default | `@svelte-plugins/datepicker` defaults `includeFont = true`, which injects `https://fonts.googleapis.com/css2?family=Rubik…`. This tree sets `includeFont={false}`. Extension CSP would also block the request. | `node_modules/@svelte-plugins/datepicker/src/datepicker.svelte` lines 193, 1113–1119; `src/components/Calendar.svelte` line 72; `src/manifest.json` CSP. | Keep `includeFont={false}`. Add a test or comment so a future UI rewrite cannot regress a Google Fonts request. |
| F10 | Info | Messages | Service worker trusts `message.msg === 'active'` and `sender.tab?.id` with no runtime schema check. Only same-extension isolated content scripts can send this (`onMessage`, not `onMessageExternal`). Payload is used for badge/title, not injection. | `src/worker.ts` lines 17–28; `src/content-scripts/send-active.ts`; no `externally_connectable`. | Optional: validate types/lengths before `setIconBadgeAndTitle`. |
| F11 | Info | Positive control | No `host_permissions` / `optional_host_permissions` on Chrome; no `web_accessible_resources`; no `update_url`; CSP on extension pages; `data_collection_permissions.required: ["none"]` on Firefox; builds not minified (`minify: false`). | `src/manifest.json`; `src/manifest.firefox.json`; `vite.config.mts` line 48; `vite.config.content-script.mts` line 21. | Keep these. |

No Critical or High findings in the **shipped extension source**. Medium is limited to Firefox’s install-time host/script grant versus “click to activate” wording.

---

## Permissions analysis

### Chrome — `src/manifest.json` (MV3)

| Key | Value | Assessment |
| --- | --- | --- |
| `manifest_version` | `3` | Current Chrome model. |
| `minimum_chrome_version` | `109` | Matches `scripting.registerContentScripts` availability. |
| `permissions` | `activeTab`, `scripting`, `storage` | See below. **No** `tabs`, `cookies`, `webRequest`, `identity`, `debugger`, `downloads`, `history`, `clipboardRead`, etc. |
| `host_permissions` | *(absent)* | Matches “minimal permissions (in Chrome).” |
| `content_scripts` | *(absent)* | Injected only after `registerContentScript()` (user apply path). |
| `background` | `worker.js` module service worker | Tab activate/update + `onMessage` for badge. |
| `action.default_popup` | `popup/main.html` | User gesture surface for `activeTab`. |
| `content_security_policy.extension_pages` | `default-src 'self'; img-src 'self' data:` | Blocks remote scripts/styles/connect. Data URIs only for images (inline SVG in CSS uses `data:`). |
| `web_accessible_resources` | *(absent)* | Pages cannot frame or import extension files. |
| `externally_connectable` | *(absent)* | No website or other-extension messaging. |
| `update_url` | *(absent)* | Store default if installed from CWS. |
| `optional_permissions` | *(absent)* | — |

**Permission justifications (Chrome)**

- **`activeTab`:** Temporary host access to the tab where the user opened the action. Required for `chrome.scripting.executeScript` / reading `tab.url` for `file://` and Web Store error messages (`src/web-ext/browser.ts` `isFileUrl`, `isExtensionGalleryUrl`, `isAboutUrl`).
- **`scripting`:** `executeScript` (read/write fake-date functions in MAIN or ISOLATED) and `registerContentScripts` / `updateContentScripts` for `document_start` persistence after first apply.
- **`storage`:** `chrome.storage.sync || chrome.storage.local` for UI settings only: `autoReload`, `stopClock`, `timezone`, `recentTimezones` (`src/web-ext/settings.ts`). Not used for the fake instant (that is page `sessionStorage`).

**APIs used without extra permissions:** `chrome.tabs.query/get/reload/onActivated/onUpdated`, `chrome.windows.getCurrent`, `chrome.action.setBadge*`, `chrome.i18n`, `chrome.runtime.getPlatformInfo`. Without the `tabs` permission, `changeInfo.url` / `tab.url` may be missing except where `activeTab` or a host grant exists; `worker.ts` bails if `changeInfo.url === undefined`.

### Firefox overlay — `src/manifest.firefox.json`

Merged on top of the Chrome manifest by `util/build.sh` (`jq '. * input'`). Adds:

- `browser_specific_settings.gecko.id` = `time@travel`; `strict_min_version` `128.0`; Android counterpart.
- `data_collection_permissions.required: ["none"]` — matches the privacy policy.
- **Static** `content_scripts` for replace-date only (MAIN, all frames, `document_start`, `http`/`https`/`file`).
- Background converted to `scripts` (event page) rather than `service_worker`.

Implied **host access** in Firefox is therefore all `http`/`https`/`file` URLs. That is required today so `replace-date.js` runs at `document_start` on the next load without a Chrome-style dynamic registration story. It is the main over-privilege versus Chrome.

`send-active.js` is **not** in the Firefox static list; it is still registered dynamically from `registerContentScript()` on first apply (same `<all_urls>` session registration).

### Injection model (page context)

```
User opens popup (activeTab)
  → setFakeDate() [ISOLATED, allFrames] writes sessionStorage + CustomEvent
  → registerContentScripts(<all_urls>, persistAcrossSessions:false)  [Chrome; Firefox already has static replace-date]
  → optional tabs.reload
  → replace-date.js [MAIN, document_start] reads captured sessionStorage, may replace Date/Intl/Temporal
  → send-active.js [ISOLATED, top frame] may chrome.runtime.sendMessage({msg:'active', ...})
```

- **MAIN vs isolated:** Fake `Date` must be MAIN (`doc/architecture.md`). Writers use ISOLATED so the page cannot swap `sessionStorage` methods (issues [#45](https://github.com/cpulvermacher/time-travel/issues/45), [#54](https://github.com/cpulvermacher/time-travel/issues/54)). Readers for the popup/icon use MAIN `window.__timeTravelState`.
- **`document_start`:** Needed so `OriginalDate` is captured before page scripts. Race with *other extensions* that also replace `Date` is possible and unclaimed.
- **Prototype / options:** `optionsWithDefaultTz` uses `Object.create` + `defineProperty` so a page `timeZone` getter cannot intercept (`FakeIntlDateTimeFormat.ts`). `copyOwnProperties` copies descriptors, not enumerable assigns (`own-properties.ts`). No privileged `chrome` object is attached to `window`.
- **Temporal:** `patchTemporal` assigns `globalThis.Temporal` and patches `Instant.prototype.toLocaleString` in place; restored on disable. Page-local only.
- **Re-injection:** Second inject aborts if `window.__timeTravelActive` is already true (`replace-date.ts`, `re-injection.test.ts`) — avoids capturing `FakeDate` as `OriginalDate` if two versions are installed.

No `eval`, `new Function`, `importScripts`, `innerHTML` assignment in `src/` (only test HTML fixtures). Popup strings use Svelte text interpolation (escaped), not `{@html}`.

### Data handling

| Data | Where | Leaves device? |
| --- | --- | --- |
| Fake date / TZ / tick start | Page `sessionStorage` + `window.__timeTravelState` | No (page origin only). Visible to that origin’s JS. |
| UI settings | `chrome.storage.sync` if available, else `local` | Sync follows the **browser** account if the user enabled sync — disclosed in `doc/Privacy Policy.md`. Values are booleans, IANA timezone ids, and a 5-entry recent list. |
| PII / accounts / cookies / history | Not collected | — |
| Telemetry / crash / analytics | None in source; `debugLog` is compiled out when `MODE === 'production'` (`src/util/log.ts`) | — |
| Network from extension | No `fetch` / XHR in `src/`. Datepicker remote font disabled. Inlang CDN is **build-time only**. | — |

Privacy policy claims match the code: local UI settings, optional browser sync, no first-party servers.

### Cross-tab / cross-origin

| Claim | Code |
| --- | --- |
| Only current tab | Fake clock keys are `sessionStorage` → **per tab, per origin**. Two tabs of `example.com` are independent. |
| Other origins not affected | **Top-level** other origins are not written unless the user applies there (and session scripts inject). **Iframes of other origins in the same tab are written** (`allFrames: true`). |
| Survives reload | Same-origin reload: yes, via `sessionStorage` + `pagehide` persist (`storage.ts` `persistState`). Cross-origin navigation in the same tab: new origin storage, fake clock off. Return to the first origin: keys may still be there. |
| Browser restart (Chrome) | Session content scripts do not persist (`persistAcrossSessions: false`). Storage keys may remain until the tab is discarded; without the content script they do nothing until the user applies again. |
| Sandboxed iframes | Isolated writes catch and return `false`; README documents no support. |
| `file://` | Chrome: user must enable “Allow access to file URLs”; popup shows `permission_error_file_url`. Firefox: `file://*/*` is in the static matches. |

---

## Dependency / supply-chain analysis

Lockfile: `pnpm-lock.yaml` (pnpm `12.4.1`, lockfileVersion 9). Workspace policy in `pnpm-workspace.yaml`:

- `minimumReleaseAge: 4320` (3 days) — delays brand-new publishes.
- `allowBuilds.esbuild: false`, `allowBuilds.spawn-sync: false` — install-time build scripts for those packages are denied.

`pnpm i --frozen-lockfile` reported: “Lockfile passes supply-chain policies (491 entries).”

### Direct dependencies

| Package | Version (resolved) | Purpose | Shipped to browser? |
| --- | --- | --- | --- |
| `svelte` | `5.57.0` | UI compiler + small runtime for the popup | **Popup bundle only** (compiled). Not in the MAIN-world content-script IIFE (`vite.config.content-script.mts` has no Svelte plugin). |
| `@svelte-plugins/datepicker` | `1.0.11` | Calendar widget (`DatePicker` in `Calendar.svelte`) | **Popup bundle only.** **Zero** runtime `dependencies` in its `package.json`. MIT, author Kieran Boyle / `svelte-plugins/datepicker`. Default Google Fonts link is disabled in this tree (`includeFont={false}`). |

Svelte 5 transitives (`acorn`, `aria-query`, `magic-string`, `zimmerframe`, …) are **compiler/runtime support**. They are build-time unless Vite emits a snippet; they are not a second UI framework on the page. Production audit treats this graph as 21 production packages / 35 with optionals — **no known CVEs**.

### Direct devDependencies (not shipped in the extension zip)

| Package | Resolved | Purpose | Notes |
| --- | --- | --- | --- |
| `@biomejs/biome` | `2.5.6` | Lint/format | Native binaries; pinned exact. |
| `@inlang/cli` | `^3.3.3` → `3.3.3` | Machine translate | Optional workflow. |
| `@inlang/paraglide-js` | `^2.24.1` → `2.24.1` | i18n compile (Vite plugin) | Loads `project.inlang` modules from jsDelivr at **build** (F6). |
| `@playwright/test` | `^1.62.1` → `1.62.1` | E2E | Dev server only. |
| `@sveltejs/vite-plugin-svelte` | `^7.3.0` → `7.3.0` | Compile `.svelte` | Build. |
| `@tsconfig/svelte` | `^5.0.8` → `5.0.8` | TS config | Types. |
| `@types/chrome` | `^0.2.9` → `0.2.9` | Types | Not shipped. |
| `@vitest/coverage-v8` | `^5.0.0` → `5.0.0` | Coverage | CI. |
| `chrome-webstore-upload-cli` | `^4.0.1` → `4.0.1` | CWS upload | Release job; holds no secrets in repo. |
| `happy-dom` | `^20.14.3` → `20.14.3` | Unit-test DOM | Not shipped. |
| `svelte-check` | `^4.7.6` → `4.7.6` | `svelte-check` | Lint. |
| `typescript` | `^6.0.3` → `6.0.3` | Typecheck | Build. |
| `vite` | `^8.2.2` → `8.2.2` | Bundler | Build. Pulls `esbuild` / Rolldown binaries. |
| `vitest` | `^5.0.0` → `5.0.0` | Unit tests | Dev. |
| `web-ext` | `^10.6.0` → `10.6.0` | Firefox lint, run, AMO sign | **All `pnpm audit` vulns.** Used in CI lint and release `web-ext sign`. |

### Notable transitives

- **Production / popup:** Svelte compiler stack only. No analytics SDKs, no HTTP clients in the production tree (`pnpm list --prod`).
- **Build:** `esbuild@0.27.2` declares `postinstall: node install.js` (download/check native binary). This repo **disallows** the esbuild build script via `allowBuilds`. Vite `8.2.2` is the bundler of record.
- **Firefox toolchain:** `web-ext` → `addons-linter`, `firefox-profile`, `eslint` — large attack surface if you run them on untrusted input (F8).
- **Vendored / CDN in repo:** No JS CDN in extension sources. Test HTML fixtures load moment.js / date-fns from cdnjs/jsDelivr (`src/test/*.html`) — **not packaged**. Inlang plugins: jsDelivr URLs in `project.inlang/settings.json` (build).

No lockfile / source `http://` (non-TLS) package tarballs observed.

### Lifecycle / postinstall scripts

Many packages declare `prepare` / `prepublish` (no-ops after publish). The only notable **install** hook in the installed tree is `esbuild`’s `postinstall`, which this workspace policy disables. Production packages `svelte` and `@svelte-plugins/datepicker` have **no** install hooks.

### Audit summary (2026-09-19, this lockfile)

```
pnpm audit --production  →  No known vulnerabilities found
pnpm audit               →  12 vulnerabilities (1 moderate, 11 high, 0 critical)
```

All 12 are **dev-only**, via `web-ext@10.6.0`:

| Severity | Package (installed) | Advisory | Role |
| --- | --- | --- | --- |
| high | `brace-expansion@1.1.14` | [GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp), [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg), [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895) | glob DoS in eslint/minimatch under addons-linter |
| high | `image-size@2.0.2` | [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr), [GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq) | infinite-loop parsers in addons-linter |
| high | `fast-uri@3.1.5` | [GHSA-5jgf-p345-68v8](https://github.com/advisories/GHSA-5jgf-p345-68v8), [GHSA-f65p-4m7j-42xc](https://github.com/advisories/GHSA-f65p-4m7j-42xc), [GHSA-fph4-wmhf-6fwf](https://github.com/advisories/GHSA-fph4-wmhf-6fwf), [GHSA-jqff-g426-hqxp](https://github.com/advisories/GHSA-jqff-g426-hqxp) | URI confusion/SSRF in ajv under addons-linter |
| high | `js-yaml@4.3.1` | [GHSA-2883-xcg3-v3hh](https://github.com/advisories/GHSA-2883-xcg3-v3hh) | YAML CPU DoS in eslint config |
| high | `adm-zip@0.6.0` | [GHSA-7q85-xj36-vmfc](https://github.com/advisories/GHSA-7q85-xj36-vmfc) | zip bomb DoS in `firefox-profile` |
| moderate | `adm-zip@0.6.0` | [GHSA-vwc7-r8mq-g2x9](https://github.com/advisories/GHSA-vwc7-r8mq-g2x9) | zip extract follows dest symlinks |

**Maintainership (qualitative):** Upstream is a small MIT project (copyright Christian Pulvermacher, `LICENSE`). Popup calendar is a small dedicated Svelte component with no further runtime deps. `web-ext` is Mozilla-maintained but currently pulls several outdated transitives.

---

## Build and release

| Control | Evidence | Assessment |
| --- | --- | --- |
| Reproducible-ish build | `util/build.sh` → Vite twice (popup/worker/send-active, then IIFE `replace-date.js`); version from `git describe`; `minify: false` | Reviewable output. Not bit-for-bit pinned (tooling floats via `^`). |
| CI (Node) | `.github/workflows/node.js.yml`: `pnpm i`, **`pnpm audit --production`**, coverage, `pnpm dev` (dev build), lint, `web-ext lint` | Prod audit is enforced. Full audit (web-ext) is not. |
| E2E | `.github/workflows/e2e.yml` Playwright chromium+firefox | Popup is tested against a **mocked** Vite page, not a packed extension in CI. |
| Release | `.github/workflows/release.yml` on `v*.*.*`: test, lint, prod audit, build, CWS upload, AMO `web-ext sign --channel listed`, GitHub release zips | Secrets referenced only as `${{ secrets.* }}` (`CHROME_CLIENT_*`, `AMO_JWT_*`, `PUBLISHER_ID`). **No secrets in the repo.** `EXTENSION_ID` `jfdbpgcmmenmelcghpbbkldkcfiejcjg` is public. |
| Workflow permissions | CI/e2e: `contents: read`. Release: `contents: write`. | Least privilege for GITHUB_TOKEN. |
| Action pinning | Only `pnpm/action-setup` is SHA-pinned (F7). | |
| Source zip | Production build clones the repo and zips it for AMO `--upload-source-code` | Good for AMO review. |

No `.env` files, no embedded API keys. `npx chrome-webstore-upload` / `npx web-ext` in release run after `pnpm i` (local bins expected).

---

## Claim vs code

| Claim | Source | Verdict |
| --- | --- | --- |
| “Minimal permissions (in Chrome)” | `README.md`, CWS copy | **Accurate.** Three permissions, no `host_permissions`, no static content scripts. |
| “Minimal permissions” as a general statement | CWS copy line 8 | **Chrome-only.** Firefox static matches are a full host grant. README already qualifies “(in Chrome).” |
| “Only affects current tab after clicking the extension icon” | README, CWS, AMO | **Mostly true for the fake clock** (sessionStorage + user apply). **False for Firefox script injection** (always present). Chrome: first apply also registers session scripts for `<all_urls>` (F2). |
| “Other tabs and origins are not affected” | README, store copy | **True for other tabs.** **False for cross-origin iframes in the active tab** (F5). |
| “We do not transmit your data… never shared with us” | `doc/Privacy Policy.md` | **Matches source.** `storage.sync` may copy settings through **Google/Mozilla** if the user enabled browser sync — the policy already says this. |
| Firefox `data_collection_permissions: none` | `manifest.firefox.json` | **Matches** (no telemetry). |
| Open source / MIT | README, LICENSE | This tree is MIT; store builds should be compared to a tag if you need binary assurance. |

---

## Residual risks

1. **Trusting the publisher and the store update channel.** The dangerous case is not this source; it is a later malicious CWS/AMO update or a look-alike listing. Firefox users give that updater always-on MAIN-world access.
2. **MAIN-world Date replacement** can confuse page integrity checks and is detectable. Do not treat a faked origin as a faithful production environment for security QA of time-hard features without also testing the server.
3. **`pagehide` persist** can fail on crash/discard (`doc/architecture.md`); not a confidentiality issue.
4. **Chrome `activeTab` + `<all_urls>` registration** was reasoned from docs and code, not re-proved in Chrome 109/119/stable for this review.
5. **Build-time jsDelivr Inlang plugins** (F6) if you build from source in CI.
6. **`web-ext` transitives** if developers unpack untrusted Firefox artifacts (F8).
7. This review did **not** hash-compare `dist/` (not in git) to the live CWS/AMO CRX/XPI.

---

## Verdict

**Yes — a careful developer can install this extension**, under these conditions:

1. **Prefer the official Chrome Web Store listing** (`jfdbpgcmmenmelcghpbbkldkcfiejcjg`) if you want the documented minimal-permission model (user gesture per tab, no install-time `<all_urls>`).
2. **Firefox/AMO is acceptable if you understand** that `replace-date.js` is injected into every `http`/`https`/`file` page from install. Only enable it in a profile you use for frontend debugging, not a daily-driver profile that holds mail/bank sessions, unless you accept that fingerprint and compromise radius.
3. **Install from CWS/AMO or a zip you built from this tree** (`pnpm build`, load `dist/chrome` / `dist/firefox`). Do not install random third-party rebuilds.
4. **Use it on sites you are debugging.** Spoofing `Date` on a real signed-in origin is a deliberate, user-driven break of that page’s JavaScript time.
5. **If you build from source:** treat Inlang jsDelivr plugins and floating GitHub Actions as the main pipeline risks; production lockfile audit is clean.

**Do not install** a copy that adds `host_permissions`, `webRequest`, `cookies`, `identity`, `<all_urls>` static scripts on Chrome, remote CSP sources, or minified/obfuscated worker/content scripts you cannot match to this repo.

---

## Appendix: grep notes

Searched the tree (extension `src/`, manifests, workflows) for `fetch(`, `XMLHttpRequest`, `eval(`, `new Function`, `chrome.cookies|identity|webRequest|debugger`, `web_accessible`, `externally_connectable`, `update_url`, `host_permissions`. **No matches** in shipped extension logic. `chrome.scripting` / `chrome.storage` / `chrome.tabs` / `chrome.runtime.sendMessage` appear only as described above.
