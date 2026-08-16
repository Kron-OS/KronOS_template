# PoC: P2-W12 dark-mode fix + P2-W13 error boundary -- real browser verification

**Versions pinned (from `frontend/package.json`):** React 19.2.7, Vite
8.1.0, Tailwind CSS 4.0.0 (`@tailwindcss/vite` 4.3.1), TanStack Router
1.170.16, vitest 4.1.9. Playwright 1.62.1 + Chromium (installed via
`npm install -D playwright && npx playwright install chromium` for this
verification pass; kept as a real devDependency afterward -- see the task
report for why).

## What this proves

1. **P2-W12** -- `frontend/src/components/Layout.tsx` (15 files touched in
   total; see the commit) now pairs every previously dark-only
   `bg-gray-*`/`text-gray-*`/`border-gray-*`/`indigo-*` Tailwind class with
   a light-mode base + `dark:` variant, and the toggle (`useDarkMode`,
   moved to `frontend/src/hooks/useDarkMode.ts`) actually flips real,
   visible colors.
2. **A second, real bug found only by actually running this in a browser**
   (not visible from reading source): `useDarkMode()`'s effect --the one
   that adds/removes the `dark` class on `<html>`-- previously lived only
   inside `Layout`. `/login` never mounts `Layout`, so a fresh load of
   `/login` always rendered light-mode-only regardless of OS preference or
   a previously-saved `kronos-theme` value. Fixed by also calling
   `useDarkMode()` once, unconditionally, at the `App()` root
   (`frontend/src/App.tsx`) so the class-sync effect runs on every route.
3. **P2-W13** -- `frontend/src/components/ErrorBoundary.tsx`, a real class
   component wrapping the router in `App.tsx`, renders a themed fallback
   (not a raw stack trace) with a working reload button when a child
   throws during render.

## How this was run

- Real dev server: `cd frontend && npm run dev -- --host 127.0.0.1 --port 5199`.
- Real headless Chromium via Playwright, launched by `run_poc.mjs` in this
  directory (temporarily copied into `frontend/` to resolve `node_modules`,
  since ESM bare-specifier resolution doesn't walk sideways from `poc/`
  into a sibling `frontend/node_modules` -- the script itself is unchanged,
  only its execution location).
- `/login` needs no auth, so it's reached directly.
- An **authenticated** route (`/cases`, `Layout` + `CasesPage`) was reached
  via a throwaway harness entry
  (`frontend/harness-authenticated.html` + `.tsx`, deleted after this run,
  not part of the commit) that pre-seeds the same zustand auth store
  `main.tsx`'s `initKeycloak()` would otherwise populate, then mounts the
  real, unmodified `<App/>`. A real Keycloak login could not be exercised
  in this sandbox: `keycloak.ts` pins `https://kronos.local:8443` as the
  sole authorized domain (`docs/lan-dev-access.md`), which doesn't resolve
  with a valid cert here (confirmed: `net::ERR_CERT_AUTHORITY_INVALID`).
  `GET /api/cases` was intercepted with Playwright's `page.route()` and
  fulfilled with fake case data, since there's no real backend running
  either -- this is browser-level network mocking of one HTTP call, not a
  change to any application code, so what's screenshotted is the real
  `CasesPage`/`Layout` component tree rendering real (fake-fed) data.
- The error boundary fallback was reached the same way, via a throwaway
  `frontend/harness-error-boundary.html` + `.tsx` (also deleted) that
  mounts `ErrorBoundary` around a component that always throws during
  render, plus a `useDarkMode()` call mirroring `App.tsx`'s so the
  screenshot reflects real production behavior (in the real app,
  `useDarkMode()` lives in `App()`, a sibling scope to `ErrorBoundary`'s
  children, so it keeps applying the theme class even while the boundary's
  fallback is showing).
- `BOOT_TIMEOUT_MS = 25000` in `run_poc.mjs`: in this sandbox,
  `main.tsx`'s `bootstrap()` awaits `initKeycloak()`, which attempts a
  real `keycloak.init()` against `https://kronos.local:8443`. That TLS
  handshake fails slowly here (no real Keycloak reachable), so the app
  doesn't call `render()` until it gives up -- confirmed by instrumenting
  a debug build: the app reliably renders around 10-15s in, well within a
  real deployment (where `kronos.local` resolves with a valid cert and
  this is fast) but well past a naive short timeout. This is a sandbox
  network characteristic, not a defect in the code under test.

## Captured output (last real run)

```
[
  { "page": "login", "mode": "dark (system default, no localStorage)", "htmlClass": "dark", "bodyBg": "rgb(3, 7, 18)" },
  { "page": "login", "mode": "light (forced via localStorage)", "htmlClass": "", "bodyBg": "rgb(249, 250, 251)" },
  { "page": "authenticated harness (Layout+CasesPage, mocked API)", "mode": "dark", "htmlClass": "dark" },
  { "page": "authenticated harness (Layout+CasesPage, mocked API)", "mode": "light", "htmlClass": "" },
  { "page": "error boundary fallback", "mode": "dark", "status": "captured" },
  { "page": "error boundary fallback", "mode": "light", "status": "captured" }
]
```

Screenshots in this directory: `login_dark.png`, `login_light.png`,
`authenticated_harness_dark.png`, `authenticated_harness_light.png`,
`error_boundary_dark.png`, `error_boundary_light.png`. `bodyBg` values
confirm real computed CSS (`rgb(3, 7, 18)` = `#030712` = Tailwind
`gray-950`; `rgb(249, 250, 251)` = `#f9fafb` = `gray-50`) driven by the
actual `dark` class on `<html>`, not just source inspection.

## How to reproduce

```sh
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5199 &
# recreate the two throwaway harness files described above if needed
cp ../poc/frontend_theme_fix/run_poc.mjs ./run_poc_tmp.mjs
POC_OUT_DIR=../poc/frontend_theme_fix node run_poc_tmp.mjs
rm run_poc_tmp.mjs
```
