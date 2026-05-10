# webapp/

Single-page React app that renders the ATSC 3.0 end-to-end gap analysis
(the same content as `docs/end_to_end_gaps.canvas.tsx`) as a static site
deployable to GitHub Pages.

Live URL (once Pages is enabled — see below):

> https://kporika.github.io/seastar-atsc3/

## Why a separate SPA

The `.canvas.tsx` source under `docs/` only renders inside the Cursor
canvas runtime; it imports `cursor/canvas` primitives that aren't published
to npm. This subproject re-implements the small set of primitives we use
(`Stack`, `Row`, `Grid`, `Card`, `Pill`, `Stat`, `Table`, `Callout`, ...)
in plain React + CSS so the same data tables and layout render in any
browser. The page module under `src/pages/EndToEndGaps.tsx` is a
near-verbatim port of the canvas source — keep them in sync when one
changes.

## Local dev

Requires Node 22+ and npm. If you only have Cursor's bundled node (no
`npm`), use Docker:

```bash
cd webapp
docker run --rm -it -v "$(pwd):/app" -w /app -u "$(id -u):$(id -g)" \
    -e HOME=/tmp -p 5173:5173 node:22-alpine \
    sh -c "npm install --no-audit --no-fund && npm run dev -- --host 0.0.0.0"
# then open http://localhost:5173/seastar-atsc3/
```

Native:

```bash
cd webapp
npm install
npm run dev          # vite dev server with HMR (http://localhost:5173/seastar-atsc3/)
npm run build        # tsc -b + vite build → dist/
npm run preview      # serve dist/ as a static-hosted preview
npm run typecheck    # tsc -b --noEmit
```

## Deployment

Pushed builds are deployed by `.github/workflows/pages.yml`. To activate
the first time:

1. Push at least once (the workflow runs on `push` to `main` *and* on
   `workflow_dispatch`).
2. Open the repo on GitHub → **Settings → Pages → Source** and choose
   **GitHub Actions**.
3. Re-run the workflow from the Actions tab (or push another commit). The
   `deploy` job's environment URL is the live Pages URL.

The workflow only fires when files under `webapp/**` or the workflow
itself change (see the `paths:` filter), so unrelated commits to the C++
codebase don't trigger redeploys.

## Customizing the base path

`vite.config.ts` defaults to `base: '/seastar-atsc3/'` — the right value
for `https://kporika.github.io/seastar-atsc3/`. Override at build time
when deploying behind a different prefix:

```bash
BASE_URL=/staging-atsc3/ npm run build
```
