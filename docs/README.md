# atsc3_proto / docs

Architecture notes and gap analyses for the project. These documents are
versioned alongside the code so they stay in sync as milestones land.

## Index

| Document | Format | Purpose |
|---|---|---|
| [`DOCKER_TESTING.md`](./DOCKER_TESTING.md) | Markdown | Docker command reference: **`make deps`**, **`make docker-ctest`**, integration via **`atsc3-deps`**, optional **`make image-integ-*`**. |
| [`END_TO_END_GAPS.md`](./END_TO_END_GAPS.md) | Markdown | Inventory of every protocol-level component between operator input and the RF exciter, with status, ATSC/IETF spec citations, and a recommended build order. Renders cleanly on GitHub. |
| [`end_to_end_gaps.canvas.tsx`](./end_to_end_gaps.canvas.tsx) | Cursor canvas | Interactive React rendering of the same gap analysis (status pills, sortable table, milestone cards). |
| [`../webapp/`](../webapp/) | Vite + React SPA | Public web rendering of the same content, served at **https://kporika.github.io/seastar-atsc3/** via `.github/workflows/pages.yml`. The webapp's `src/pages/EndToEndGaps.tsx` is a near-verbatim port of the canvas — keep them in sync. |

## Viewing the canvas in Cursor

Cursor only renders `.canvas.tsx` files when they live under the managed
canvases directory for the active workspace, **not** under the workspace
itself. To view the canvas interactively:

```bash
mkdir -p ~/.cursor/projects/Users-kalidasporika-mydaddy-atsc3/canvases
cp atsc3_proto/docs/end_to_end_gaps.canvas.tsx \
   ~/.cursor/projects/Users-kalidasporika-mydaddy-atsc3/canvases/
```

Then open the canvas from the Cursor file picker; it will compile and
appear beside the chat. Edits made there can be copied back into
`atsc3_proto/docs/end_to_end_gaps.canvas.tsx` to keep the persisted copy
in sync with the live one.

> The Cursor managed-projects path encodes the workspace path
> (`/Users/<user>/mydaddy/atsc3` becomes
> `Users-<user>-mydaddy-atsc3`). Adjust the path above for your username.

## Editing convention

All three artifacts are derived from the same data set. When you update
one, update the others so the markdown rendering, the canvas, and the
public SPA stay in sync:

- The **canvas** (`end_to_end_gaps.canvas.tsx`) is the source of truth
  for layout — it carries the curated component-by-component data tables.
- The **markdown** (`END_TO_END_GAPS.md`) is the source of truth for
  prose intended to be browsed on GitHub.
- The **SPA** (`../webapp/src/pages/EndToEndGaps.tsx`) is a near-verbatim
  port of the canvas; the only deltas are the imports
  (`./canvas-primitives` instead of `cursor/canvas`) and a few
  `useHostTheme()`-driven inline styles converted to CSS classes. After
  editing the canvas, run a 3-way diff against the SPA and apply the
  same changes there.
- When **`scripts/run_all_integration.sh`** or **`Makefile`** **`image-integ-all`**
  script order changes, sync the harness bullet in **`END_TO_END_GAPS.md`**, the
  matching line in the canvas + **`webapp/`** SPA, **`README.md`** integ comments,
  and the header comment in **`run_all_integration.sh`** itself.
- When **MMTP** lab coverage changes (e.g. **`mmtp_word0_integration_test.sh`**
  phases **E**–**X**, **ISOBMFF** / **GFD** / **signalling** strip semantics), also update **`END_TO_END_GAPS.md`**
  §M8 narrative, the **`README.md`** M8 bullet + **One-shot integration** script
  examples, and this repo’s **`protocol/*.yaml`** header comments that point at
  the same milestone.
