# atsc3_proto / docs

Architecture notes and gap analyses for the project. These documents are
versioned alongside the code so they stay in sync as milestones land.

## Index

| Document | Format | Purpose |
|---|---|---|
| [`END_TO_END_GAPS.md`](./END_TO_END_GAPS.md) | Markdown | Inventory of every protocol-level component between operator input and the RF exciter, with status, ATSC/IETF spec citations, and a recommended build order. Renders cleanly on GitHub. |
| [`end_to_end_gaps.canvas.tsx`](./end_to_end_gaps.canvas.tsx) | Cursor canvas | Interactive React rendering of the same gap analysis (status pills, sortable table, milestone cards). |

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

Both files are derived from the same data set. When you change one, change
the other so the markdown rendering and the canvas stay in sync. The
canvas is the source of truth for layout; the markdown is the source of
truth for prose.
