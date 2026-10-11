---
paths:
  - "intent.md"
  - "plan.md"
  - "progress.md"
  - "docs/**"
  - "memory/**"
---

# Knowledge files — conventions (enforced by the `graph` gate and the guard)

- **Language:** Georgian prose; ids, file names, paths, commands and code in English.
- **Frontmatter** (YAML subset: `key: value`, quoted strings, `[a, b]`, `- item` lists) is required by
  location: `intent.md` → intent · `plan.md` → roadmap · `progress.md` → progress ·
  `docs/specs/SPEC-*` → spec · `docs/plans/PLAN-*` → plan · `docs/adr/ADR-*` → adr ·
  `docs/domain/*` → domain · `memory/episodes/EP-*` → episode. File name starts with its id.
  An engine ADR carries `scope: engine` (the engine's own rule — it never holds up the project's stage);
  a project ADR has no `scope`. Any other value is a SCOPE error.
- **Statuses:** intent draft/accepted · spec draft/review/approved/superseded ·
  plan draft/approved/in-progress/done · adr proposed/accepted/rejected/superseded.
  You may set only: intent draft · spec draft, review · plan draft, and in-progress/done on an approved
  plan · adr proposed. Everything else is the owner's `/approve` (guard G4 blocks it; gate LEDGER
  catches any status without an owner record).
- **Frozen:** accepted intent, approved spec, decided ADR. Change = reopen (an edit that only sets
  `status: draft`), then edit, then ask the owner to approve again. An ADR is never reopened — write a
  new one with `supersedes: "[[ADR-…]]"`. Approved plans: tick boxes, append under `## გადახრები`,
  approved → in-progress → done.
- **Links:** `[[file-stem]]` — the FILE name, not the id (`[[ADR-0003-context-graph-obsidian]]`, not
  `[[ADR-0003]]`); a README by path (`[[memory/README]]`); in frontmatter always quoted (`"[[intent]]"`).
  Relative Markdown links for files outside the knowledge set (`[x](../../research/…/file.md)`).
- **Append-only:** `memory/approvals.md` (never — only `tools/approve.py`); other sessions' episodes
  (only `needs_reconcile` / `reconciled_*`); the progress log (insert at the top; replace only an
  `<!-- ep:… -->` auto entry for your own episode); `memory/episodes/INDEX.md` is generated.
- **Auto blocks:** keep `<!-- auto: … -->` markers intact — hooks read between them.
- **One fact, one place:** domain facts in `docs/domain/`, decisions in ADRs, state in `progress.md`;
  elsewhere link to them.
- **Foreign folders** (`research/` — other sessions' research or material copied in from outside) —
  read and link, never edit or move.
- After editing: `py -3.12 tools/context_graph.py check <file>` (the Stop hook does it too).
