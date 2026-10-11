---
name: session-close
allowed-tools: Bash(py -3.12 *episodic.py status*)
description: Close the working session properly — write this session's episode, update progress.md ("ახლა" + log) and plan.md, record lessons and proposals, reconcile auto-summarised sessions, run the gates and commit. Use when the owner says the session is ending (e.g. "დავასრულოთ", "დავხუროთ", "ვამთავრებთ"), before /clear or a new terminal, or when the status line shows ↻3.
---

# /session-close — distribute this session into the project's memory

Facts for this session (from `.claude/hooks/episodic.py`):

!`py -3.12 "${CLAUDE_PROJECT_DIR}/.claude/hooks/episodic.py" status ${CLAUDE_SESSION_ID}`

Do every step. File content in Georgian prose; ids, paths and commands unchanged. Only facts that
actually happened in this session — no plans presented as done.

1. **Episode** (the path above; if it does not exist, create it with the frontmatter used in
   `memory/episodes/`): fill `## რა გაკეთდა`, `## გადაწყვეტილებები` (with the reason),
   `## ღია საკითხები`, `## შემდეგი ნაბიჯი`, `## წინადადებები`; set `title` (3–8 words). Add `## აუდიტი` with
   the one line printed by `py -3.12 tools/observe.py report --session ${CLAUDE_SESSION_ID} --brief` (transcripts
   are deleted after ~30 days; this line is what git keeps). If it prints `OBSERVE INCONCLUSIVE`, write that.
2. **progress.md** — rewrite the block between `<!-- auto: current-state:start -->` and `:end`
   (ფაზა · ბოლოს გაკეთდა · შემდეგი ნაბიჯი · ბლოკერები · მფლობელის მოლოდინში). Insert ONE entry at the
   top of the `auto: log` block: `### YYYY-MM-DD · [[EP-…]] · <title>` + 2–4 bullets. If an auto entry
   for this episode exists (`<!-- ep:EP-…:start -->`), replace it with yours. Never edit older entries.
3. **plan.md** — tick finished items, rewrite the `auto: current-phase` block, add new backlog items.
   For an approved feature plan in `docs/plans/`: only tick boxes, move approved → in-progress → done,
   or append under `## გადახრები` (the guard allows exactly that).
   **tasks/todo.md** — tick finished items only with their receipt (`✓ YYYY-MM-DD · <commit | მფლობელი | file>`)
   and move them under `## დასრულებული`; rewrite the `auto: todo-now` block (ახლა / შემდეგი); add the concrete
   next tasks with the next free `D-NNN`; delete done items older than 14 days. `tasks` gate must pass.
4. **Reconcile** every episode listed under `needs_reconcile`: read its auto summary, make sure
   progress.md and plan.md reflect it, then set `needs_reconcile: false` and
   `reconciled_at: <now_utc>` in that episode (the only fields you may change in another session's episode).
5. **Lessons** — if something failed twice or cost real time, add it to `memory/LESSONS.md` in the file's
   format, including "Guarded by: <check> | none". Keep the file ≤ 60 lines (merge or retire old ones).
6. **Proposals** — new skill / gate / ADR / spec / tool ideas go to `memory/PROPOSALS.md` as
   `- [ ] **P-NNN** …` (next free number) before `<!-- auto: proposals:end -->`. Never create a skill or
   install anything without the owner's yes.
7. **Close the episode** — set `closed_by: session-close` and `closed_at: <now_utc from above>`.
8. **Gates** — `py -3.12 tools/gates/gate.py --pre-commit`; fix every failure (never bypass, never weaken).
9. **Commit** — CHECKPOINT format (what was done / files / status), on the current branch.
10. **Tell the owner** in 2–4 Georgian sentences: what was done, what is next, what waits for them.
    If compacts ≥ 3, recommend a new terminal or `/clear` now that everything is saved.
