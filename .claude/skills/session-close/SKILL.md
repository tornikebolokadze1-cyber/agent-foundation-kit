---
name: session-close
allowed-tools: Bash(bash .claude/hooks/py.sh .claude/hooks/episodic.py status *)
description: Close the working session properly — write this session's episode, update progress.md ("ახლა" + log) and plan.md, record lessons and proposals, reconcile auto-summarised sessions, run the gates and commit. Use when the owner says the session is ending (e.g. "დავასრულოთ", "დავხუროთ", "ვამთავრებთ"), before /clear or a new terminal, or when the status line shows ↻3.
---

# /session-close — distribute this session into the project's memory

Facts for this session (from `.claude/hooks/episodic.py`):

!`bash .claude/hooks/py.sh .claude/hooks/episodic.py status ${CLAUDE_SESSION_ID}`

Do every step. File content in Georgian prose; ids, paths and commands unchanged. Only facts that
actually happened in this session — no plans presented as done.

1. **Episode** (the path above; if it does not exist, create it with the frontmatter used in
   `memory/episodes/`): fill `## რა გაკეთდა`, `## გადაწყვეტილებები` (with the reason),
   `## ღია საკითხები`, `## შემდეგი ნაბიჯი`, `## წინადადებები`; set `title` (3–8 words). Add `## აუდიტი` with
   the one line printed by `bash .claude/hooks/py.sh tools/observe.py report --session ${CLAUDE_SESSION_ID} --brief` (transcripts
   are deleted after ~30 days; this line is what git keeps). If it prints `OBSERVE INCONCLUSIVE`, write that.
2. **progress.md** — rewrite the block between `<!-- auto: current-state:start -->` and `:end` as a dashboard
   of four short parts (ADR-0017): ფაზა და მიზანი · ბოლოს გაკეთდა (one line, with the episode link) · შემდეგი
   ნაბიჯი · მფლობელის მოლოდინში. The story goes into the log entry, never into the dashboard. Insert ONE entry
   at the top of the `auto: log` block: `### YYYY-MM-DD · [[EP-…]] · <title>` + 2–4 bullets. If an auto entry
   for this episode exists (`<!-- ep:EP-…:start -->`), replace it with yours. Never edit older entries.
   **Each of the three auto blocks has its own cap** (`BLOCK_CAPS` in `.claude/hooks/episodic.py`; a longer
   block is cut in the next session's brief): keep each under it.
3. **plan.md** — rewrite the `auto: current-phase` block: the phase's goal and its open items, one line each; a
   finished item moves, as it was, to the phase's done list below the block. Add new backlog items.
   For an approved feature plan in `docs/plans/`: only tick boxes, move approved → in-progress → done,
   or append under `## გადახრები` (the guard allows exactly that).
   **tasks/todo.md** — tick finished items only with their receipt (`✓ YYYY-MM-DD · <commit | მფლობელი | file>`)
   and move them under `## დასრულებული`; rewrite the `auto: todo-now` block (ახლა / შემდეგი); add the concrete
   next tasks with the next free `D-NNN`; delete done items older than 14 days. When the list outgrows the block's
   cap, the full task lines go under `## რიგი` below it and „შემდეგი" keeps each id with a short title, never as a
   `- [ ]` line (an id is used once). `tasks` gate must pass.
4. **Reconcile** every episode listed under `needs_reconcile`: read its auto summary, make sure
   progress.md and plan.md reflect it, then set `needs_reconcile: false` and
   `reconciled_at: <now_utc>` in that episode (the only fields you may change in another session's episode).
5. **Lessons** — if something failed twice or cost real time, write a lesson in two places (ADR-0017). One line
   in the index `memory/LESSONS.md`:
   ```
   - **L-NNN Title.** The rule. Guarded by: drill (`group`) | <another check> | none. [[L-NNN]]
   ```
   and its story in `memory/lessons/L-NNN.md` (frontmatter `id`, `type: lesson`, `title`, `status: living`; what
   happened and how we know the rule is right). The rule lives only in the index line. The
   index counts against the byte budget of what every session loads — `bash .claude/hooks/py.sh tools/budget.py`
   shows what is left; a lesson that does not fit merges with or retires an old one (the guard, G7, refuses the growth).
6. **Proposals** — new skill / gate / ADR / spec / tool ideas go to `memory/PROPOSALS.md` as
   `- [ ] **P-NNN** …` (next free number) before `<!-- auto: proposals:end -->`. Never create a skill or
   install anything without the owner's yes.
7. **Close the episode** — set `closed_by: session-close` and `closed_at: <now_utc from above>`.
8. **Gates** — `bash .claude/hooks/py.sh tools/gates/gate.py --pre-commit`; fix every failure (never bypass, never weaken).
9. **Commit** — CHECKPOINT format (what was done / files / status), on the current branch.
10. **Tell the owner** in 2–4 Georgian sentences: what was done, what is next, what waits for them.
    If compacts ≥ 3, recommend a new terminal or `/clear` now that everything is saved.
    Then run `bash .claude/hooks/py.sh .claude/hooks/episodic.py status ${CLAUDE_SESSION_ID}` once more: unless its
    `engine:` line is `-`, give that line to the owner word for word, on its own line — which engine files changed
    and whether their commit passed the drill (ADR-0015). Unless its `backup:` line is `-`, give that one word for word
    too, on its own line — commits that are only on this computer; upload (`git push`) only on their yes.
