---
name: reflect
description: Self-improvement pass — read recent episodes, lessons and proposals, find repeated friction, repeated manual steps and checks done by eye, and propose concrete improvements (a skill, rule, gate or ADR) in memory/PROPOSALS.md. Creates nothing without the owner's yes. Use every few sessions, when the owner asks what to improve, or right after a repeated mistake.
argument-hint: "[optional focus]"
---

# /reflect — the project improves itself, with the owner's consent

1. **Read** `memory/episodes/INDEX.md` and the last ~5 episodes (their "გაკვეთილები" and
   "წინადადებები" sections), `memory/LESSONS.md`, `memory/PROPOSALS.md`, and the latest gate/drill output
   if relevant.
2. **Find patterns** — the same mistake twice (→ lesson + a gate that prevents it); the same multi-step
   instruction given by the owner twice (→ skill candidate); a check done by eye that a script could do
   (→ gate candidate); a decision made implicitly (→ ADR candidate); a stale fact in CLAUDE.md, AGENTS.md
   or docs (→ correction).
3. **Dream — the top layer against the records** (ADR-0017 §4). Run
   `bash .claude/hooks/py.sh tools/gates/gate.py --only memory`: every claim it fails is a fact a machine disproved
   (a commit that does not exist, a drill group's wrong name). For each lesson's rule in `memory/LESSONS.md` and each
   line of the three dashboards (progress.md "ახლა", plan.md's current phase, tasks/todo.md "now / next") that names a
   decision, a number or the owner's words, search the records —
   `bash .claude/hooks/py.sh tools/recall.py "<its key phrase>"` — and note where they disagree; exit 1 ("not found")
   proves nothing either way. Name the duplicate and the stale proposals in `memory/PROPOSALS.md` to merge, and the
   top-layer lines too long to stay (their story moves to the lesson's file or to the log). The dream is ONE proposal
   in two parts: (a) the fact fixes a machine proved — made in this session's `/session-close`; (b) changes of
   judgement (a lesson's rule rewritten or retired, proposals merged) — they wait for the owner's yes. Nothing enters
   the top layer by itself. Then record the run:
   `bash .claude/hooks/py.sh .claude/hooks/episodic.py reflected ${CLAUDE_SESSION_ID}` — the start brief counts the
   sessions closed from here and reminds after five.
4. **Write each as a proposal** in `memory/PROPOSALS.md`: `- [ ] **P-NNN** <change> — why (episode
   links as evidence) — cost/risk — how we will know it worked (a machine check if possible)`.
5. **Present the top 3** to the owner in Georgian, one sentence each, with your recommendation.
6. **Only after an explicit yes:** implement it; for a new skill use `.claude/skills/<name>/SKILL.md`
   with a name that does not collide with `~/.claude/skills` (global skills win on a clash) and a
   description that says when to use it; add a drill for any script. Then mark the proposal `[x]` with
   the date and move it under "გადაწყვეტილი". A "no" is recorded there too, with the reason.
