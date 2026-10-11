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
3. **Write each as a proposal** in `memory/PROPOSALS.md`: `- [ ] **P-NNN** <change> — why (episode
   links as evidence) — cost/risk — how we will know it worked (a machine check if possible)`.
4. **Present the top 3** to the owner in Georgian, one sentence each, with your recommendation.
5. **Only after an explicit yes:** implement it; for a new skill use `.claude/skills/<name>/SKILL.md`
   with a name that does not collide with `~/.claude/skills` (global skills win on a clash) and a
   description that says when to use it; add a drill for any script. Then mark the proposal `[x]` with
   the date and move it under "გადაწყვეტილი". A "no" is recorded there too, with the reason.
