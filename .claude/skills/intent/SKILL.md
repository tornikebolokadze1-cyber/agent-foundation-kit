---
name: intent
description: Structure or update the owner's intent in intent.md — vision, measurable goals, non-goals, constraints, working principles, open questions. Use when the owner describes what the product or the way of working should be, answers interview questions, or wants to change the goal.
argument-hint: "[what changed, or the owner's new answers]"
---

# /intent — the owner's intent, structured

`intent.md` is the root of the chain intent → spec → plan. You write drafts; only the owner accepts
(`/approve intent`). You never set `status: accepted`.

1. **Read** `intent.md`, `docs/domain/*.md`, the "ახლა" block of `progress.md`, and
   `py -3.12 tools/context_graph.py query intent`.
2. **Reopen if needed.** If `intent.md` is `accepted` and must change: first an edit that ONLY sets
   `status: draft` (the guard allows exactly that), then the content edits.
3. **The idea first (ADR-0011).** If §1 still holds only the template's `_…_` line and the person has just
   described what they want to build, write it into §1 at once — their own words, spelling lightly corrected,
   source **მფლობელი** with the date — before the first question. Never ask for setup, a README step or an
   approval of the engine's own ADRs. Write the project's type into the frontmatter — `kind:` website / game /
   agent / automation / other (the table in `docs/guides/other.md` decides a mixed idea) — and take the
   interview's questions from that type's guide, `docs/guides/<kind>.md` §1.
4. **Interview when information is missing** — ONE question at a time, in Georgian, with 2–3 concrete
   options and your recommendation. Start from the open questions in §7.
5. **Keep the fixed structure** (§1 ხედვა … §8 წყაროები + ცვლილებების ისტორია). Goals keep stable IDs
   (G1, G2…) — never renumber; retire one with ~~strike-through~~ and the reason. Every goal has
   "how we measure". Every item names its source: **მფლობელი** (the owner said it — with the date) or
   **ჰიპოთეზა** (inferred — needs confirmation). Never present a hypothesis as the owner's words.
6. **Version** — bump `version` (0.1 → 0.2), set `updated`, add one line to the history.
7. **Check** — `py -3.12 tools/context_graph.py check intent.md`; fix every error.
8. **Tell the owner** in 2–3 Georgian sentences what changed and what to review, and the next step from
   `py -3.12 tools/context_graph.py stage`; the decision is `/approve intent`.
