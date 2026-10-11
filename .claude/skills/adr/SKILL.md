---
name: adr
description: Record an architectural decision as docs/adr/ADR-NNNN-slug.md with status proposed — context, options considered, decision, consequences, and how we will confirm it. Use whenever a choice is hard to reverse or shapes several parts of the system (stack, data, hosting, model, channel, security, process), and to replace an accepted decision (supersedes).
argument-hint: "<the decision to record> | supersede ADR-NNNN"
---

# /adr — record a decision the owner will accept or reject

1. **Is it an ADR?** Yes if it is hard to reverse, affects several parts, or someone will later ask
   "why did we do it this way?". A reversible detail belongs in a plan's `## გადახრები`, not an ADR.
2. **Context** — `intent.md` (goals, non-goals), accepted ADRs (`docs/adr/README.md`), domain facts,
   `py -3.12 tools/context_graph.py query <related id>`.
   **The stack decision (stage 3)** takes its 2–3 options from `docs/guides/<kind>.md` §2 (`kind` is in
   intent.md) and records the stack's five commands — install · run · lint · test · show — with lint and test
   pointed at the project's own code folder, never the engine's `tools/`.
3. **Large-scale decision + orchestration enabled?** Suggest the architecture loop to the owner:
   `py -3.12 orchestration/run.py arch --topic "…"` (Fable ↔ Astra, one round; the owner is asked).
   Its `synthesis.md` becomes this ADR's draft.
4. **Write** `docs/adr/ADR-NNNN-<english-kebab-slug>.md` (next free number — `docs/adr/README.md` names the
   reserved ones; a project's own ADR has no `scope`, an engine rule gets `scope: engine` — ADR-0011), Georgian
   prose, with frontmatter `id`, `type: adr`, `title`, `status: proposed`, `date`, `deciders`, `related` (quoted
   wikilinks), and sections: კონტექსტი · გადაწყვეტილება · განხილული ალტერნატივები (≥2, each with why
   not) · შედეგები (+ / −) · დადასტურება (prefer a machine check). Copy the shape of
   `docs/adr/ADR-0001-foundation-and-sdlc-loop.md`.
5. **Replacing an accepted ADR?** Accepted ADRs are immutable (guard G5). Write a new ADR with
   `supersedes: "[[ADR-XXXX-…]]"`; when the owner approves it, `approve.py` marks the old one superseded.
6. **Index** — add a row to `docs/adr/README.md`; run `py -3.12 tools/context_graph.py check <file>`.
7. **Tell the owner** in 2–4 Georgian sentences what is being decided and what it costs; the decision is
   `/approve adr NNNN` or `/approve reject adr NNNN <reason>`.
