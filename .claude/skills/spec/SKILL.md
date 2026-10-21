---
name: spec
description: Write or revise a feature specification (docs/specs/SPEC-NNNN-slug.md) from the accepted intent, the domain facts and the accepted ADRs, then have it reviewed by the spec-reviewer subagent. Use when the owner wants a feature defined, or before planning any feature.
argument-hint: "<the feature in a few words> | revise SPEC-NNNN"
---

# /spec — a specification the owner can approve and a machine can check

**Precondition:** `intent.md` is `accepted`. If it is not, stop and tell the owner that `/approve intent`
comes first (a spec cannot be approved before that — `approve.py` refuses and the CHAIN gate fails).

1. **Context** — goals G* and non-goals in `intent.md`, `docs/domain/*.md`, accepted ADRs
   (`docs/adr/README.md`), existing specs; `bash .claude/hooks/py.sh tools/context_graph.py query intent`.
2. **New file** — next free number `SPEC-NNNN`; `docs/specs/SPEC-NNNN-<english-kebab-slug>.md` from
   [template.md](template.md). Revising an approved spec: reopen it first (status only → draft).
3. **Fill every section.** Requirements `REQ-NNN` each trace to a goal G*. Acceptance criteria are
   Given / When / Then, testable, and each names the gate, test or eval that will prove it — and, in the
   column „რას დაინახავ ან გააკეთებ", what the person will see or do to check it with their own eyes
   („ტელეფონზე გახსნი გვერდს და პირველ ეკრანზე ღილაკს დაინახავ"); a criterion nobody can see says so in
   words („თვალით არ ჩანს — ამას ტესტი ამტკიცებს"), never an empty cell or a dash. Include
   Georgian-language quality, grounding and the domain invariants (`REVIEW.md`, `docs/domain/`) where they
   apply. Anything unknown → "ღია კითხვები", never a guess. The first version's scope and example criteria
   for this kind of project are in `docs/guides/<kind>.md` §3. Keep a first version's spec small enough for
   a beginner to judge: about 5–8 requirements and at most ~10 acceptance criteria; ask a missing fact in
   the chat (one question per message) rather than piling up open questions — at most 3 stay in the file.
   Describe what the result does, not how it is built: the stack is decided at stage 3.
4. **Index** — add a row to `docs/specs/README.md` (wikilink to the file). When complete, set
   `status: review`.
5. **Review** — run the `spec-reviewer` subagent on the file. Fix critical/high findings; record the
   rest under "ღია კითხვები". Then the builder check ([builder-check.md](../intent/builder-check.md)) on the
   spec, its questions sorted into the same three piles as in `/intent` step 4: the person's pile — at most
   three, in one message — goes with the summary of step 7, and their answers go into the spec before they
   approve it.
6. **Check** — `bash .claude/hooks/py.sh tools/context_graph.py check <file>`; fix every error. From
   `review` on it also fails on a line left from the template, an empty cell in the requirements or criteria
   table, or more than 3 open questions.
7. **Tell the owner** — 3–5 Georgian sentences: what the spec covers, what is out of scope, what they
   must decide; this summary is what they judge — never ask them to read the file. The approval is
   `/approve spec NNNN`. Planning (`/feature-plan`) starts only after it.
