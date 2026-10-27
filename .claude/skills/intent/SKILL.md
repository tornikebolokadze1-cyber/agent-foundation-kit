---
name: intent
description: Structure or update the owner's intent in intent.md — vision, measurable goals, non-goals, constraints, working principles, open questions. Use when the owner describes what the product or the way of working should be, answers interview questions, or wants to change the goal.
argument-hint: "[what changed, or the owner's new answers]"
---

# /intent — the owner's intent, structured

`intent.md` is the root of the chain intent → spec → plan. You write drafts; only the owner accepts
(`/approve intent`). You never set `status: accepted`.

1. **Read** `intent.md`, `docs/domain/*.md`, the "ახლა" block of `progress.md`, and
   `bash .claude/hooks/py.sh tools/context_graph.py query intent`.
2. **Reopen if needed.** If `intent.md` is `accepted` and must change: first an edit that ONLY sets
   `status: draft` (the guard allows exactly that), then the content edits.
3. **The idea first (ADR-0011).** If §1 still holds only the template's `_…_` line and the person has just
   described what they want to build, write it into §1 at once — their own words, spelling lightly corrected,
   source **მფლობელი** with the date — before the first question. Never ask for setup, a README step or an
   approval of the engine's own ADRs. Write the project's type into the frontmatter — `kind:` website / game /
   agent / automation / other (the table in `docs/guides/other.md` decides a mixed idea) — and take the
   interview's questions from that type's guide, `docs/guides/<kind>.md` §1.
4. **Interview when information is missing** — ONE question per message (never two), in Georgian, with
   2–3 concrete options and your recommendation. Once `kind` is set, the guide's §1 questions replace the
   template's list in §7: rewrite §7 as the guide's questions the idea has not answered yet, ask every one
   of them (none is skipped as obvious), and when one is answered, write the answer where it belongs and
   delete the question from §7. A question about the stack (what to build it with) waits for stage 3.
   **How to ask.** Ask so that a plain „კი" agrees with your recommendation, and record such a yes as
   **მფლობელი (დაეთანხმა რეკომენდაციას)** with the date — the choice is the owner's, the words are yours.
   „როგორც შენ გინდა" or „არ ვიცი" is not a choice: say in one sentence what your recommendation decides and ask
   again. When the person is stuck, ask about a concrete moment („ბოლოს როდის დაგჭირდა…?") or offer a guess for them
   to correct. When they answer in their own words, drop the options and follow their words. A new wish that comes up
   mid-interview goes at once into §4 as „მოგვიანებით" with its date, and the interview goes on. The interview is
   done when nobody will ever have to ask what the person really meant.
   **Builder check.** When §7 holds no question any more, run the builder check
   ([builder-check.md](builder-check.md)) on `intent.md` before you offer `/approve intent`, and sort what it asks
   into three piles: **answered already** (the conversation or a document holds the answer — write it in);
   **minor** (a sensible builder could settle it without changing what gets built — decide it yourself and mark it
   **ჰიპოთეზა**); **theirs** (only the person can answer it, and the answer changes what gets built). Ask the
   person's pile in one message, most important first, at most three questions, each with its options and your
   recommendation — the one exception to one question per message, because it is the last round. Write the
   person's pile into §7 as its open questions, so the stage stays at the interview until they are answered, and
   write the check into the history (step 6) as `- <version> — <date> — მშენებლის შემოწმება: <N> კითხვა — <a> უკვე
   ნაპასუხები, <b> თავად გადავწყვიტე (ჰიპოთეზა), <c> ადამიანს ვკითხე`: until that line is there, the stage block
   names only the check and never `/approve intent`. When you offer `/approve intent`, name in a sentence or
   two the calls you made yourself, so the person can check them.
5. **Keep the fixed structure** (§1 ხედვა … §8 წყაროები + ცვლილებების ისტორია). Goals keep stable IDs
   (G1, G2…) — never renumber; retire one with ~~strike-through~~ and the reason. Every goal has
   "how we measure". Every item names its source: **მფლობელი** (the owner said it — with the date) or
   **ჰიპოთეზა** (inferred — needs confirmation). Never present a hypothesis as the owner's words.
6. **Version** — bump `version` (0.1 → 0.2), set `updated`, add one line to the history.
7. **Check** — `bash .claude/hooks/py.sh tools/context_graph.py check intent.md`; fix every error.
8. **Tell the owner** in 2–3 Georgian sentences what changed and what to review, and the next step from
   `bash .claude/hooks/py.sh tools/context_graph.py stage`; the decision is `/approve intent`.
