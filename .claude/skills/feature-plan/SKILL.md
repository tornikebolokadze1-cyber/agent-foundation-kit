---
name: feature-plan
description: Turn an APPROVED specification into an implementation plan (docs/plans/PLAN-NNNN-slug.md) — tasks traced to requirements and acceptance criteria, the gates that must be green, rollback, and the orchestration loop. Also the procedure for executing an approved plan. Use after /approve spec, or when the owner asks how a feature will be built.
argument-hint: "SPEC-NNNN | execute PLAN-NNNN"
---

# /feature-plan — plan an approved spec, then execute it

## A. Writing the plan

**Precondition:** the spec is `approved`. If not, stop — tell the owner which `/approve spec NNNN` is
missing. (`approve.py` refuses a plan on an unapproved spec, and the CHAIN-PLAN gate fails.)

1. Read the spec, its linked ADRs, `docs/domain/*.md`, `REVIEW.md`, and
   `py -3.12 tools/context_graph.py query <SPEC stem>`.
2. If the plan needs a decision that no accepted ADR covers (stack, data store, hosting, channel,
   model), write that ADR first with `/adr` — the plan links to it and waits for its approval.
3. Create `docs/plans/PLAN-NNNN-<slug>.md` from [template.md](template.md), `status: draft`,
   `spec: "[[SPEC-…]]"`. Every task: `- [ ] T<n> — <what> (REQ-…, AC-…) — verify: <command or check>`.
   Small tasks (one commit each). The first tasks write the failing tests/evals (TDD).
4. List which gates must be green, which new gates or eval cases this plan adds (each with a drill),
   and the rollback path.
5. Add a row to `docs/plans/README.md`; run `py -3.12 tools/context_graph.py check <file>`.
6. Tell the owner in Georgian what will be built, in what order, and how they will see it working;
   the decision is `/approve plan NNNN`.

## B. Executing an approved plan

1. Set `status: in-progress` (allowed). Work task by task, on a branch. Before the first task, if the
   `lint` and `unit` gates in `tools/gates/gates.toml` are both off, switch them on with the stack ADR's
   commands, pointed at the project's own code (not the engine's `tools/`) — a protected file, so the person
   says yes; `unit` goes on together with the first test (an empty test run proves nothing).
2. For each task: failing test/eval first → code → `py -3.12 tools/gates/gate.py` green → tick the box
   → CHECKPOINT commit.
3. If orchestration is enabled (`orchestration/config.toml`): after the task's code is ready, run
   `py -3.12 orchestration/run.py code-check --plan PLAN-NNNN --task T<n>` (the owner is asked).
   Fix critical/high findings; at most 2 rounds — after that report open findings as UNVERIFIED.
4. Any change of approach → append a dated line under `## გადახრები` (what and why). A change of scope
   → stop, reopen the plan (status only → draft) and ask the owner.
5. Done = every task ticked, every gate green, the `verifier` subagent returns `VERDICT: pass`.
   Then set `status: done` and update `plan.md` / `progress.md` (or run `/session-close`), and show the
   result the way `docs/guides/<kind>.md` §4 describes.
