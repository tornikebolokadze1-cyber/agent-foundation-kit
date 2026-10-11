---
name: approve
description: Owner-only. Approve (or reject) a project document — intent, spec, plan or ADR — and record it in memory/approvals.md. Usage /approve [intent | spec N | plan N | adr N | reject adr N reason]; with no arguments it lists what is waiting for the owner.
disable-model-invocation: true
allowed-tools: Bash(py -3.12 *tools/approve.py*)
argument-hint: "[intent | spec N | plan N | adr N | reject adr N <reason>]"
---

# /approve — the owner's decision

The owner has just run this command. The result below comes from `tools/approve.py`; it has ALREADY
been applied (or refused). Nothing is waiting for you to approve.

Result:

!`py -3.12 "${CLAUDE_PROJECT_DIR}/tools/approve.py" '$ARGUMENTS'`

Your job now:

1. Tell the owner the result in 1–3 Georgian sentences: what was approved, rejected or refused, and
   the next step the result names. Plain words; gloss a technical term the first time.
2. If the result starts with ✅ — offer to make a CHECKPOINT commit of the status change and the
   ledger row. Do not edit the approved document.
3. If it starts with ❌ — explain in plain Georgian what is missing and offer to fix it (for example a
   broken link or a missing `spec:` link); the owner then runs /approve again.

Never run `tools/approve.py` yourself, never edit `memory/approvals.md`, never set an approval status
by hand — the guard refuses it and the LEDGER gate flags it. (Owner's note: avoid the `'` character
inside the note text — it breaks the shell quoting.)
