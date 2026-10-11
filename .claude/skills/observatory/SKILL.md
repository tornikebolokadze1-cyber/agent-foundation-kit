---
name: observatory
description: Show the owner what the agents did in this project — every tool call, changed file, notable command, web and MCP use, what the guard and the sentinel refused or hid, permission denials, token use and what it cost (prompt cache, rebuilds and their causes) — read from Claude Code's own session transcripts by tools/observe.py and explained in Georgian. Use when the owner asks what an agent did, wants an audit or the "AI observatory" view, asks about security events, or before /session-close.
argument-hint: "[session-id prefix | last | days N]"
allowed-tools: Bash(py -3.12 tools/observe.py*)
---

# /observatory — what the agents did, in Georgian

1. Run `py -3.12 tools/observe.py report --session ${CLAUDE_SESSION_ID}` — or, with the owner's argument, a session
   id prefix or `last`; for "the last N days" run `py -3.12 tools/observe.py sessions --days N`.
2. Exit 2 (`OBSERVE INCONCLUSIVE`) means nothing was proved — say so plainly; never present it as "nothing happened".
3. Explain to the owner in 2–4 connected Georgian paragraphs: how much was done; which files changed and why (name the
   task `D-NNN` or plan task it served); every line under "ბრძანებები, რომლებსაც ყურადღება სჭირდება"; every security
   event — `GUARD[..]` (what was refused and why), `SENTINEL[R1/R2]` (a key appeared — where, and that the owner should
   rotate it), `SENTINEL[I1/I2]` (suspicious outside text); permission denials; token use; and the "ქეში და ხარჯი"
   section — the API-price yardstick (a measure of the subscription limits, not a bill), the share read from the
   cache, and every rebuild with its cause; for an avoidable one (a long pause, a restart, a model switch) name
   the habit that avoids it ([[process]] §5, ADR-0010). `--session all` measures every session of the project.
4. Never paste a tool's output or any secret — the report is already redacted. If something looks wrong (a changed file
   no task explains, a refused attempt that repeats), say so and propose the next step; do not fix anything here.
5. State the limits honestly: the report sees only Claude Code sessions of this project folder (not Codex, not other
   tools); a file changed by a shell command is listed only when Claude Code tracked it; transcripts are deleted after
   about 30 days, which is why `/session-close` keeps the brief line in the episode (ADR-0007).
