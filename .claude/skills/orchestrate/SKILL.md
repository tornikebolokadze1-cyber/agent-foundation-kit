---
name: orchestrate
description: Owner-only. Show the maker–checker orchestration status — stage 1 runs Claude models only, architecture loop Opus 5.5 ↔ Sonnet 5.5 (1 round), coding loop Sonnet 5.5 ↔ Opus 5.5 (max 2 rounds) — whether it is enabled, whether the claude CLI is ready, and the recorded runs. Dormant until the owner enables it.
disable-model-invocation: true
allowed-tools: Bash(bash .claude/hooks/py.sh orchestration/run.py status)
---

# /orchestrate — status of the maker–checker loops

!`bash .claude/hooks/py.sh orchestration/run.py status`

Explain this to the owner in 2–4 Georgian sentences: is it enabled, which stage it is in and which model
takes which role, is the claude CLI ready (the codex CLI matters only from stage 2), what the round limits
are, and what runs exist. A `CONFIG PROBLEM` line is a fault to report. If it is disabled, say that
switching it on is their decision (proposal P-001, ADR-0005) and means setting `enabled = true` in
`orchestration/config.toml` (a protected file — you will be asked before changing it). Do not start a loop from here.
