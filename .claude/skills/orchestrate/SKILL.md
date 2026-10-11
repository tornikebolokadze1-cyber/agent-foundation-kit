---
name: orchestrate
description: Owner-only. Show the maker–checker orchestration status — architecture loop Fable 5.1 ↔ GPT-6 Astra (1 round), coding loop Opus 5 ↔ GPT-5.6 Sol (max 2 rounds) — whether it is enabled, whether the claude and codex CLIs are ready, and the recorded runs. Dormant until the owner enables it.
disable-model-invocation: true
allowed-tools: Bash(py -3.12 *orchestration/run.py status*)
---

# /orchestrate — status of the maker–checker loops

!`py -3.12 "${CLAUDE_PROJECT_DIR}/orchestration/run.py" status`

Explain this to the owner in 2–4 Georgian sentences: is it enabled, are both CLIs ready and logged in,
what the round limits are, and what runs exist. If it is disabled, say that switching it on is their
decision (proposal P-001, ADR-0005) and means setting `enabled = true` in `orchestration/config.toml`
(a protected file — you will be asked before changing it). Do not start a loop from here.
