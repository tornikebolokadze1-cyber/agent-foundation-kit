---
id: lessons
type: memory
title: გაკვეთილები — რა აღარ უნდა განმეორდეს
status: living
---

# Lessons (loaded into every session via CLAUDE.md)

One line per lesson: the rule, the check that guards it ("none" — then it is a backlog item) and a link to the lesson's
own file, which holds the story — what happened and how we know the rule is right (ADR-0017). The rule lives only here.
A new lesson takes the next free number, a line here and its file `memory/lessons/L-NNN.md`. They were learned while the
engine was built; they are about the engine, the way of working and the machines it runs on, so they apply to every
project made from the kit.

- **L-001 Georgian output on Windows.** Every script that prints reconfigures stdout/stderr to UTF-8; hooks run with `PYTHONUTF8=1` through `py.sh`. Guarded by: drill (`episodic`). [[L-001]]
- **L-002 SessionEnd has a 1.5 s budget.** Slow work in a hook detaches — the child survives `claude` exiting. Guarded by: drill (`episodic`). [[L-002]]
- **L-003 Git Bash rewrites slash arguments.** Passing a slash command from bash, prefix `MSYS2_ARG_CONV_EXCL='*'` — never `MSYS_NO_PATHCONV=1`, which also stops converting environment variables. Guarded by: none. [[L-003]]
- **L-004 Skill `!` injections.** A `!` line runs before any hook and needs its `allowed-tools`; `'$ARGUMENTS'` arrives as raw text — keep such skills owner-only (`disable-model-invocation`) with one exact script allowed, matched as `*script.py* arg*` because the injected path is quoted; only the `${CLAUDE_PROJECT_DIR}` / `${CLAUDE_SESSION_ID}` substitutions reach it. Guarded by: drill (`guard`) — G9 refuses a new `!` line the guard would refuse; the rest none. [[L-004]]
- **L-005 Never touch global git config.** It belongs to the person; a project configures its own repository only (`git config --local`). Guarded by: drill (`wiring`) — every `git config` asks the owner. [[L-005]]
- **L-006 No Haiku for Georgian text.** Georgian a person reads comes from a Sonnet-class model or better. Guarded by: none for code yet (the episodic summarizer is pinned to sonnet). [[L-006]]
- **L-007 Another session may be working in this folder.** Never commit, move or edit its files. Guarded by: none. [[L-007]]
- **L-008 A shell guard must read the command the way the shell runs it.** Probe every new guard pattern with wrappers, nested shells, substitutions, multi-line commands, shell grammar before the command, `eval`, `find -exec` and a shell fed from stdin; re-run a public corpus; when the parser changes, compare the old and the new guard's verdicts. Known gap: code inside an interpreter heredoc. Guarded by: drill (`guard`). [[L-008]]
- **L-009 A stub proves the stub.** After the drill, exercise the real binary once. Guarded by: drill (`episodic`) and a live run by hand. [[L-009]]
- **L-010 Real use is a test the drill cannot run.** After a new hook ships, look at what it produced after a few days of real use. Guarded by: drill (`episodic`) — empty sessions leave no trace. [[L-010]]
- **L-011 Two sessions in one folder share the next number, the branch and the IDE bridge.** Before writing a numbered document, look at the folder itself, not only the index; before a commit, run `git branch --show-current`; reopen a conversation by its id (`claude --resume <id>`) — `--continue` takes the newest, maybe the other session's; a VS Code window's `/ide` bridge serves one conversation, so when `/ide` fails, look for another live one first. Guarded by: none. [[L-011]]
- **L-012 A subagent's research conclusion without a primary source does not go into a document.** A number or a direction comes from a primary source, or is openly marked "secondary source". Guarded by: none. [[L-012]]
- **L-013 A new hard rule gets its test scenario in the same change.** Guarded by: none until the eval suite is switched on. [[L-013]]
- **L-014 The guard over-blocks commands that merely name a trigger string.** Use the Grep/Edit tools instead of shell `grep`/heredoc, describe such a string instead of typing it, stage with `git add -u`, and pass a message that names one as a file (`git commit -F`) from the session's scratchpad, never from `.git/`. Guarded by: none — fail-closed by design ([[ADR-0007-ai-security-and-observability]]). [[L-014]]
- **L-015 Strong-safeguard models flag defensive guard-hardening as cyber-offense.** Prove guard fixes with mutation tests; keep bypass forms in code and drill files, never in prose or in a printed scan of drill.py; when a critic is blocked, the machine check is the stronger evidence. Guarded by: none (platform behaviour). [[L-015]]
- **L-016 The engine is judged by a new user's journey, not by its documents.** Test an engine change the way a new user meets it: a fresh copy, an idea as the first message, a real `claude -p` session. Guarded by: a live session in a fresh copy, by hand. [[L-016]]
- **L-017 The author's machine hides what a new user's machine lacks.** Run a new feature's drill groups once with the author's tools hidden — swap the one function that searches for a tool rather than dropping its PATH folder. Guarded by: drill (`gates`, `wiring`); the hidden-tools run is by hand. [[L-017]]
- **L-018 Two texts that name different sources for one step make the agent pick one at random.** One step, one instruction: a skill, the stage block, a guide and a template say the same thing about it, and the stage block names the source. Guarded by: drill (`graph`) — the stage texts; drill (`wiring`) — each guide's `code:` folders are in the code rule's `paths`; the rest of the skills and guides is not checked. [[L-018]]
- **L-019 A drill's timing margin is measured on a loaded machine.** A timing case leaves several seconds beyond the slowest measured step; a date is read when it is compared, not when the drill starts. Guarded by: drill (`statusline`); the date: none. [[L-019]]
- **L-020 A missing brief is an alarm.** A session that starts without the stage block and the brief runs `bash .claude/hooks/py.sh --version` before any work; if Python is missing, tell the person. Guarded by: drill (`episodic`) after the fact; live: none. [[L-020]]
- **L-021 Random test data can match a neighbouring check.** When several patterns judge one text, decide which wins and seed one deterministic case where they collide. Guarded by: drill (`decision`) — this template has no dispatcher code, so its drill leaves that group out. [[L-021]]
- **L-022 The engine's Linux runs went through WSL, and three things bite.** Start the script with `exec 2>&1`, prefix `MSYS2_ARG_CONV_EXCL='*'`, and run a copy in the Linux home with `git config core.fileMode false` in the copy only. Guarded by: none. [[L-022]]
- **L-023 A document names the file a check lives in.** Write "the drill checks it" only when `tools/gates/drill.py` or a gate runs the case; otherwise name the file and how it runs. Guarded by: none. [[L-023]]
- **L-024 A mutation MISS can mean an incomplete battery, not a redundant fix.** Before calling a security check redundant, build a battery that exercises its exact threat and confirm 0 flips there; a revert to a narrower pattern is a relaxation. Guarded by: drill (`guard`). [[L-024]]
- **L-025 One folder, several spellings.** Compare a path you were given with a resolved one in one spelling, and drill it through a folder link. Guarded by: drill (`sentinel`, `gates`). [[L-025]]
- **L-026 A graph error in a file you may not edit does not stop your work.** At commit the gates read only the staged tree, so a broken link in another session's uncommitted episode fails only a commit that stages that episode or a file linking to it: stage around it (`git update-index --cacheinfo`), tell the owner, never go around G3. Guarded by: none. [[L-026]]
