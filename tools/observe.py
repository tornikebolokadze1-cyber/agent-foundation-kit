#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Observatory: what the agents did in this project, read from Claude Code's own session transcripts.

Claude Code already writes every step of a session to ~/.claude/projects/<project>/<session>.jsonl —
tool calls with their inputs, results and errors, hook output, permission denials, token usage — and
every subagent to <session>/subagents/*.jsonl. This tool only reads those files: no extra hook, no
runtime cost, no second log that could drift from the first. The report is in Georgian (ADR-0007).

  bash .claude/hooks/py.sh tools/observe.py report [--session ID|last|all] [--brief] [--json]
  bash .claude/hooks/py.sh tools/observe.py sessions [--days N]

Exit 0 = report printed · 2 = INCONCLUSIVE: no transcript found, or nothing in it could be read (no
evidence is not a clean report). It never prints a tool's output, and every command, path or query it
shows goes through tools/redact.py first.

The same reading gives an episode its actions block (actions_block, ADR-0018 §3 — episodic.py writes it at SessionEnd
and in /session-close): the files the session changed and read, the commits it made, the gates it ran and their
results, the guard's and the sentinel's codes and the cost — paths and numbers only, never a conversation's, a
command's or a tool's text, and a path outside the project only as a number.

Environment: OBSERVE_TRANSCRIPTS — the transcript folder (default: the folder Claude Code names after
the project path); OBSERVE_ROOT — the project root (default: this file's project).
The transcript format is Claude Code's own and is not a public contract: an unreadable line is counted
and reported, never skipped silently. Transcripts are deleted after `cleanupPeriodDays` (default 30) —
/session-close copies the --brief line into the episode, which git keeps.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / ".claude" / "hooks"))
import cache_cost  # noqa: E402  — prices the model calls and names the cache rebuilds (ADR-0010)
import graph_layers  # noqa: E402  — the actions block's format, which the graph reads back (ADR-0018 §3)
import guard  # noqa: E402  — a command line is read the way the guard reads it (L-008)
import redact  # noqa: E402

OUTSIDE = "გარეთ: "  # how rel_path names a path outside the project
MORE_FILES = "(და კიდევ — Claude Code-მა ყველა არ ჩამოთვალა)"  # bashEditDiff's moreFiles, as files_via_shell counts it
READ_TOOLS = {"Read", "Grep", "Glob", "LS", "NotebookRead"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}
WEB_TOOLS = {"WebFetch", "WebSearch"}
AGENT_TOOLS = {"Agent", "Task"}
GUARD_RE = re.compile(r"GUARD\[([A-Z]\d+)\]")
SENTINEL_RE = re.compile(r"SENTINEL\[([A-Z]\d+)\]")
# Notable = a command that RUNS one of these, not a line that mentions it: `grep -rn "curl " src` is a search.
GIT_WRITES = {"commit", "push", "pull", "merge", "rebase", "reset", "clone", "checkout", "switch", "restore",
              "clean", "cherry-pick", "revert", "am", "apply", "rm", "mv"}
GIT_READ_FORMS = {"stash": {"list", "show"}, "remote": {"-v", "show", "get-url"}}
INSTALLERS = {"pip", "pip3", "npm", "pnpm", "yarn", "uv", "winget", "choco", "scoop", "cargo", "gem", "brew", "apt",
              "apt-get"}
INSTALL_SUBCMDS = {"install", "i", "add", "ci"}
REMOTE_RUNNERS = {"npx", "pnpx", "bunx", "pipx", "uvx"}
DELETERS = {"rm", "rmdir", "del", "erase", "rd", "remove-item", "ri", "unlink", "shred"}
NETWORK = {"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "scp", "sftp", "rsync", "ssh",
           "nc", "ncat", "telnet", "ftp"}
# What the actions block reads out of the outputs (ADR-0018 §3) — git's own line for a commit it made, `[main 1a2b3c4] …`
# or `[main (root-commit) 1a2b3c4] …`; the same, cheaply, in a transcript's raw line; gate.py's last line and its line for
# a gate that did not pass; the drill's last line. A gate's output is read only from a command that runs the gates or
# commits — a log printed back later is not a run.
COMMIT_OUT_RE = re.compile(r"(?m)^\[[^\]\n]{1,200}? ([0-9a-f]{7,40})\] ")
COMMIT_HINT_RE = re.compile(r"\[[^\]\"\\\n]{1,200} [0-9a-f]{7,40}\] ")
GATES_OUT_RE = re.compile(r"(?m)^GATES (PASS|FAIL|INCONCLUSIVE): ")
GATE_FAIL_RE = re.compile(r"(?m)^(FAIL|INCONCLUSIVE) +([\w.-]+) ")
DRILL_OUT_RE = re.compile(r"(?m)^ARMED=\d+ [^\n]*?DEAD/DEFECT=\d+ +INCONCLUSIVE=\d+")
RUNS_GATES_RE = re.compile(r"(?:gate|drill)\.py\b")
READ_SHOWN = 40          # the read files an actions block names; the rest it counts (ADR-0018 §3)
COMMIT_SLACK_S = 120     # a commit made in the session lies between its transcript's first and last line, give or take
MAX_COMMIT_CHECKS = 200  # commit lines a block asks git about


@dataclass
class Report:
    sessions: list[str] = field(default_factory=list)
    start: str = ""
    end: str = ""
    version: str = ""
    branch: str = ""
    models: Counter = field(default_factory=Counter)
    tools: Counter = field(default_factory=Counter)
    by_subagents: int = 0
    subagent_files: int = 0
    files_written: Counter = field(default_factory=Counter)
    files_via_shell: Counter = field(default_factory=Counter)
    files_read: Counter = field(default_factory=Counter)  # files inside the project its tools read (ADR-0018 §3)
    reads_outside: int = 0
    commit_seen: dict = field(default_factory=dict)  # hash → when git's own output named it (session_commits checks it)
    commit_commands: int = 0  # `git commit` runs, of them in the background — whose output the session may never see
    commit_background: int = 0
    gates: Counter = field(default_factory=Counter)  # PASS / FAIL / INCONCLUSIVE, as gate.py's last line said it
    gate_failures: Counter = field(default_factory=Counter)  # "<gate> FAIL" — the gates that did not pass
    drills: list[str] = field(default_factory=list)  # each drill run's last line
    background: int = 0  # gate, drill or commit commands run in the background: their output is elsewhere
    watched: dict = field(default_factory=dict)  # tool use id → its command runs the gates or commits (result to come)
    pending: dict = field(default_factory=dict)  # tool use id → (counter, path) of a file it changed or read, until its
    #                                              result: a call that failed or was refused changed and read nothing
    commands: int = 0
    notable: list[str] = field(default_factory=list)
    web: Counter = field(default_factory=Counter)
    mcp: Counter = field(default_factory=Counter)
    agents: list[str] = field(default_factory=list)
    skills: Counter = field(default_factory=Counter)
    guard: Counter = field(default_factory=Counter)
    guard_examples: list[str] = field(default_factory=list)
    sentinel: Counter = field(default_factory=Counter)
    denials: Counter = field(default_factory=Counter)
    tool_errors: int = 0
    tokens: Counter = field(default_factory=Counter)
    calls: list = field(default_factory=list)  # one cache_cost.Request per model call, in transcript order
    lines: int = 0
    unreadable: int = 0
    known: int = 0


def root_dir() -> Path:
    env = os.environ.get("OBSERVE_ROOT")
    return Path(env).resolve() if env else HERE.parent


def transcripts_dir(root: Path) -> Path:
    env = os.environ.get("OBSERVE_TRANSCRIPTS")
    if env:
        return Path(env)
    return Path.home() / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9]", "-", str(root))


def clean(text: str, n: int = 110) -> str:
    one = " ".join(str(text).split())
    return redact.redact(one)[0][:n]


def rel_path(raw: str, root: Path) -> str:
    try:
        return Path(raw).resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return OUTSIDE + clean(raw, 80)


def git_kind(seg: list[str], start: int) -> str | None:
    sub, rest, _ = guard.git_subcommand(seg, start)
    flags = {a for a in rest if a.startswith("-")}
    if sub in GIT_WRITES or (sub == "config" and not flags & {"--get", "--get-all", "--get-regexp", "--list", "-l"}):
        return "git-ის ჩანაწერი"
    if sub in ("tag", "branch") and (any(not a.startswith("-") for a in rest)
                                     or flags & {"-d", "-D", "--delete", "-m", "-M", "-f", "--force"}):
        return "git-ის ჩანაწერი"
    if sub in GIT_READ_FORMS and rest and rest[0] not in GIT_READ_FORMS[sub]:
        return "git-ის ჩანაწერი"
    if sub == "stash" and not rest:
        return "git-ის ჩანაწერი"
    return None


def notable_kind(seg: list[str], word: str, start: int) -> str | None:
    args = [a.lower() for a in seg[start + 1:]]
    gi = guard.git_index(seg, word, start)
    if gi is not None:
        return git_kind(seg, gi)
    launcher = word in ("bash", "sh") and args[:1] != [] and args[0].replace("\\", "/").endswith("py.sh")
    python = bool(re.fullmatch(r"py|python[\d.]*", word)) or launcher  # python3.12, .venv/bin/python, py.sh
    pip_module = python and "-m" in args and "pip" in args and "install" in args
    if word in REMOTE_RUNNERS or pip_module or (word in INSTALLERS and INSTALL_SUBCMDS & set(args)):
        return "დაყენება"
    if word in DELETERS or (word == "find" and "-delete" in args):
        return "წაშლა"
    if word in NETWORK or (word == "gh" and args[:1] == ["api"]):
        return "ქსელი"
    return None


def run_segments(cmd: str, depth: int = 0):
    """(segment, its first word, where it starts) for every segment a command runs, the way the guard reads it —
    into nested shells, eval and $(…), with `cat <<EOF` bodies read as text."""
    cmd = guard.heredocs(cmd)[0]
    if depth < guard.MAX_NESTING:
        for inner in guard.substitutions(cmd):
            yield from run_segments(inner, depth + 1)
    for seg in guard.segments(cmd):
        word, start = guard.first_word(seg)
        nested = guard.nested_command(seg, word, start) if depth < guard.MAX_NESTING else None
        if nested:
            yield from run_segments(nested, depth + 1)
            continue
        yield seg, word, start


def notable_commands(cmd: str) -> list[tuple[str, str]]:
    """(kind, the command segment) for every segment that writes git history, installs, deletes or goes to the
    network."""
    return [(kind, " ".join(seg[start:])) for seg, word, start in run_segments(cmd)
            if (kind := notable_kind(seg, word, start))]


def git_commits(cmd: str) -> int:
    """How many of the command's segments run `git commit`."""
    return sum(1 for seg, word, start in run_segments(cmd)
               if (gi := guard.git_index(seg, word, start)) is not None and guard.git_subcommand(seg, gi)[0] == "commit")


def on_tool_use(r: Report, name: str, ti: dict, root: Path, sub: bool, use_id: str = "") -> None:
    r.tools[name] += 1
    r.by_subagents += sub
    if name in WRITE_TOOLS:
        rel = rel_path(str(ti.get("file_path") or ti.get("notebook_path") or "?"), root)
        r.files_written[rel] += 1
        if use_id:
            r.pending[use_id] = (r.files_written, rel)
    elif name in READ_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path") or ti.get("path")
        rel = rel_path(str(raw), root) if raw else ""
        r.reads_outside += rel.startswith(OUTSIDE)
        # a Read names a file; a search names a file or a folder — only a file is a file the session read
        if rel and not rel.startswith(OUTSIDE) and (name in ("Read", "NotebookRead") or (root / rel).is_file()):
            r.files_read[rel] += 1
            if use_id:
                r.pending[use_id] = (r.files_read, rel)
    elif name in SHELL_TOOLS:
        r.commands += 1
        cmd = str(ti.get("command") or "")
        found = notable_commands(cmd)
        for kind, text in found:
            line = f"{kind}{' (subagent)' if sub else ''}: {clean(text)}"
            if line not in r.notable and len(r.notable) < 40:
                r.notable.append(line)
        made = git_commits(cmd)
        r.commit_commands += made
        r.commit_background += made if ti.get("run_in_background") else 0
        if RUNS_GATES_RE.search(cmd) or any(kind == "git-ის ჩანაწერი" for kind, _ in found):
            if ti.get("run_in_background"):
                r.background += 1
            elif use_id:
                r.watched[use_id] = True
    elif name == "WebFetch":
        r.web["fetch " + (urlparse(str(ti.get("url") or "")).hostname or "?")] += 1
    elif name == "WebSearch":
        r.web["search"] += 1
    elif name.startswith("mcp__"):
        parts = name.split("__")
        r.mcp["/".join(parts[1:3]) if len(parts) >= 3 else name] += 1
    elif name in AGENT_TOOLS:
        r.agents.append(f"{ti.get('subagent_type') or 'general'}: {clean(ti.get('description') or '', 60)}")
    elif name == "Skill":
        r.skills[str(ti.get("skill") or "?")] += 1


def result_text(content: object) -> str:
    """A tool result's text: a string, or the text blocks of a list."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(c.get("text") or "") for c in content if isinstance(c, dict))
    return ""


def gate_output(r: Report, text: str) -> None:
    """What a command that ran the gates (or committed — the pre-commit hook runs them) printed about them."""
    r.gates.update(GATES_OUT_RE.findall(text))
    r.gate_failures.update(f"{gate} {status}" for status, gate in GATE_FAIL_RE.findall(text))
    r.drills += [" ".join(m.group(0).split()) for m in DRILL_OUT_RE.finditer(text)]


def on_tool_result(r: Report, block: dict) -> None:
    use_id = str(block.get("tool_use_id") or "")
    if r.watched.pop(use_id, None):
        gate_output(r, result_text(block.get("content")))
    took = r.pending.pop(use_id, None)
    if not block.get("is_error"):
        return
    if took:  # the call failed or was refused: the file was neither changed nor read by it
        counter, rel = took
        counter[rel] -= 1
        if counter[rel] <= 0:
            del counter[rel]
    content = block.get("content")
    text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
    codes = GUARD_RE.findall(text)
    if codes:
        r.guard.update(codes)
        if len(r.guard_examples) < 8:
            r.guard_examples.append(f"{codes[0]}: {clean(text.split(codes[0] + ']:', 1)[-1], 90)}")
    elif "Permission to use" in text or "permission" in text.lower() and "denied" in text.lower():
        pass  # counted from toolDenialKind on the same record
    else:
        r.tool_errors += 1


def epoch(ts: str) -> float:
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def read_file(r: Report, path: Path, root: Path, sub: bool) -> None:
    usage: dict[str, dict] = {}
    calls: dict[str, cache_cost.Request] = {}
    compacted = fallback = restarted = False  # a marker line seen since the last model call
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        r.unreadable += 1
        return
    for line in lines:
        if not line.strip():
            continue
        r.lines += 1
        try:
            d = json.loads(line)
        except ValueError:
            r.unreadable += 1
            continue
        if not isinstance(d, dict):
            r.unreadable += 1
            continue
        if not sub and d.get("isSidechain"):
            continue  # a subagent's step: counted from its own file
        typ = d.get("type")
        ts = str(d.get("timestamp") or "")
        if ts:
            r.start = min(r.start or ts, ts)
            r.end = max(r.end, ts)
        r.version = str(d.get("version") or r.version)
        r.branch = str(d.get("gitBranch") or r.branch)
        if d.get("isCompactSummary") or d.get("subtype") == "compact_boundary":
            compacted = True
        elif d.get("subtype") == "model_refusal_fallback":
            fallback = True
        elif isinstance(d.get("attachment"), dict) and d["attachment"].get("type") == "session_context":
            restarted = True  # written when Claude Code opens (or re-opens) the session
        raw_msg = d.get("message")
        msg: dict = raw_msg if isinstance(raw_msg, dict) else {}
        # git's line for a commit it made, wherever an output reached the session — a command's result, a background
        # task's notice; never the model's own text or its tool inputs (session_commits keeps only this session's)
        if typ in ("user", "attachment", "queue-operation") and COMMIT_HINT_RE.search(line):
            for sha in COMMIT_OUT_RE.findall(redact.text_of(d)):
                r.commit_seen.setdefault(sha, ts)
        if typ == "assistant":
            r.known += 1
            if msg.get("model") == "<synthetic>":
                continue  # a placeholder Claude Code writes itself (e.g. after an API error): no model call, no usage
            if msg.get("model"):
                r.models[str(msg["model"])] += 0 if msg.get("id") in usage else 1
            if isinstance(msg.get("usage"), dict):
                key = str(msg.get("id") or len(usage))
                usage[key] = msg["usage"]
                if key not in calls:
                    calls[key] = cache_cost.Request(path.stem, sub, str(msg.get("model") or "?"), epoch(ts),
                                                    str(d.get("version") or ""), compacted=compacted, fallback=fallback,
                                                    restarted=restarted)
                    r.calls.append(calls[key])
                    compacted = fallback = restarted = False
                calls[key].update(msg["usage"])
                diag = msg.get("diagnostics")
                miss = diag.get("cache_miss_reason") if isinstance(diag, dict) else None
                if isinstance(miss, dict) and miss.get("type"):
                    calls[key].miss = str(miss["type"])  # the transcript's own cache-miss reason
            for c in msg.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    on_tool_use(r, str(c.get("name") or "?"), c.get("input") or {}, root, sub, str(c.get("id") or ""))
        elif typ == "user":
            r.known += 1
            if d.get("toolDenialKind"):
                r.denials[str(d["toolDenialKind"])] += 1
            tur = d.get("toolUseResult")
            diff = tur.get("bashEditDiff") if isinstance(tur, dict) else None
            if isinstance(diff, dict):  # files a shell command changed, as far as Claude Code tracked them
                for item in diff.get("files") or []:
                    if isinstance(item, dict) and item.get("filePath"):
                        r.files_via_shell[rel_path(str(item["filePath"]), root)] += 1
                if diff.get("moreFiles"):
                    r.files_via_shell[MORE_FILES] += int(diff.get("moreFiles") or 0)
            content = msg.get("content")
            for c in content if isinstance(content, list) else []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    on_tool_result(r, c)
        elif typ == "attachment":
            r.known += 1
            a = d.get("attachment") or {}
            if isinstance(a, dict) and "hook" in str(a.get("type")):
                r.sentinel.update(SENTINEL_RE.findall(str(a.get("content") or "")))
    for u in usage.values():
        r.tokens["input"] += int(u.get("input_tokens") or 0)
        r.tokens["cache_read"] += int(u.get("cache_read_input_tokens") or 0)
        r.tokens["cache_write"] += int(u.get("cache_creation_input_tokens") or 0)
        r.tokens["output"] += int(u.get("output_tokens") or 0)


def build(files: list[Path], root: Path) -> Report:
    r = Report()
    for f in files:
        r.sessions.append(f.stem)
        read_file(r, f, root, sub=False)
        subdir = f.with_suffix("") / "subagents"
        for s in sorted(subdir.glob("*.jsonl")) if subdir.is_dir() else []:
            r.subagent_files += 1
            read_file(r, s, root, sub=True)
    return r


def local(ts: str) -> str:
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts or "?"


def num(n: int) -> str:
    return f"{n / 1e6:.2f}M" if n >= 1e6 else (f"{n / 1e3:.0f}K" if n >= 1e3 else str(n))


def counts(c: Counter, sep: str = " · ") -> str:
    return sep.join(f"{k} ×{v}" for k, v in c.most_common()) or "—"


def actions(r: Report) -> int:
    return sum(r.tools.values())


def cost_text(r: Report) -> str:
    """The sessions' cost at API list prices and the cache's share (ADR-0010) — "" when no model call was read."""
    cache = cache_cost.summarize(r.calls)
    unpriced = f", ფასის გარეშე: {', '.join(cache['unpriced'])}" if cache["unpriced"] else ""
    if cache["usd"] is not None:
        share = f", ქეშიდან {cache['cache_share']}%" if cache["cache_share"] is not None else ""
        return f"≈${cache['usd']:.2f} API-ის ფასით{share}{unpriced}"
    return f"ფასი უცნობია{unpriced}" if cache["requests"] else ""


def brief(r: Report) -> str:
    changed = len(set(r.files_written) | set(r.files_via_shell))
    priced = cost_text(r)
    cost = f" · {priced}" if priced else ""
    return (f"აუდიტი ({', '.join(s[:8] for s in r.sessions)}): {actions(r)} მოქმედება · {changed} ფაილი "
            f"შეიცვალა · {r.commands} ბრძანება · guard-ის ბლოკი {sum(r.guard.values())}"
            f"{' (' + ', '.join(sorted(r.guard)) + ')' if r.guard else ''} · sentinel {sum(r.sentinel.values())}"
            f"{' (' + ', '.join(sorted(r.sentinel)) + ')' if r.sentinel else ''} · უარყოფილი ნებართვა "
            f"{sum(r.denials.values())} · ტოკენები: {num(r.tokens['input'] + r.tokens['cache_read'] + r.tokens['cache_write'])}"
            f" შესვლა / {num(r.tokens['output'])} გამოსვლა{cost}")


def full(r: Report, src: Path) -> str:
    t = r.tools
    groups = {"წაკითხვა": READ_TOOLS, "ჩაწერა": WRITE_TOOLS, "ბრძანება": SHELL_TOOLS, "ვებ": WEB_TOOLS,
              "subagent-ის გაშვება": AGENT_TOOLS, "skill": {"Skill"}}
    shown = {k: sum(t[n] for n in names) for k, names in groups.items()}
    shown["MCP"] = sum(v for k, v in t.items() if k.startswith("mcp__"))
    shown["სხვა"] = actions(r) - sum(shown.values())
    out = [
        f"# დაკვირვება — {', '.join(s[:8] for s in r.sessions)}",
        f"დრო: {local(r.start)} – {local(r.end)} · ბრანჩი: {r.branch or '?'} · Claude Code {r.version or '?'} · "
        f"მოდელები: {', '.join(r.models) or '?'}",
        "",
        f"## მოქმედებები: {actions(r)} (მათგან subagent-ებმა — {r.by_subagents}, {r.subagent_files} ფაილი)",
        " · ".join(f"{k}: {v}" for k, v in shown.items()),
        f"პროექტის გარეთ წაკითხული: {r.reads_outside}",
        "",
        f"## შეცვლილი ფაილები ({len(set(r.files_written) | set(r.files_via_shell))})",
        *[f"- {p} (×{n})" for p, n in sorted(r.files_written.items())],
        *[f"- {p} (ბრძანებით ×{n})" for p, n in sorted(r.files_via_shell.items())],
        "(ბრძანებით შეცვლილი ჩანს მხოლოდ ის ფაილი, რომელსაც Claude Code ადევნებდა თვალს — სრული სია მხოლოდ git-ს აქვს)",
        "",
        "## ბრძანებები, რომლებსაც ყურადღება სჭირდება",
        *([f"- {x}" for x in r.notable] or ["- არცერთი (git-ის ჩანაწერი, დაყენება, წაშლა, ქსელი)"]),
        "",
        f"## ვებ და MCP\nვებ: {counts(r.web)}\nMCP: {counts(r.mcp)}",
        f"subagent-ები: {'; '.join(r.agents) or '—'}",
        f"skill-ები: {counts(r.skills)}",
        "",
        "## უსაფრთხოება",
        f"- guard-მა შეაჩერა: {sum(r.guard.values())} ({counts(r.guard)})",
        *[f"  - {x}" for x in r.guard_examples],
        f"- sentinel: {sum(r.sentinel.values())} ({counts(r.sentinel)}) — R1/R2 გასაღები გამოჩნდა, I1/I2 საეჭვო ტექსტი",
        f"- უარყოფილი ნებართვა: {sum(r.denials.values())} ({counts(r.denials)})",
        f"- ხელსაწყოს სხვა შეცდომები: {r.tool_errors}",
        "",
        f"## ტოკენები\nშესვლა {num(r.tokens['input'])} · cache-დან {num(r.tokens['cache_read'])} · "
        f"cache-ში ჩაწერა {num(r.tokens['cache_write'])} · გამოსვლა {num(r.tokens['output'])}",
        "",
        *cache_cost.render(cache_cost.summarize(r.calls)),
        "",
        f"წყარო: {src} · ხაზები: {r.lines} · წაუკითხავი: {r.unreadable}",
    ]
    return "\n".join(out)


# ── An episode's actions block (ADR-0018 §3; tools/graph_layers.py reads it back) ─────────────────────────────────
ACTIONS_TITLE = graph_layers.ACTIONS_HEAD + " (გენერირებულია სესიის ჩანაწერიდან — ADR-0018 §3; ხელით არ იცვლება)"


def session_commits(r: Report, root: Path) -> tuple[list[str], int, str]:
    """(short hashes, the others, why none could be checked) of the commits git's own output in this transcript names,
    kept when this repository holds them and they were made while the session ran — not a hash an old log printed back,
    not another repository's commit."""
    if not r.commit_seen:
        return [], 0, ""
    rc, top = graph_layers.git_answers(root, "rev-parse", "--show-toplevel")
    if rc != 0 or not graph_layers.same_folder(top, root):
        return [], len(r.commit_seen), "პროექტის საქაღალდე git-ის საცავი არ არის"
    lo = epoch(r.start) - COMMIT_SLACK_S if r.start else 0.0
    hi = epoch(r.end) + COMMIT_SLACK_S if r.end else float("inf")
    mine: list[str] = []
    for sha in list(r.commit_seen)[:MAX_COMMIT_CHECKS]:
        rc, out = graph_layers.git_answers(root, "show", "-s", "--format=%h %ct", f"{sha}^{{commit}}")
        short, _, when = out.partition(" ")
        if rc == 0 and when.isdigit() and lo <= int(when) <= hi and short not in mine:
            mine.append(short)
    return mine, len(r.commit_seen) - len(mine), ""


def nameable(path: str) -> bool:
    """A path the block can write as code: no backtick, no control or hidden character."""
    return "`" not in path and path.isprintable() and not redact.hidden_chars(path)


def spans(items: list[tuple[str, int]]) -> str:
    shown = [f"`{p}` ×{n}" for p, n in items if nameable(p)]
    odd = len(items) - len(shown)
    return (" · ".join(shown) or "—") + (f" · კიდევ {odd}, რომლის სახელი ჩასაწერად არ გამოდგება" if odd else "")


def gates_text(r: Report) -> str:
    runs = " · ".join(f"GATES {k} ×{r.gates[k]}" for k in ("PASS", "FAIL", "INCONCLUSIVE") if r.gates[k])
    failed = f" (არ გავიდა: {counts(r.gate_failures, ', ')})" if r.gate_failures else ""
    drill = f" · დრილი ×{len(r.drills)}, ბოლოს: {r.drills[-1]}" if r.drills else ""
    away = f" · ფონზე გაშვებული {r.background} — მათი შედეგი აქ არ ჩანს" if r.background else ""
    return (runs or "არცერთი გაშვება არ ჩანს") + failed + drill + away


def actions_block(r: Report, root: Path) -> str:
    """The actions block of the session this report read (ADR-0018 §3): the files it changed and read — inside the
    project, by relative path; the read list names the READ_SHOWN most read and counts the rest —, the commits it made
    (session_commits), the gates it ran and their results, the guard's and the sentinel's codes, and the cost. Never a
    conversation's text, a command's text or a tool's output; a path outside the project only as a number; every line
    through tools/redact.py."""
    def inside(c: Counter) -> Counter:
        return Counter({p: n for p, n in c.items() if not p.startswith(OUTSIDE) and p != MORE_FILES})
    gl = graph_layers
    changed = inside(r.files_written) + inside(r.files_via_shell)
    outside = sum(1 for p in set(r.files_written) | set(r.files_via_shell) if p.startswith(OUTSIDE))
    more = r.files_via_shell.get(MORE_FILES, 0)
    reads = sorted(inside(r.files_read).items(), key=lambda kv: (-kv[1], kv[0]))
    commits, others, unchecked = session_commits(r, root)
    cut = f", ნაჩვენებია {READ_SHOWN}, კიდევ {len(reads) - READ_SHOWN} — მხოლოდ რიცხვად" if len(reads) > READ_SHOWN else ""
    beyond = (f" · ვერ შემოწმდა {others}: {unchecked}" if unchecked
              else f" · კიდევ {others} — სხვა საცავისაა ან ამ სესიამდე გაკეთდა" if others else "")
    if r.commit_commands:  # a commit whose output the session never saw (in the background, sent to a file) is not here
        away = f", ფონზე {r.commit_background}" if r.commit_background else ""
        beyond += (f" · git commit ×{r.commit_commands}{away} — სიაშია ის, რომლის hash-იც git-მა სესიას აჩვენა")
    tokens = r.tokens["input"] + r.tokens["cache_read"] + r.tokens["cache_write"]
    cost = cost_text(r)
    lines = [
        gl.ACTIONS_START, ACTIONS_TITLE, "",
        f"- ჩანაწერი: {local(r.start)} – {local(r.end)} · ხაზი {r.lines}, წაუკითხავი {r.unreadable} · subagent-ის "
        f"ფაილი {r.subagent_files}",
        f"{gl.CHANGED_HEAD} ({len(changed)}): {spans(sorted(changed.items()))}"
        + (f" · კიდევ {more}, რომელიც Claude Code-მა არ ჩამოთვალა" if more else ""),
        f"{gl.READ_HEAD} ({len(reads)}{cut}): {spans(reads[:READ_SHOWN])}",
        f"- პროექტის გარეთ (მხოლოდ რიცხვი): წაკითხვა {r.reads_outside} · შეცვლილი ფაილი {outside}",
        f"{gl.COMMITS_HEAD} ({len(commits)}): {' · '.join(f'`{s}`' for s in commits) or '—'}{beyond}",
        f"- კარიბჭეები: {gates_text(r)}",
        f"- guard: {counts(r.guard)} · sentinel: {counts(r.sentinel)} · უარყოფილი ნებართვა: {sum(r.denials.values())}",
        f"- ხარჯი: {actions(r)} მოქმედება · {r.commands} ბრძანება · ტოკენები: {num(tokens)} შესვლა / "
        f"{num(r.tokens['output'])} გამოსვლა" + (f" · {cost}" if cost else ""),
        gl.ACTIONS_END,
    ]
    return "\n".join(redact.redact(x)[0] for x in lines) + "\n"


def actions_unread(why: str) -> str:
    """The block for a session whose transcript could not be read: it says so — an empty list would read as a session
    that did nothing."""
    gl = graph_layers
    return "\n".join([gl.ACTIONS_START, ACTIONS_TITLE, "", f"{gl.UNREAD_HEAD}: {redact.redact(why)[0]} — ეს არ "
                      "ნიშნავს, რომ სესიაში არაფერი გაკეთებულა.", gl.ACTIONS_END]) + "\n"


def pick(folder: Path, session: str | None) -> list[Path]:
    files = sorted(folder.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not session or session == "last":
        return files[-1:]
    if session == "all":
        return files
    return [f for f in files if f.stem.startswith(session)]


def inconclusive(msg: str) -> int:
    print(f"OBSERVE INCONCLUSIVE: {msg}")
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="what the agents did — read from Claude Code transcripts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("report")
    rp.add_argument("--session")
    rp.add_argument("--brief", action="store_true")
    rp.add_argument("--json", action="store_true")
    sp = sub.add_parser("sessions")
    sp.add_argument("--days", type=int, default=14)
    a = ap.parse_args(argv)
    root = root_dir()
    folder = transcripts_dir(root)
    if not folder.is_dir():
        return inconclusive(f"transcript folder not found: {folder}")
    if a.cmd == "sessions":
        cutoff = dt.datetime.now().timestamp() - a.days * 86400
        files = [f for f in sorted(folder.glob("*.jsonl"), key=lambda p: p.stat().st_mtime) if f.stat().st_mtime >= cutoff]
        if not files:
            return inconclusive(f"no session in the last {a.days} day(s) in {folder}")
        for f in files:
            print("- " + brief(build([f], root)))
        return 0
    files = pick(folder, a.session)
    if not files:
        return inconclusive(f"no transcript matches session {a.session!r} in {folder}")
    r = build(files, root)
    if r.known == 0:
        return inconclusive(f"{r.lines} line(s) read, none in a known format ({r.unreadable} unreadable) — "
                            "Claude Code may have changed its transcript format")
    if a.json:
        data = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in r.__dict__.items() if k not in ("calls", "watched", "pending")}
        data["cache"] = cache_cost.summarize(r.calls)
        print(json.dumps(data, ensure_ascii=False, indent=1))
    else:
        print(brief(r) if a.brief else full(r, files[0] if len(files) == 1 else folder))
    return 0


if __name__ == "__main__":
    sys.exit(main())
