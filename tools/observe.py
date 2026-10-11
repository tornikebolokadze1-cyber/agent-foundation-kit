#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Observatory: what the agents did in this project, read from Claude Code's own session transcripts.

Claude Code already writes every step of a session to ~/.claude/projects/<project>/<session>.jsonl —
tool calls with their inputs, results and errors, hook output, permission denials, token usage — and
every subagent to <session>/subagents/*.jsonl. This tool only reads those files: no extra hook, no
runtime cost, no second log that could drift from the first. The report is in Georgian (ADR-0007).

  py -3.12 tools/observe.py report [--session ID|last|all] [--brief] [--json]
  py -3.12 tools/observe.py sessions [--days N]

Exit 0 = report printed · 2 = INCONCLUSIVE: no transcript found, or nothing in it could be read (no
evidence is not a clean report). It never prints a tool's output, and every command, path or query it
shows goes through tools/redact.py first.

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
import guard  # noqa: E402  — a command line is read the way the guard reads it (L-008)
import redact  # noqa: E402

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
    reads_outside: int = 0
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
        return "გარეთ: " + clean(raw, 80)


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
    pip_module = word in ("py", "python", "python3") and "-m" in args and "pip" in args and "install" in args
    if word in REMOTE_RUNNERS or pip_module or (word in INSTALLERS and INSTALL_SUBCMDS & set(args)):
        return "დაყენება"
    if word in DELETERS or (word == "find" and "-delete" in args):
        return "წაშლა"
    if word in NETWORK or (word == "gh" and args[:1] == ["api"]):
        return "ქსელი"
    return None


def notable_commands(cmd: str, depth: int = 0) -> list[tuple[str, str]]:
    """(kind, the command segment) for every segment that writes git history, installs, deletes or goes to the
    network — segment by segment, into nested shells, eval and $(…), with `cat <<EOF` bodies read as text."""
    cmd = guard.strip_cat_heredocs(cmd)
    out: list[tuple[str, str]] = []
    if depth < guard.MAX_NESTING:
        for inner in guard.substitutions(cmd):
            out += notable_commands(inner, depth + 1)
    for seg in guard.segments(cmd):
        word, start = guard.first_word(seg)
        nested = guard.nested_command(seg, word, start) if depth < guard.MAX_NESTING else None
        if nested:
            out += notable_commands(nested, depth + 1)
            continue
        kind = notable_kind(seg, word, start)
        if kind:
            out.append((kind, " ".join(seg[start:])))
    return out


def on_tool_use(r: Report, name: str, ti: dict, root: Path, sub: bool) -> None:
    r.tools[name] += 1
    r.by_subagents += sub
    if name in WRITE_TOOLS:
        r.files_written[rel_path(str(ti.get("file_path") or ti.get("notebook_path") or "?"), root)] += 1
    elif name in READ_TOOLS:
        raw = ti.get("file_path") or ti.get("path")
        r.reads_outside += bool(raw) and rel_path(str(raw), root).startswith("გარეთ")
    elif name in SHELL_TOOLS:
        r.commands += 1
        for kind, text in notable_commands(str(ti.get("command") or "")):
            line = f"{kind}{' (subagent)' if sub else ''}: {clean(text)}"
            if line not in r.notable and len(r.notable) < 40:
                r.notable.append(line)
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


def on_tool_result(r: Report, block: dict) -> None:
    if not block.get("is_error"):
        return
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
            for c in msg.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    on_tool_use(r, str(c.get("name") or "?"), c.get("input") or {}, root, sub)
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
                    r.files_via_shell["(და კიდევ — Claude Code-მა ყველა არ ჩამოთვალა)"] += int(diff.get("moreFiles") or 0)
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


def brief(r: Report) -> str:
    changed = len(set(r.files_written) | set(r.files_via_shell))
    cache = cache_cost.summarize(r.calls)
    cost = ""
    unpriced = f", ფასის გარეშე: {', '.join(cache['unpriced'])}" if cache["unpriced"] else ""
    if cache["usd"] is not None:
        share = f", ქეშიდან {cache['cache_share']}%" if cache["cache_share"] is not None else ""
        cost = f" · ≈${cache['usd']:.2f} API-ის ფასით{share}{unpriced}"
    elif cache["requests"]:
        cost = f" · ფასი უცნობია{unpriced}"
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
        data = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in r.__dict__.items() if k != "calls"}
        data["cache"] = cache_cost.summarize(r.calls)
        print(json.dumps(data, ensure_ascii=False, indent=1))
    else:
        print(brief(r) if a.brief else full(r, files[0] if len(files) == 1 else folder))
    return 0


if __name__ == "__main__":
    sys.exit(main())
