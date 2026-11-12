#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic gate runner. The gates themselves are listed in tools/gates/gates.toml.

  bash .claude/hooks/py.sh tools/gates/gate.py                  every enabled gate, whole project
  bash .claude/hooks/py.sh tools/gates/gate.py --pre-commit     gates marked pre_commit, on what the commit records
  bash .claude/hooks/py.sh tools/gates/gate.py --files F [F…]   gates marked stop, restricted to these files
  bash .claude/hooks/py.sh tools/gates/gate.py --only graph,json   these gates; a name no gate has is INCONCLUSIVE
  bash .claude/hooks/py.sh tools/gates/gate.py --list

Exit 0 = every enabled gate passed · 1 = at least one FAILED · 2 = INCONCLUSIVE (a gate
could not run, or checked zero files). SKIP (switched off) is reported and is not a pass.
Every result line names the input it actually used, so a gate that quietly checked
nothing cannot look green (ADR-0006: no evidence is not a pass).

At commit (--pre-commit) a gate that reads files reads the staged text — the next commit's tree, exported from the
git index — never the working copy; the secrets gate reads the staged files itself. A gate that runs the working
copy's code (a `cmd` gate, the drill) is INCONCLUSIVE when a staged file changed again after `git add`. The drill gate's
own table (its floor, on or off) is the staged gates.toml's too, unless drill.py on disk is not what the commit
records: then the drill counts the disk's cases and is held to the disk's floor. Known limit: a file changed on disk but
not staged at all still reaches a `cmd` gate or the drill as it is on disk.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
# Windows looks for a program in the current folder before PATH unless this is set. Here the current folder is the
# project, where a planted gitleaks.bat would otherwise stand in for the scanner and report a pass (review S4).
os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import budget  # noqa: E402
import context_graph as cg  # noqa: E402
import drill_floor  # noqa: E402
import engine_line  # noqa: E402
import redact  # noqa: E402
# One implementation of "does this commit, this path exist" for the tasks gate, the memory gate and the graph's bridges
# (ADR-0018 §2): it lives in the graph's leaf module.
from graph_layers import (COMMENT_STYLES, IMPORT_READERS, SHA_RE, TASK_DONE_RE, TASK_ID_RE, TASK_LINE_RE,  # noqa: E402
                          commit_exists, git_answers, path_claim, path_status)

TEXT_SUFFIXES = {".py", ".sh", ".md", ".json", ".toml", ".txt", ".yml", ".yaml", ".js", ".ts", ".css", ".html", ".csv"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".editorconfig", ".env.example", "pre-commit"}
# What the graph's code layer reads (ADR-0018 §4) is exported with its text at commit too: a file exported empty would
# hide its imports and the ids its comments cite from the commit's graph check (a .tsx, an .mjs, a .scss)
CODE_TEXT_SUFFIXES = frozenset(COMMENT_STYLES) | frozenset(IMPORT_READERS)


@dataclass
class Result:
    gate: str
    status: str                 # PASS | FAIL | INCONCLUSIVE | SKIP
    summary: str
    details: list[str] = field(default_factory=list)
    notice: bool = False        # a PASS that left something unchecked: shown even with --quiet (the commit hook)


def root_dir() -> Path:
    env = os.environ.get("GATE_ROOT")
    return Path(env).resolve() if env else HERE.parents[1]


def project_files(root: Path) -> tuple[list[Path], str]:
    """Files git would track (tracked + untracked-not-ignored). Names the input it used."""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                           capture_output=True, timeout=30)
        if r.returncode == 0:
            names = [n for n in r.stdout.decode("utf-8", "replace").split("\0") if n]
            return [root / n for n in names if (root / n).is_file()], "git ls-files"
    except (OSError, subprocess.SubprocessError):
        pass
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "__pycache__", "graph"}]
        out += [Path(dirpath) / f for f in filenames]
    return out, "filesystem walk (git unavailable)"


def rel(root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(p)


def owned(root: Path, p: Path) -> bool:
    """False for foreign folders (other sessions' research) — their files are not ours to police."""
    return not rel(root, p).startswith(cg.FOREIGN_PREFIXES)


def pick(files: list[Path], suffixes: set[str], names: set[str] = frozenset()) -> list[Path]:
    out = []
    for p in files:
        if p.suffix.lower() in suffixes or p.name in names:
            out.append(p)
        elif p.parent.name == ".githooks" and ".sh" in suffixes and not p.suffix:
            out.append(p)
    return out


# ── builtin checkers ─────────────────────────────────────────────────────────
def gate_graph(root: Path, files: list[Path] | None, repo: Path | None = None, **_) -> Result:
    if not (root / "intent.md").exists() and not (root / "docs").is_dir():
        return Result("graph", "INCONCLUSIVE", f"{root} does not look like the project root")
    # the bridges too (ADR-0018 §2): at commit `root` is a copy of the index and `repo` the repository it came from
    g = cg.load(root, layers=True, repo=repo or root, at_commit=repo is not None and repo != root)
    scanned = sum(1 for n in g.nodes.values() if n.path.endswith(".md") and not n.foreign)
    if scanned == 0:
        return Result("graph", "INCONCLUSIVE", "0 knowledge files scanned")
    issues = cg.check(g)
    if files is not None:
        issues = cg.filter_issues(issues, [str(f) for f in files], root)
    errors = [i for i in issues if i.level == "error"]
    warns = [i for i in issues if i.level == "warning"]
    scope = f"{len(files)} file(s)" if files is not None else "whole vault"
    _, links, _, bridges = cg.counts(g)
    unread = g.coverage.get("commits") if isinstance(g.coverage.get("commits"), str) else ""
    s = (f"{scanned} notes, {links} links, {bridges} bridges{f' (commits not read: {unread})' if unread else ''}; "
         f"scope={scope}; errors={len(errors)}, warnings={len(warns)}")
    return Result("graph", "FAIL" if errors else "PASS", s, [i.fmt() for i in errors + warns][:40], notice=bool(unread))


# JSON with comments and trailing commas (JSONC): the TypeScript and VS Code settings files a scaffold writes
# (`npm create vite`, `npm create astro`) are read that way by their own tools, so a comment there is no error (review M8).
JSONC_NAMES = re.compile(r"^(?:tsconfig|jsconfig)(?:\.[\w.-]+)?\.json$|^(?:devcontainer|\.devcontainer)\.json$")
JSONC_COMMENT_RE = re.compile(r'"(?:[^"\\]|\\.)*"|//[^\n]*|/\*.*?\*/', re.S)
JSONC_COMMA_RE = re.compile(r'"(?:[^"\\]|\\.)*"|,(?=\s*[\]}])')


def jsonc_text(text: str) -> str:
    """JSONC as plain JSON: comments out, then trailing commas out; a string is never touched."""
    def keep_strings(m: re.Match[str]) -> str:
        return m.group(0) if m.group(0).startswith('"') else ""
    return JSONC_COMMA_RE.sub(keep_strings, JSONC_COMMENT_RE.sub(keep_strings, text))


def gate_json(root: Path, files: list[Path], **_) -> Result:
    # The product's own code folder (CODE_MARKERS — package.json, pyproject.toml) is checked by its own lint and tests,
    # as the context graph leaves it to them too.
    product = cg.code_folders(root)
    todo = [p for p in pick(files, {".json"}) if owned(root, p) and not rel(root, p).startswith(product)]
    bad = []
    for p in todo:
        try:
            text = p.read_text(encoding="utf-8")
            jsonc = JSONC_NAMES.match(p.name) or p.parent.name in (".vscode", ".devcontainer")
            json.loads(jsonc_text(text) if jsonc else text)
        except (ValueError, OSError) as e:
            bad.append(f"{rel(root, p)}: {e}")
    return Result("json", "FAIL" if bad else "PASS", f"{len(todo)} .json file(s) parsed", bad)


def gate_toml(root: Path, files: list[Path], **_) -> Result:
    todo = [p for p in pick(files, {".toml"}) if owned(root, p)]
    bad = []
    for p in todo:
        try:
            tomllib.loads(p.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as e:
            bad.append(f"{rel(root, p)}: {e}")
    return Result("toml", "FAIL" if bad else "PASS", f"{len(todo)} .toml file(s) parsed", bad)


def gate_python(root: Path, files: list[Path], **_) -> Result:
    todo = [p for p in pick(files, {".py"}) if owned(root, p)]
    bad = []
    for p in todo:
        try:
            compile(p.read_text(encoding="utf-8"), str(p), "exec")
        except (SyntaxError, ValueError, OSError) as e:
            bad.append(f"{rel(root, p)}: {type(e).__name__}: {e}")
    return Result("python", "FAIL" if bad else "PASS", f"{len(todo)} .py file(s) compiled", bad)


def _is_wsl_bash(p: str) -> bool:
    """Windows' System32/WindowsApps bash.exe is the WSL launcher, not Git Bash — it rejects Windows paths and drops env vars."""
    return os.name == "nt" and p.replace("\\", "/").lower().endswith(
        ("/system32/bash.exe", "/system32/bash.bat", "/sysnative/bash.exe", "/windowsapps/bash.exe"))


def find_bash() -> str | None:
    for cand in (os.environ.get("GATE_BASH"), shutil.which("bash"), r"C:\Program Files\Git\bin\bash.exe"):
        if cand and not _is_wsl_bash(cand) and Path(cand).exists():
            return cand
    return None


def gate_shell(root: Path, files: list[Path], repo: Path | None = None, **_) -> Result:
    todo = [p for p in pick(files, {".sh"}) if owned(root, p)]
    if not todo:
        return Result("shell", "PASS", "0 shell script(s) in scope")
    bash = find_bash()
    if not bash:
        return Result("shell", "INCONCLUSIVE", f"bash not found — {len(todo)} script(s) NOT checked")
    bad = []
    for p in todo:
        r = subprocess.run([bash, "-n", str(p)], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            bad.append(f"{rel(root, p)}: {r.stderr.strip()[:200]}")
    # git runs a hook only when it is executable. Windows cannot tell, so the mode git stores is what a macOS or Linux
    # clone gets: a hook stored as 100644 is skipped there, with no more than a hint in git's output.
    hooks = [rel(root, p) for p in todo if p.parent.name == ".githooks"]
    stored = []  # (mode, name) for each hook git has in its index; an untracked one has no stored mode yet
    if hooks:
        try:
            r = subprocess.run(["git", "-C", str(repo or root), "ls-files", "-s", "--", *hooks], capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=30)
            why = "" if r.returncode == 0 else (r.stderr.strip() or f"exit {r.returncode}")[:160]
        except (OSError, subprocess.SubprocessError) as e:
            r, why = None, str(e)[:160]
        if why:
            return Result("shell", "FAIL" if bad else "INCONCLUSIVE", f"{len(todo)} script(s) checked with "
                          f"{Path(bash).name} -n; git could not list the hooks ({why}) — the executable mode of "
                          f"{len(hooks)} hook(s) NOT checked", bad)
        stored = [(meta.split()[0], name) for meta, _, name in (ln.partition("\t") for ln in r.stdout.splitlines())]
    for mode, name in stored:
        if mode != "100755":
            bad.append(f"{name}: stored in git as {mode}, not 100755 — on macOS and Linux git would skip this hook; "
                       f"`git update-index --chmod=+x {name}`")
    return Result("shell", "FAIL" if bad else "PASS", f"{len(todo)} script(s) checked with {Path(bash).name} -n; "
                  f"{len(stored)} of {len(hooks)} hook(s) checked for the executable mode git stores"
                  + (f" ({len(hooks) - len(stored)} not in git yet: no stored mode)" if len(stored) < len(hooks) else ""), bad)


def gate_eol(root: Path, files: list[Path], **_) -> Result:
    todo = [p for p in pick(files, TEXT_SUFFIXES, TEXT_NAMES) if owned(root, p)]
    todo += [p for p in files if p.parent.name == ".githooks" and p not in todo]
    bad = []
    for p in todo:
        try:
            if b"\r\n" in p.read_bytes():
                bad.append(f"{rel(root, p)}: CRLF line endings")
        except OSError as e:
            bad.append(f"{rel(root, p)}: unreadable: {e}")
    return Result("eol", "FAIL" if bad else "PASS", f"{len(todo)} text file(s) checked for CRLF", bad)


def find_gitleaks() -> str | None:
    explicit = os.environ.get("GITLEAKS_BIN")
    if explicit:  # an explicit setting wins — a wrong one must not silently fall back
        return explicit if Path(explicit).exists() else None
    for cand in (shutil.which("gitleaks"), str(Path.home() / "bin" / "gitleaks.exe"), str(Path.home() / "bin" / "gitleaks")):
        if cand and Path(cand).exists():
            return cand
    return None


def untracked_files(root: Path) -> list[Path] | None:
    """Files git does not track yet and does not ignore (None if git cannot say)."""
    r = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "-z"],
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        return None
    return [root / n for n in r.stdout.decode("utf-8", "replace").split("\0") if n and (root / n).is_file()]


SCAN_CHUNK, SCAN_OVERLAP = 1_000_000, 8_192


def staged_blobs(root: Path) -> tuple[list[tuple[str, bytes | None]], str]:
    """(path, staged content) of every file the next commit adds or changes, and what went wrong ("" when nothing).
    A submodule entry (gitlink, mode 160000) points at another repository's commit — no content: listed with None."""
    r = subprocess.run(["git", "-C", str(root), "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
                        "--diff-filter=ACMT"], capture_output=True, timeout=30)
    if r.returncode != 0:
        return [], "git could not list the staged files"
    fields = r.stdout.decode("utf-8", "replace").split("\0")
    out = []
    for meta, name in zip(fields[0::2], fields[1::2]):  # ":old_mode new_mode old_sha new_sha status", then the path
        parts = meta.split()
        if len(parts) != 5 or not name:
            return [], f"git listed a staged entry it could not parse ({meta[:60]!r})"
        if parts[1] == "160000":
            out.append((name, None))
            continue
        blob = subprocess.run(["git", "-C", str(root), "cat-file", "blob", parts[3]], capture_output=True, timeout=30)
        if blob.returncode != 0:
            return [], f"git could not read the staged {name}"
        out.append((name, blob.stdout))
    return out, ""


def engine_scan(root: Path, files: list[Path], pre_commit: bool) -> Result:
    """gitleaks is not installed (ADR-0011): the engine's own scanner — tools/redact.py, the list the sentinel uses —
    reads the same files. It has no entropy threshold and does not read git history; the result line says so."""
    label = "staged" if pre_commit else "working-tree"
    if pre_commit:
        blobs, err = staged_blobs(root)
        if err:
            return Result("secrets", "INCONCLUSIVE", f"gitleaks not installed and {err} — nothing was scanned")
    else:
        blobs = []
        for p in files:
            try:
                blobs.append((rel(root, p), p.read_bytes()))
            except OSError as e:
                return Result("secrets", "INCONCLUSIVE", f"engine scanner could not read {rel(root, p)}: {e}")
    found, scanned, binary, links = [], 0, [], 0
    for name, data in blobs:
        if data is None:
            links += 1
            continue
        text = readable(data)
        if text is None:
            binary.append(name)
            continue
        scanned += 1
        found += [f"{label} {name}:{line} — {kind}" for kind, line in secret_lines(text)]  # never the value
    summary = ("engine scanner (gitleaks not installed — no entropy threshold, git history not scanned, a token marked as "
               f"an example right beside it is not counted): {scanned} {label} file(s)"
               + (f", {len(binary)} binary NOT scanned" if binary else "")
               + (f", {links} submodule pointer(s) — no content" if links else ""))
    shown = [f"binary, not scanned: {b}" for b in binary[:10]]
    if found:
        return Result("secrets", "FAIL", summary, found)
    if binary and not scanned:  # content was there and none of it could be read
        return Result("secrets", "INCONCLUSIVE", summary + " — nothing readable was scanned", shown)
    return Result("secrets", "PASS", summary, shown, notice=bool(binary))


def readable(data: bytes) -> str | None:
    """A file's text, or None for a binary one. UTF-16 with a byte-order mark is text, not binary."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def secret_lines(text: str) -> list[tuple[str, int]]:
    """(kind, line) of every credential in `text`, read in overlapping 1 MB pieces: a large file is scanned whole at
    a cost that grows with its size, and a token on a piece's edge is complete in one of them."""
    seen: set[int] = set()
    out = []
    for base in range(0, len(text) or 1, SCAN_CHUNK):
        for kind, start, _end in redact.find_secrets(text[base:base + SCAN_CHUNK + SCAN_OVERLAP], skip_decoys=True):
            if base + start not in seen:
                seen.add(base + start)
                out.append((kind, text.count("\n", 0, base + start) + 1))
    return out


def gate_secrets(root: Path, files: list[Path], pre_commit: bool = False, **_) -> Result:
    gl = find_gitleaks()
    if not gl:
        explicit = os.environ.get("GITLEAKS_BIN")
        if explicit:  # a named gitleaks that is not there is a broken setting, not a missing tool
            return Result("secrets", "INCONCLUSIVE", f"GITLEAKS_BIN names {explicit}, which does not exist — "
                                                     "nothing was scanned")
        return engine_scan(root, files, pre_commit)
    # gitleaks' git modes never read an untracked file, so the full run also scans those one by one
    # (`gitleaks dir` takes exactly one path). The commit itself is guarded by the staged scan.
    scans = [("staged", ["git", "--pre-commit", "--staged", str(root)])]
    if not pre_commit:
        scans += [("unstaged", ["git", "--pre-commit", str(root)]), ("history", ["git", str(root)])]
        untracked = untracked_files(root)
        if untracked is None:
            return Result("secrets", "INCONCLUSIVE", "git could not list untracked files — they were NOT scanned")
        scans += [(f"untracked {rel(root, p)}", ["dir", str(p)]) for p in untracked]
    found, labels = [], []
    for label, args in scans:
        r = subprocess.run([gl, *args, "--redact", "--no-banner", "--exit-code", "3", "-l", "warn"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode == 3:
            found.append(f"{label}: " + (r.stdout + r.stderr).strip()[-400:])
        elif r.returncode != 0:
            return Result("secrets", "INCONCLUSIVE", f"gitleaks failed on the {label} scan (rc={r.returncode})",
                          [(r.stderr or r.stdout).strip()[-300:]])
        labels.append(label)
    shown = [lb for lb in labels if not lb.startswith("untracked ")]
    if not pre_commit:
        shown.append(f"{len(labels) - len(shown)} untracked file(s)")
    return Result("secrets", "FAIL" if found else "PASS", f"gitleaks {Path(gl).name}: scanned {', '.join(shown)}", found)


# Files every session obeys (CLAUDE.md imports AGENTS.md): another tool's managed block in them would silently become
# binding instructions. AIWorkHub writes exactly such a block, and its server creates .aiworkhub/ in any git repo it
# starts in (measured while the engine was built, 2026-10).
INSTRUCTION_FILES = ("CLAUDE.md", "AGENTS.md", "REVIEW.md", ".github/copilot-instructions.md")
FOREIGN_BLOCK_RE = re.compile(r"AIWORKHUB_TOOL_USE_POLICY_(?:START|END)")
FOREIGN_DIRS = (".aiworkhub",)
MCP_CONFIGS = (".mcp.json", ".vscode/mcp.json")


def gate_instructions(root: Path, files: list[Path], **_) -> Result:
    todo = [p for p in pick(files, TEXT_SUFFIXES, TEXT_NAMES) if owned(root, p)]
    bad = []
    for p in todo:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            bad.append(f"{rel(root, p)}: unreadable: {e}")
            continue
        for kind in redact.hidden_chars(text):
            bad.append(f"{rel(root, p)}: hidden characters ({kind}) — invisible to a person, read by a model")
        r = rel(root, p)
        if (r in INSTRUCTION_FILES or r.startswith(".claude/")) and FOREIGN_BLOCK_RE.search(text):
            bad.append(f"{r}: a block managed by another tool (AIWorkHub) — it would become binding instructions")
    for d in FOREIGN_DIRS:
        if (root / d).exists():
            bad.append(f"{d}/: created by another tool, not by this project — ask the owner before keeping it")
    for m in MCP_CONFIGS:
        p = root / m
        if p.is_file() and "aiworkhub" in p.read_text(encoding="utf-8", errors="replace").lower():
            bad.append(f"{m}: registers the AIWorkHub MCP server (writes and launches switched on) — not added by the owner")
    return Result("instructions", "FAIL" if bad else "PASS",
                  f"{len(todo)} text file(s) checked for hidden characters; instruction files and project root checked "
                  "for foreign tool footprints", bad)


# tasks/*.md — the agent's concrete task list. A box means something only when a ticked item carries a date and
# evidence, and a commit it cites really exists (atlas-orchestrator's "closure receipt"). The line, its receipt and the
# commit check come from tools/graph_layers.py, which the graph's bridges read the same way.
def gate_tasks(root: Path, files: list[Path], repo: Path | None = None, **_) -> Result:
    todo = sorted(p for p in (root / "tasks").glob("*.md") if p.name.lower() != "readme.md") if (root / "tasks").is_dir() else []
    if not todo:
        return Result("tasks", "INCONCLUSIVE", "no tasks/*.md file — the concrete task list is missing")
    bad: list[str] = []
    seen: dict[str, str] = {}
    items = 0
    for p in todo:
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            m = TASK_LINE_RE.match(line)
            if not m:
                continue
            items += 1
            where, body = f"{rel(root, p)}:{n}", m.group(2).strip()
            mid = TASK_ID_RE.match(body)
            if not mid:
                bad.append(f"{where}: a task line needs an id — `- [ ] D-NNN — what …`")
                continue
            tid = mid.group(1)
            if tid in seen:
                bad.append(f"{where}: {tid} is already used at {seen[tid]} — ids are never reused")
            seen.setdefault(tid, where)
            if m.group(1) == " ":
                continue
            done = TASK_DONE_RE.search(body)
            if not done or not (done.group(2) or "").strip():
                bad.append(f"{where}: {tid} is ticked without a receipt — end the line with `✓ YYYY-MM-DD · <commit | მფლობელი | file>`")
                continue
            for sha in SHA_RE.findall(done.group(2)):
                ok = commit_exists(repo or root, sha)
                if ok is None:
                    return Result("tasks", "INCONCLUSIVE", f"git could not check commit {sha} cited by {tid} ({where})")
                if not ok:
                    bad.append(f"{where}: {tid} cites commit {sha}, which does not exist in this repository")
    return Result("tasks", "FAIL" if bad else "PASS", f"{items} task line(s), {len(seen)} id(s) in "
                  f"{', '.join(rel(root, p) for p in todo)}; ticked ones need a dated receipt  [input: tasks/*.md]", bad)


def gate_budget(root: Path, files: list[Path], gate: dict | None = None, **_) -> Result:
    """What every session loads stays under max_bytes, and max_bytes is no higher than the owner last approved."""
    cap = (gate or {}).get("max_bytes")
    if not isinstance(cap, int):
        return Result("budget", "INCONCLUSIVE", "the budget gate has no integer max_bytes in gates.toml — nothing to hold")
    loaded = budget.always_loaded(root)
    if "CLAUDE.md" not in loaded:
        return Result("budget", "INCONCLUSIVE", "no CLAUDE.md — nothing a session loads was measured")
    total, owner = sum(loaded.values()), budget.owner_budget(root)
    largest = ", ".join(f"{f} {n:,}" for f, n in sorted(loaded.items(), key=lambda kv: -kv[1])[:3])
    bad = [f"over by {total - cap:,} bytes — shorten an always-loaded file (largest: {largest}); only the owner raises "
           "the budget: /approve budget <N>"] if total > cap else []
    if owner is not None and cap > owner:
        bad.append(f"max_bytes {cap:,} is above the owner's last approved budget {owner:,} ({budget.LEDGER}) — only "
                   "/approve budget raises it")
    return Result("budget", "FAIL" if bad else "PASS", f"{total:,} of {cap:,} bytes loaded in every session, "
                  f"{len(loaded)} file(s)  [input: CLAUDE.md and its imports, unscoped rules, skill and agent listings]", bad)


# the files the drill runs for at commit are the engine files the session-end line names (ADR-0015): one list
HARNESS_PREFIXES = engine_line.PREFIXES
DRILL_SCRIPT = HERE / "drill.py"
# The limit only stops a drill that hangs, and a stopped drill is INCONCLUSIVE — never a pass. A full drill took 263–811 s
# on a busy Windows machine and 115–188 s on CI (2026-10-23); 600 s stopped good commits there.
DRILL_TIMEOUT_S = 1800


def git_show(root: Path, spec: str) -> str | None:
    """A file as git holds it — `HEAD:<path>` in the last commit, `:<path>` staged —, or None when git has none."""
    try:
        r = subprocess.run(["git", "-C", str(root), "show", spec], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def floor_lowered(root: Path, floor: int, pre_commit: bool) -> str:
    """ADR-0015: the drill's floor below the last commit's needs the owner's `/approve floor` row for exactly it,
    written since that commit — in the ledger the commit records (staged) at commit, the working copy otherwise.
    "" when the floor stands; LEDGER and the reason when it went down on its own."""
    head = drill_floor.floor_in(git_show(root, f"HEAD:{drill_floor.GATES}"))
    if head is None or floor >= head:
        return ""
    ledger = root / drill_floor.LEDGER
    now = (git_show(root, f":{drill_floor.LEDGER}") if pre_commit
           else ledger.read_text(encoding="utf-8", errors="replace") if ledger.is_file() else None)
    if drill_floor.approved_since(now, git_show(root, f"HEAD:{drill_floor.LEDGER}"), floor):
        return ""
    where = "staged " if pre_commit else ""
    return (f"LEDGER: the drill's floor went down from {head:,} to {floor:,} and the {where}{drill_floor.LEDGER} holds no "
            f"new owner row for it — only the owner lowers the floor (/approve floor {floor}); bring the cases back instead")


def floor_verdict(last: str, floor: int) -> str:
    """"" when the drill holds exactly its floor of cases (ARMED plus ELSEWHERE); otherwise what is wrong (ADR-0015)."""
    cases = drill_floor.cases_in(last)
    if cases is None:
        return "the drill's last line names no case count (ARMED=…) — its floor could not be checked"
    if cases < floor:
        return (f"FLOOR: the drill holds {cases:,} cases, its floor is {floor:,} — {floor - cases:,} case(s) were removed "
                "or stopped running; bring them back (only the owner lowers the floor: /approve floor <N>)")
    if cases > floor:
        return (f"FLOOR: the drill grew to {cases:,} cases, its floor is still {floor:,} — the floor rises with the drill: "
                f"floor = {cases} on the drill gate in {drill_floor.GATES}, in this commit")
    return ""


def drill_switched_off(root: Path, gates: list[dict], pre_commit: bool) -> Result | None:
    """ADR-0015: a drill gate switched off, removed, or kept from the commit (pre_commit = false) arms no case — its floor
    is 0, which needs the owner's row like any other lowering. When the last commit's drill gate already did not
    run at commit (the owner switched it off with their row), the floor written on it is what is held — written
    against written, as in the guard's G7 —, so a later commit no longer needs that row again, while lowering
    the written floor or taking the gate out still does. None when the drill runs, or that row is there."""
    drill = next((g for g in gates if drill_floor.is_drill(g)), None)
    if drill is not None and drill.get("enabled") and (drill.get("pre_commit") or not pre_commit):
        return None
    head = drill_floor.drill_gate(git_show(root, f"HEAD:{drill_floor.GATES}"))
    standing = None if head is None or drill_floor.runs_at_commit(head) else drill_floor.floor_of(drill)
    lowered = floor_lowered(root, 0 if standing is None else standing, pre_commit)
    if not lowered:
        return None
    how = ("is gone from gates.toml" if drill is None else "is switched off" if not drill.get("enabled")
           else "no longer runs at commit (pre_commit = false)")
    if standing is not None:
        return Result("drill", "FAIL", f"the drill gate {how} and the floor written on it went down — once the owner "
                      "has switched the drill off, that floor is what is held: put it back", [lowered])
    return Result("drill", "FAIL", f"the drill gate {how} — a drill that does not run arms no case, its floor would be 0: "
                  "switch it back on", [lowered])


def drill_not_staged(root: Path) -> str:
    """At commit, drill.py on disk that is not what the commit records — cases not staged yet, perhaps another
    session's (L-007): the drill would count cases the commit does not hold, so it is not run. "" when they are one
    text, or when drill.py lies outside the project (a drill case's stand-in)."""
    script = rel(root, DRILL_SCRIPT)
    if Path(script).is_absolute():
        return ""
    r = subprocess.run(["git", "-C", str(root), "diff", "--quiet", "--", script], capture_output=True, timeout=60)
    if r.returncode == 0:
        return ""
    if r.returncode != 1:
        return (f"DRILL-UNSTAGED: git could not tell whether {script} on disk is what this commit records — nothing "
                "was run")
    return (f"DRILL-UNSTAGED: {script} on disk is not what this commit records — the drill would count cases the "
            f"commit does not hold: stage it (git add {script}) and commit again, or, if another session is changing "
            "it, wait until that session commits (L-007)")


def gate_drill(root: Path, files: list[Path], pre_commit: bool = False, gate: dict | None = None, **_) -> Result:
    if pre_commit:
        staged = subprocess.run(["git", "-C", str(root), "diff", "--cached", "--name-only"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace").stdout.split()
        if not any(s.startswith(HARNESS_PREFIXES) for s in staged):
            return Result("drill", "SKIP", "no engine file is staged — the drill runs when one changes (and on every "
                                           "full `gate.py` run)")
        unstaged = drill_not_staged(root)
        if unstaged:
            return Result("drill", "INCONCLUSIVE", unstaged)
    floor = drill_floor.floor_of(gate)
    if floor is None:
        return Result("drill", "INCONCLUSIVE", "the drill gate has no integer `floor` in gates.toml — the drill's floor is "
                      "not held, so the drill was not run (ADR-0015)")
    lowered = floor_lowered(root, floor, pre_commit)
    if lowered:
        return Result("drill", "FAIL", f"floor {floor:,} is below the last commit's — the drill was not run", [lowered])
    try:
        r = subprocess.run([sys.executable, str(DRILL_SCRIPT)], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=str(root), timeout=DRILL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return Result("drill", "INCONCLUSIVE", f"the drill ran longer than {DRILL_TIMEOUT_S:,} s and was stopped — nothing "
                      "was proved; run it on its own: bash .claude/hooks/py.sh tools/gates/drill.py")
    tail = [ln for ln in r.stdout.splitlines() if ln.startswith(("  DEAD", "  DEFECT", "  INCONCL"))]
    last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
    status = {0: "PASS", 1: "FAIL"}.get(r.returncode, "INCONCLUSIVE")
    off = floor_verdict(last, floor) if status == "PASS" else ""
    if off:
        status = "FAIL" if off.startswith("FLOOR") else "INCONCLUSIVE"
        tail = [off] + tail
    elif status == "PASS":
        last += f"  · floor {floor:,} held"
        if pre_commit and not engine_line.write_receipt(root):  # the session-end line reads it (ADR-0015)
            last += "  · no receipt written: the session-end line will call this commit unchecked"
    return Result("drill", status, last, tail + ([r.stderr.strip()[-300:]] if r.returncode not in (0, 1) else []),
                  notice="LEFT OUT" in last)


# memory — the top layer every session trusts before it reads anything else (ADR-0017 §2): the lessons index (CLAUDE.md
# loads it) and the three auto blocks the start brief shows. A claim there that a machine can check is checked — a
# commit, a file path, a D-, P- or L- number, a drill group — and a block the brief would cut fails instead of being cut
# in silence. The log below the blocks is history: it is not read.
MEMORY_BLOCKS = (("progress.md", "current-state"), ("plan.md", "current-phase"), ("tasks/todo.md", "todo-now"))
LESSONS_INDEX = "memory/LESSONS.md"
REGISTERS = {"D": "tasks/*.md", "P": "memory/PROPOSALS.md", "L": LESSONS_INDEX}
GEORGIAN = f"{chr(0x10D0)}-{chr(0x10FF)}"
# A commit as the tasks gate reads one, and one a Georgian ending follows (`15d0999-ზე`). A commit of another repository
# carries that repository's name in front (`kit:f4d7b77`): it is not this repository's to check.
MEMORY_SHA_RE = re.compile(rf"(?<![\w./:#-])(?=[0-9a-f]*[0-9])[0-9a-f]{{7,40}}(?![\w/:#]|-(?![{GEORGIAN}])|\.\w)")
MEMORY_ID_RE = re.compile(r"(?<![\w-])([DPL]-\d{3,})(?!\d)")
PROPOSAL_LINE_RE = re.compile(r"(?m)^\s*[-*] \[[ xX]\] \*\*(P-\d{3,})\*\*")
LESSON_LINE_RE = re.compile(r"(?m)^[-*] \*\*(L-\d{3,})\b")
MEMORY_TICK_RE = re.compile(r"`([^`\n]+)`")
GUARDED_RE = re.compile(r"drill \(([^)\n]*)\)")
GROUP_NAME_RE = re.compile(r"`([a-z_]+)`")
EPISODIC = HERE.parents[1] / ".claude" / "hooks" / "episodic.py"


def brief_limits() -> tuple[dict, int, object] | str:
    """The start brief's own limits and block reader — BLOCK_CAPS, WORKING_LINES, extract_block — from episodic.py, so
    the gate and the brief can never disagree on them; what went wrong when they cannot be read."""
    try:
        spec = importlib.util.spec_from_file_location("episodic_brief", EPISODIC)
        if spec is None or spec.loader is None:
            return f"no module at {EPISODIC}"
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # its dataclasses look themselves up there
        spec.loader.exec_module(mod)
        return dict(mod.BLOCK_CAPS), int(mod.WORKING_LINES), mod.extract_block
    except Exception as e:  # noqa: BLE001 — any failure leaves the blocks unmeasured, and the gate says so
        return f"{type(e).__name__}: {e}"


def drill_groups(root: Path) -> tuple[set[str] | None, str]:
    """The drill's groups (`GROUPS` in drill.py) — the checked tree's drill.py, else the engine's own — and which one."""
    own = root / "tools/gates/drill.py"
    path, label = (own, "tools/gates/drill.py") if own.is_file() else (DRILL_SCRIPT, "the engine's drill.py")
    try:
        for node in ast.parse(path.read_text(encoding="utf-8", errors="replace")).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "GROUPS" for t in node.targets):
                value = ast.literal_eval(node.value)
                if isinstance(value, list) and all(isinstance(v, str) for v in value):
                    return set(value), label
    except (OSError, SyntaxError, ValueError):
        pass
    return None, label


def memory_registers(root: Path) -> dict[str, set[str]]:
    """Where a number lives: D — a task line in tasks/*.md, P — a proposal line, L — a lesson's index line."""
    def text(rel_path: str) -> str:
        p = root / rel_path
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
    tasks = sorted(p for p in (root / "tasks").glob("*.md") if p.name.lower() != "readme.md") if (root / "tasks").is_dir() else []
    d = set()
    for p in tasks:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            m = TASK_LINE_RE.match(line)
            mid = TASK_ID_RE.match(m.group(2).strip()) if m else None
            if mid:
                d.add(mid.group(1))
    return {"D": d, "P": set(PROPOSAL_LINE_RE.findall(text("memory/PROPOSALS.md"))),
            "L": set(LESSON_LINE_RE.findall(text(LESSONS_INDEX)))}


def memory_sources(root: Path, extract) -> tuple[list[tuple[str, str, str | None]], list[str]]:
    """(where, text, the file whose brief cap holds it — None for the lessons index), and a file whose block is gone."""
    out, bad = [], []
    lessons = root / LESSONS_INDEX
    if lessons.is_file():
        out.append((LESSONS_INDEX, lessons.read_text(encoding="utf-8", errors="replace"), None))
    for name, block in MEMORY_BLOCKS:
        p = root / name
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if f"<!-- auto: {block}:start -->" not in text or f"<!-- auto: {block}:end -->" not in text:
            bad.append(f"{name}: no `{block}` block (`<!-- auto: {block}:start -->` … `:end -->`) — the start brief shows "
                       "it empty and its claims go unchecked: put the markers back")
            continue
        out.append((f"{name} ({block})", extract(text, block), name))
    return out, bad


def gate_memory(root: Path, files: list[Path], repo: Path | None = None, **_) -> Result:
    limits = brief_limits()
    if isinstance(limits, str):
        return Result("memory", "INCONCLUSIVE", f"the start brief's limits could not be read from "
                      f"{rel(HERE.parents[1], EPISODIC)} ({limits}) — nothing was checked")
    caps, working_lines, extract = limits
    sources, bad = memory_sources(root, extract)
    if not sources and not bad:
        return Result("memory", "INCONCLUSIVE", f"none of {LESSONS_INDEX}, {', '.join(n for n, _ in MEMORY_BLOCKS)} — the "
                      "top layer every session trusts was not found, nothing was checked")
    registers, (groups, groups_from) = memory_registers(root), drill_groups(root)
    git_repo, at_commit = repo or root, repo is not None and repo != root
    top = {p.name for p in root.iterdir()}
    unknown: list[str] = []
    counts = {"commit": 0, "number": 0, "path": 0, "group": 0}
    is_repo: bool | None = None
    for where, text, capped in sources:
        for sha in sorted(set(MEMORY_SHA_RE.findall(text))):
            counts["commit"] += 1
            ok = commit_exists(git_repo, sha)
            if ok:
                continue
            if is_repo is None:
                is_repo = git_answers(git_repo, "rev-parse", "--git-dir")[0] == 0
            if ok is None or not is_repo:
                unknown.append(f"{where}: commit {sha} could not be checked — git has no repository at {git_repo}")
            elif git_answers(git_repo, "rev-parse", "--is-shallow-repository")[1] == "true":
                unknown.append(f"{where}: commit {sha} is not in this shallow clone — it may be older than the history "
                               "the clone holds")
            else:
                bad.append(f"{where}: commit {sha} does not exist in this repository — correct the claim; another "
                           "repository's commit is written with its name in front (`kit:<sha>`)")
        for num in sorted(set(MEMORY_ID_RE.findall(text))):
            counts["number"] += 1
            if num not in registers[num[0]]:
                bad.append(f"{where}: {num} is in no register — {REGISTERS[num[0]]} holds no line for it (a done task "
                           "older than 14 days is deleted): drop the number or name what replaced it")
        for token in sorted({t.strip() for t in MEMORY_TICK_RE.findall(text)}):
            if not path_claim(token, top):
                continue
            counts["path"] += 1
            # at commit, git's own folder and a file git ignores never reach the commit: for them the disk is all there is
            found = path_status(root, git_repo, token, at_commit)
            if found:
                continue
            if found is None:
                unknown.append(f"{where}: git could not tell whether `{token}` is a file it ignores")
                continue
            bad.append(f"{where}: `{token}` does not exist{' in this commit' if at_commit else ''} — correct the path "
                       "or drop the claim")
        for inner in GUARDED_RE.findall(text):
            for name in GROUP_NAME_RE.findall(inner):
                counts["group"] += 1
                if groups is None:
                    unknown.append(f"{where}: drill group `{name}` could not be checked — no GROUPS list in {groups_from}")
                elif name not in groups:
                    bad.append(f"{where}: drill group `{name}` does not exist ({groups_from}: {', '.join(sorted(groups))}) "
                               "— name the group that runs the case, or say `none`")
        if capped is not None:
            n_lines = len(text.splitlines())
            if n_lines > working_lines:
                bad.append(f"{where}: {n_lines} lines — the start brief shows {working_lines}, the rest would be cut")
            if capped in caps and len(text) > caps[capped]:
                bad.append(f"{where}: {len(text):,} characters, its cap is {caps[capped]:,} — the next session's brief "
                           "would cut it: keep the block short, the story goes to the log below it")
    status = "FAIL" if bad else "INCONCLUSIVE" if unknown else "PASS"
    names = ", ".join(w for w, _, _ in sources) or "(none)"
    summary = (f"{sum(counts.values())} claim(s) checked — {counts['commit']} commit(s), {counts['number']} number(s), "
               f"{counts['path']} path(s), {counts['group']} drill group(s); blocks within the brief's caps"
               f"{'' if not bad else ' unless named below'}  [input: {names}; drill groups: {groups_from}]")
    return Result("memory", status, summary, bad + unknown)


BUILTINS = {"graph": gate_graph, "json": gate_json, "toml": gate_toml, "python": gate_python,
            "shell": gate_shell, "eol": gate_eol, "secrets": gate_secrets, "instructions": gate_instructions,
            "tasks": gate_tasks, "drill": gate_drill, "budget": gate_budget, "memory": gate_memory}


def venv_python(root: Path) -> Path:
    """The project's own virtual environment's Python: .venv/Scripts/python.exe on Windows, .venv/bin/python on
    macOS and Linux — a guide writes `{venv_python}` once for every system (docs/guides/agent.md)."""
    return root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run_cmd_gate(root: Path, g: dict) -> Result:
    """A `cmd` gate: an argument list run without a shell, so nothing in it is ever re-parsed. `{venv_python}` is the
    project's virtual environment's Python, `{python}` the engine's own — the one running this file."""
    argv = g["cmd"] if isinstance(g["cmd"], list) else shlex.split(g["cmd"])
    if any("{venv_python}" in a for a in argv) and not venv_python(root).is_file():
        return Result(g["id"], "INCONCLUSIVE", f"`{{venv_python}}` is {venv_python(root).relative_to(root).as_posix()}, "
                      "which does not exist — create the environment first: `bash .claude/hooks/py.sh -m venv .venv`")
    argv = [a.replace("{venv_python}", str(venv_python(root))).replace("{python}", sys.executable) for a in argv]
    exe = shutil.which(argv[0]) if argv else None
    shown = " ".join(argv)
    if not exe:
        return Result(g["id"], "INCONCLUSIVE", f"`{argv[0] if argv else '(empty cmd)'}` not found — `{shown}` did not run")
    r = subprocess.run([exe, *argv[1:]], cwd=str(root), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=1800)
    status = "PASS" if r.returncode == 0 else "FAIL"
    return Result(g["id"], status, f"`{shown}` exit {r.returncode}", (r.stdout + r.stderr).strip().splitlines()[-15:])


def gates_file() -> Path:
    return Path(os.environ.get("GATES_TOML") or HERE / "gates.toml")


def load_gates() -> list[dict]:
    return tomllib.loads(gates_file().read_text(encoding="utf-8"))["gate"]


def committed_drill(root: Path, gates: list[dict]) -> list[dict]:
    """At commit, the drill gate — its floor, on or off, run at commit — as the commit records it, from the
    staged gates.toml: a raised floor left unstaged no longer passes a grown drill that is staged. drill.py on disk that
    is not what the commit records no longer brings the disk's gate along: it stops the drill
    (drill_not_staged). A gate list outside the project (a drill case) or not under git yet is used as it is."""
    name = rel(root, gates_file())
    if Path(name).is_absolute():
        return gates
    staged = git_show(root, f":{name}")
    if staged is None and git_show(root, f"HEAD:{name}") is None:
        return gates
    try:
        table = tomllib.loads(staged or "").get("gate", [])
    except tomllib.TOMLDecodeError:
        table = []  # the toml gate names the error; a drill gate the commit cannot read arms no case
    drills = [g for g in table if drill_floor.is_drill(g)] if isinstance(table, list) else []
    at = next((i for i, g in enumerate(gates) if drill_floor.is_drill(g)), len(gates))
    rest = [g for g in gates if not drill_floor.is_drill(g)]
    return rest[:at] + drills + rest[at:]


# At commit these read the next commit's tree (export_index); the secrets gate reads the staged files itself, and the
# drill and the `cmd` gates run the working copy's code (changed_after_add).
STAGED_READERS = {"graph", "json", "toml", "python", "shell", "eol", "instructions", "tasks", "budget", "memory"}
STAGED_INPUT = "staged files (git index)"


def reads_text(name: str) -> bool:
    p = Path(name)
    suffix = p.suffix.lower()
    return suffix in TEXT_SUFFIXES or suffix in CODE_TEXT_SUFFIXES or p.name in TEXT_NAMES or p.parent.name == ".githooks"


def export_index(root: Path) -> tuple[Path | None, list[Path], str]:
    """The next commit's tree in a temporary folder, so a gate run at commit judges what the commit records: a broken
    file staged and then fixed on disk used to pass (review 2026-10-22 H4). A text file a gate reads holds its staged
    bytes, with no line-ending conversion; any other file is created empty — a gate only checks that it exists (a link
    to an image). (folder, its files, what went wrong — "" when nothing)."""
    r = subprocess.run(["git", "-C", str(root), "ls-files", "-s", "-z"], capture_output=True, timeout=60)
    if r.returncode != 0:
        return None, [], "git could not list the staged files"
    entries = []
    for rec in filter(None, r.stdout.decode("utf-8", "replace").split("\0")):
        meta, _, name = rec.partition("\t")  # "<mode> <sha> <stage>", then the path
        parts = meta.split()
        if len(parts) != 3 or not name or ".." in name.split("/"):
            return None, [], f"git listed an index entry it could not use ({rec[:60]!r})"
        if parts[2] != "0":
            return None, [], f"{name} is not merged yet — finish the merge first"
        if parts[0] != "160000":  # a submodule pointer: another repository's commit, no file here
            entries.append((name, parts[1]))
    texts = [(n, sha) for n, sha in entries if reads_text(n)]
    r = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], input="".join(f"{sha}\n" for _, sha in texts).encode(),
                       capture_output=True, timeout=300)
    blobs, data, pos = {}, r.stdout, 0
    for name, _ in texts if r.returncode == 0 else []:  # each: "<sha> blob <size>\n<content>\n"
        nl = data.find(b"\n", pos)
        head = data[pos:nl].split() if nl >= 0 else []
        if len(head) != 3 or head[1] != b"blob":
            break
        blobs[name], pos = data[nl + 1:nl + 1 + int(head[2])], nl + 2 + int(head[2])
    if len(blobs) != len(texts):
        return None, [], "git could not read the staged files"
    # one spelling: macOS's temporary folder is /var/… behind /private/var/…, a Windows runner's the short RUNNER~1, and
    # every gate compares a resolved file with this root (L-025)
    dest = Path(tempfile.mkdtemp(prefix="gate-staged-")).resolve()
    for name, _ in entries:
        (dest / name).parent.mkdir(parents=True, exist_ok=True)
        (dest / name).write_bytes(blobs.get(name, b""))
    return dest, [dest / n for n, _ in entries], ""


def changed_after_add(root: Path) -> list[str] | None:
    """Staged paths whose working copy is not what the commit records — changed again after `git add`, or taken out
    of the commit while still on disk. None when git cannot tell."""
    lists = []
    for extra in ([], ["--cached"], ["--cached", "--diff-filter=D"]):
        r = subprocess.run(["git", "-C", str(root), "diff", *extra, "--name-only", "--no-renames", "-z"],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            return None
        lists.append(set(filter(None, r.stdout.decode("utf-8", "replace").split("\0"))))
    later, staged, removed = lists
    return sorted(n for n in staged if n in later or (n in removed and (root / n).exists()))


def ran_on_other_text(g: dict, later: list[str] | None) -> Result | None:
    """The drill and a `cmd` gate run the working copy's code: when a staged file differs from it, their verdict is
    not about the commit."""
    if later is None:
        return Result(g["id"], "INCONCLUSIVE", "git could not tell whether a staged file changed after `git add` — "
                      "nothing was run")
    hit = [n for n in later if not drill_floor.is_drill(g) or n.startswith(HARNESS_PREFIXES)]
    if not hit:
        return None
    return Result(g["id"], "INCONCLUSIVE", f"{len(hit)} staged file(s) changed after `git add` ({', '.join(hit[:3])}) — "
                  "this would run the working copy, not what the commit records: `git add` them again, then commit",
                  hit[:10])


def run(root: Path, gates: list[dict], files: list[Path] | None, pre_commit: bool) -> list[Result]:
    results = []
    all_files, source = (files, "given files") if files is not None else project_files(root)
    on = [g for g in gates if g.get("enabled")]
    at_commit = pre_commit and files is None
    staged, staged_files, why = (export_index(root) if at_commit and any(g.get("builtin") in STAGED_READERS for g in on)
                                 else (None, [], ""))
    later = changed_after_add(root) if at_commit and any(g.get("builtin") in ("drill", None) for g in on) else []
    try:
        for g in gates:
            if not g.get("enabled"):
                results.append(Result(g["id"], "SKIP", f"level {g['level']} — {g.get('reason', 'switched off')}"))
                continue
            builtin, label = g.get("builtin"), source
            try:
                if at_commit and builtin in STAGED_READERS:
                    label = STAGED_INPUT
                    res = (BUILTINS[builtin](staged, staged_files, pre_commit=True, gate=g, repo=root) if staged
                           else Result(g["id"], "INCONCLUSIVE", f"{why} — nothing the commit records was checked"))
                elif at_commit and builtin in ("drill", None) and (other := ran_on_other_text(g, later)):
                    res = other
                elif builtin:
                    fn = BUILTINS[builtin]
                    res = fn(root, files if builtin == "graph" else all_files, pre_commit=pre_commit, gate=g)
                else:
                    res = run_cmd_gate(root, g)
            except Exception as e:
                res = Result(g["id"], "INCONCLUSIVE", f"gate crashed: {type(e).__name__}: {e}")
            named = label == STAGED_INPUT or builtin not in ("graph", "drill", "tasks", "budget", "memory", None)
            res.summary += f"  [input: {label}]" if named else ""
            results.append(res)
    finally:
        if staged:
            shutil.rmtree(staged, ignore_errors=True)
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="deterministic gates")
    ap.add_argument("--pre-commit", action="store_true")
    ap.add_argument("--files", nargs="+")
    ap.add_argument("--only", help="comma-separated gate ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="print only failures and the summary")
    a = ap.parse_args(argv)
    root = root_dir()
    gates = every = load_gates()
    if a.list:
        for g in gates:
            state = "on " if g.get("enabled") else "off"
            print(f"L{g['level']} {state} {g['id']:16} {g['what']}" + ("" if g.get("enabled") else f"  — {g.get('reason')}"))
        return 0
    if a.pre_commit and not a.files:  # the drill gate the commit records
        gates = every = committed_drill(root, every)
    drills = [g for g in every if drill_floor.is_drill(g)]
    known = sorted({str(g.get("id")) for g in every})  # read here: a doubled drill gate is taken out of the list below
    several = None
    if len(drills) > 1:  # one gate holds the drill's floor: a second one hid the last commit's
        ids = ", ".join(str(g.get("id")) for g in drills)
        several = Result("drill", "FAIL", f"DRILLS: {gates_file().name} has {len(drills)} drill gates ({ids}) — one "
                         "gate holds the drill's floor and a second one hides it: keep one")
        gates = every = [g for g in every if not drill_floor.is_drill(g)]
    # names are read as drill.py reads its own --only: split on commas, spaces around a name dropped
    want = {name.strip() for name in a.only.split(",") if name.strip()} if a.only else set()
    unknown = sorted(want.difference(known))
    if a.only:  # the id is read the way `known` reads it, so a name is never both "unknown" and run
        gates = [g for g in gates if str(g.get("id")) in want]
    elif a.files:
        gates = [g for g in gates if g.get("stop") or not g.get("enabled")]
    elif a.pre_commit:
        gates = [g for g in gates if g.get("pre_commit")]
    files = [Path(f) if Path(f).is_absolute() else (Path.cwd() / f) for f in a.files] if a.files else None
    if files is not None:
        files = [f.resolve() for f in files if f.exists()]
    results = run(root, gates, files, a.pre_commit)
    # A name no gate has checked nothing. It used to drop out without a word while the gates named next to it passed
    # (`--only json,jsno` → GATES PASS, exit 0): now it is its own INCONCLUSIVE line.
    results += [Result(name, "INCONCLUSIVE", f"ONLY-UNKNOWN: --only names a gate {gates_file().name} does not have — "
                       f"nothing was checked under this name (gates: {', '.join(known)})") for name in unknown]
    if several:
        results.append(several)
    elif not a.files and (not want or "drill" in want):  # a run that holds the drill (ADR-0015)
        off = drill_switched_off(root, every, a.pre_commit)
        results = [r for r in results if r.gate != "drill"] + [off] if off else results
    for r in results:
        if a.quiet and r.status in ("PASS", "SKIP") and not r.notice:
            continue
        print(f"{r.status:12} {r.gate:16} {r.summary}")
        for d in r.details[:25]:
            print(f"{'':14}{d}")
    counts = {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "INCONCLUSIVE", "SKIP")}
    verdict = "FAIL" if counts["FAIL"] else ("INCONCLUSIVE" if counts["INCONCLUSIVE"] or not counts["PASS"] else "PASS")
    print(f"GATES {verdict}: pass={counts['PASS']} fail={counts['FAIL']} inconclusive={counts['INCONCLUSIVE']} "
          f"skip={counts['SKIP']} (skip = not checked, not passed)")
    return {"PASS": 0, "FAIL": 1}.get(verdict, 2)


if __name__ == "__main__":
    sys.exit(main())
