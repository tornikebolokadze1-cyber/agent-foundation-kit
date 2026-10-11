#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic gate runner. The gates themselves are listed in tools/gates/gates.toml.

  py -3.12 tools/gates/gate.py                  every enabled gate, whole project
  py -3.12 tools/gates/gate.py --pre-commit     gates marked pre_commit (secrets: staged files only)
  py -3.12 tools/gates/gate.py --files F [F…]   gates marked stop, restricted to these files
  py -3.12 tools/gates/gate.py --only graph,json
  py -3.12 tools/gates/gate.py --list

Exit 0 = every enabled gate passed · 1 = at least one FAILED · 2 = INCONCLUSIVE (a gate
could not run, or checked zero files). SKIP (switched off) is reported and is not a pass.
Every result line names the input it actually used, so a gate that quietly checked
nothing cannot look green (ADR-0006: no evidence is not a pass).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
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
import context_graph as cg  # noqa: E402
import redact  # noqa: E402

TEXT_SUFFIXES = {".py", ".sh", ".md", ".json", ".toml", ".txt", ".yml", ".yaml", ".js", ".ts", ".css", ".html", ".csv"}
TEXT_NAMES = {".gitignore", ".gitattributes", ".editorconfig", ".env.example", "pre-commit"}


@dataclass
class Result:
    gate: str
    status: str                 # PASS | FAIL | INCONCLUSIVE | SKIP
    summary: str
    details: list[str] = field(default_factory=list)


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
def gate_graph(root: Path, files: list[Path] | None, **_) -> Result:
    if not (root / "intent.md").exists() and not (root / "docs").is_dir():
        return Result("graph", "INCONCLUSIVE", f"{root} does not look like the project root")
    g = cg.load(root)
    scanned = sum(1 for n in g.nodes.values() if n.path.endswith(".md") and not n.foreign)
    if scanned == 0:
        return Result("graph", "INCONCLUSIVE", "0 knowledge files scanned")
    issues = cg.check(g)
    if files is not None:
        issues = cg.filter_issues(issues, [str(f) for f in files], root)
    errors = [i for i in issues if i.level == "error"]
    warns = [i for i in issues if i.level == "warning"]
    scope = f"{len(files)} file(s)" if files is not None else "whole vault"
    s = f"{scanned} notes, {len(g.edges())} links; scope={scope}; errors={len(errors)}, warnings={len(warns)}"
    return Result("graph", "FAIL" if errors else "PASS", s, [i.fmt() for i in errors + warns][:40])


def gate_json(root: Path, files: list[Path], **_) -> Result:
    todo = [p for p in pick(files, {".json"}) if owned(root, p)]
    bad = []
    for p in todo:
        try:
            json.loads(p.read_text(encoding="utf-8"))
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


def find_bash() -> str | None:
    for cand in (os.environ.get("GATE_BASH"), shutil.which("bash"), r"C:\Program Files\Git\bin\bash.exe"):
        if cand and Path(cand).exists():
            return cand
    return None


def gate_shell(root: Path, files: list[Path], **_) -> Result:
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
    return Result("shell", "FAIL" if bad else "PASS", f"{len(todo)} script(s) checked with {Path(bash).name} -n", bad)


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
    return Result("secrets", "PASS", summary, shown)


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
# evidence, and a commit it cites really exists (atlas-orchestrator's "closure receipt").
TASK_LINE_RE = re.compile(r"^\s*[-*] \[([ xX])\] (.*)$")
TASK_ID_RE = re.compile(r"^(D-\d{3,}) — \S")
TASK_DONE_RE = re.compile(r"✓ (\d{4}-\d{2}-\d{2})(?: · (.+))?$")
SHA_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{7,40}(?![0-9a-fA-F])")


def commit_exists(root: Path, sha: str) -> bool | None:
    try:
        r = subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.returncode == 0


def gate_tasks(root: Path, files: list[Path], **_) -> Result:
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
                ok = commit_exists(root, sha)
                if ok is None:
                    return Result("tasks", "INCONCLUSIVE", f"git could not check commit {sha} cited by {tid} ({where})")
                if not ok:
                    bad.append(f"{where}: {tid} cites commit {sha}, which does not exist in this repository")
    return Result("tasks", "FAIL" if bad else "PASS", f"{items} task line(s), {len(seen)} id(s) in "
                  f"{', '.join(rel(root, p) for p in todo)}; ticked ones need a dated receipt  [input: tasks/*.md]", bad)


HARNESS_PREFIXES = (".claude/hooks/", ".claude/settings", ".githooks/", "tools/", "orchestration/run.py",
                    "orchestration/config.toml", "orchestration/prompts/")


def gate_drill(root: Path, files: list[Path], pre_commit: bool = False, **_) -> Result:
    if pre_commit:
        staged = subprocess.run(["git", "-C", str(root), "diff", "--cached", "--name-only"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace").stdout.split()
        if not any(s.startswith(HARNESS_PREFIXES) for s in staged):
            return Result("drill", "SKIP", "no check, hook or gate file is staged — the drill runs when a checker changes "
                                           "(and on every full `gate.py` run)")
    drill = HERE / "drill.py"
    r = subprocess.run([sys.executable, str(drill)], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=str(root), timeout=600)
    tail = [ln for ln in r.stdout.splitlines() if ln.startswith(("  DEAD", "  DEFECT", "  INCONCL"))]
    last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
    status = {0: "PASS", 1: "FAIL"}.get(r.returncode, "INCONCLUSIVE")
    return Result("drill", status, last, tail + ([r.stderr.strip()[-300:]] if r.returncode not in (0, 1) else []))


BUILTINS = {"graph": gate_graph, "json": gate_json, "toml": gate_toml, "python": gate_python,
            "shell": gate_shell, "eol": gate_eol, "secrets": gate_secrets, "instructions": gate_instructions,
            "tasks": gate_tasks, "drill": gate_drill}


def run_cmd_gate(root: Path, g: dict) -> Result:
    """A `cmd` gate: an argument list run without a shell, so nothing in it is ever re-parsed."""
    argv = g["cmd"] if isinstance(g["cmd"], list) else shlex.split(g["cmd"])
    exe = shutil.which(argv[0]) if argv else None
    shown = " ".join(argv)
    if not exe:
        return Result(g["id"], "INCONCLUSIVE", f"`{argv[0] if argv else '(empty cmd)'}` not found — `{shown}` did not run")
    r = subprocess.run([exe, *argv[1:]], cwd=str(root), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=1800)
    status = "PASS" if r.returncode == 0 else "FAIL"
    return Result(g["id"], status, f"`{shown}` exit {r.returncode}", (r.stdout + r.stderr).strip().splitlines()[-15:])


def load_gates() -> list[dict]:
    path = Path(os.environ.get("GATES_TOML") or HERE / "gates.toml")
    return tomllib.loads(path.read_text(encoding="utf-8"))["gate"]


def run(root: Path, gates: list[dict], files: list[Path] | None, pre_commit: bool) -> list[Result]:
    results = []
    all_files, source = (files, "given files") if files is not None else project_files(root)
    for g in gates:
        if not g.get("enabled"):
            results.append(Result(g["id"], "SKIP", f"level {g['level']} — {g.get('reason', 'switched off')}"))
            continue
        try:
            if "builtin" in g:
                fn = BUILTINS[g["builtin"]]
                res = fn(root, files if g["builtin"] == "graph" else all_files, pre_commit=pre_commit)
            else:
                res = run_cmd_gate(root, g)
        except Exception as e:
            res = Result(g["id"], "INCONCLUSIVE", f"gate crashed: {type(e).__name__}: {e}")
        res.summary += f"  [input: {source}]" if g.get("builtin") not in ("graph", "drill", "tasks", None) else ""
        results.append(res)
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
    gates = load_gates()
    if a.list:
        for g in gates:
            state = "on " if g.get("enabled") else "off"
            print(f"L{g['level']} {state} {g['id']:16} {g['what']}" + ("" if g.get("enabled") else f"  — {g.get('reason')}"))
        return 0
    if a.only:
        want = set(a.only.split(","))
        gates = [g for g in gates if g["id"] in want]
    elif a.files:
        gates = [g for g in gates if g.get("stop") or not g.get("enabled")]
    elif a.pre_commit:
        gates = [g for g in gates if g.get("pre_commit")]
    files = [Path(f) if Path(f).is_absolute() else (Path.cwd() / f) for f in a.files] if a.files else None
    if files is not None:
        files = [f.resolve() for f in files if f.exists()]
    results = run(root, gates, files, a.pre_commit)
    for r in results:
        if a.quiet and r.status in ("PASS", "SKIP"):
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
