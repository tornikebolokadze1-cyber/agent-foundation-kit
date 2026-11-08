#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One Georgian line at the end of a session: which engine files changed, and whether their commit passed the drill
(ADR-0015). Information, not a lock — the person sees that the engine changed and can ask why.

  bash .claude/hooks/py.sh tools/engine_line.py [--root DIR] [--since REV]

Engine files are the ones the drill runs for at commit — PREFIXES, which gate.py takes as its HARNESS_PREFIXES, so the
two never disagree: hooks, the commit check, the permissions file, skills, agents, rules, the engine's tools and the
orchestration code. "Changed" means committed after --since — the commit the session started from (HEAD when not
given: only what is not committed yet; "-" when the session began before the first commit: every commit after the
first) — or not committed yet, whoever changed it. A project's first commit is where the engine arrives, not a change
to it, and before it there is nothing to compare with: no line.
A commit passed the drill when the drill gate, at that commit, left a receipt for the tree it records (write_receipt —
<git common dir>/engine-drill-receipts). A commit made without the commit check (pulled, rebased, `--no-verify`, a
commit check that no longer runs the drill) has none and reads "not checked by the drill". ⚠ marks the guard and the
commit check (.githooks/): a change there can weaken every other check.
Prints nothing when no engine file changed. Exit 0, or 2 when git could not answer (nothing is claimed then).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PREFIXES = (".claude/hooks/", ".claude/settings", ".claude/skills/", ".claude/agents/", ".claude/rules/", ".githooks/",
            "tools/", "orchestration/run.py", "orchestration/decide.py", "orchestration/config.toml",
            "orchestration/prompts/")
RECEIPTS = "engine-drill-receipts"
# (a file, or a folder ending in /, and the words a person reads) — the first that matches wins
WORDS = ((".claude/hooks/guard.py", "⚠ guard (უსაფრთხოების შემმოწმებელი)"), (".githooks/", "⚠ commit-ის შემოწმება"),
         (".claude/hooks/sentinel.py", "sentinel (გარე ტექსტისა და გასაღებების მცველი)"),
         (".claude/hooks/episodic.py", "სესიების მეხსიერება"), (".claude/hooks/stop_gate.py", "ტურის ბოლოს შემოწმება"),
         (".claude/hooks/statusline.py", "სტატუსის ხაზი"), (".claude/hooks/firstrun.py", "პირველი გაშვება"),
         (".claude/hooks/py.sh", "Python-ის გამშვები"), (".claude/hooks/", "hook-ები"),
         (".claude/settings", "ნებართვების ფაილი"), ("tools/gates/gates.toml", "კარიბჭეების სია"),
         ("tools/gates/drill.py", "დრილი"), ("tools/gates/gate.py", "კარიბჭეების გამშვები"),
         ("tools/gates/README.md", "კარიბჭეების სახელმძღვანელო"), ("tools/gates/", "კარიბჭეები"),
         ("tools/drill_floor.py", "დრილის იატაკი"), ("tools/engine_line.py", "სესიის ბოლოს ხაზი"),
         ("tools/approve.py", "მფლობელის დამტკიცება (/approve)"), ("orchestration/", "ორკესტრაცია"))
STATES = (("unchecked", "⚠ commit-შია, მაგრამ დრილს არ შეუმოწმებია"),
          ("pending", "ჯერ commit-ში არ არის (დრილი commit-ზე შეამოწმებს)"),
          ("checked", "commit-შია და დრილმა შეამოწმა ✓"))


def git(root: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def receipts_file(root: Path) -> Path | None:
    common = (git(root, "rev-parse", "--git-common-dir") or "").strip()
    if not common:
        return None
    p = Path(common)
    return (p if p.is_absolute() else root / p) / RECEIPTS


def write_receipt(root: Path) -> bool:
    """At commit, once the drill passed: the tree the commit records (`git write-tree` — the index the commit takes,
    GIT_INDEX_FILE included). Best effort: without a receipt the line only calls that commit unchecked."""
    tree, where = (git(root, "write-tree") or "").strip(), receipts_file(root)
    if not tree or where is None:
        return False
    try:
        with where.open("a", encoding="utf-8") as fh:
            fh.write(tree + "\n")
    except OSError:
        return False
    return True


def words(path: str) -> str:
    parts = path.split("/")
    if path.startswith(".claude/skills/") and len(parts) > 3:
        return f"skill /{parts[2]}"
    if path.startswith((".claude/agents/", ".claude/rules/")) and len(parts) > 2:
        return ("subagent " if parts[1] == "agents" else "წესი ") + Path(parts[-1]).stem
    for start, said in WORDS:
        if path == start or (start.endswith("/") and path.startswith(start)) or path.startswith(start + "."):
            return said
    return f"ძრავის ხელსაწყო {parts[-1]}"


def committed(root: Path, since: str | None, seen: set[str]) -> dict[str, str] | None:
    """{engine file: checked | unchecked} in the commits after `since` (None: every commit but the first). The drill at
    commit runs over the whole tree, so a file is checked when the commit that last changed it, or any newer one, left a
    receipt — that tree holds the file exactly as it is now; a change newer than the newest receipt is unchecked."""
    log = git(root, "log", "--format=%x00%T %P", "--name-only", "--no-renames", "HEAD" if since is None else f"{since}..HEAD")
    if log is None:
        return None
    out: dict[str, str] = {}
    drilled = False  # this commit or a newer one left a receipt
    for chunk in log.split("\0"):  # newest first
        lines = chunk.strip().splitlines()
        if not lines or len(lines[0].split()) < 2:  # a first commit has no parent: the engine arrives, it does not change
            continue
        drilled = drilled or lines[0].split()[0] in seen
        for f in lines[1:]:
            if f.startswith(PREFIXES) and f not in out:
                out[f] = "checked" if drilled else "unchecked"
    return out


def changes(root: Path, since: str | None) -> dict[str, str] | None:
    """{engine file: checked | unchecked | pending}; {} before the first commit; None when git could not answer."""
    where = receipts_file(root)
    if where is None:
        return None
    if git(root, "rev-parse", "--verify", "-q", "HEAD") is None:
        return {}  # before the first commit there is nothing to compare with
    try:
        seen = set(where.read_text(encoding="utf-8").split()) if where.is_file() else set()
    except OSError:
        seen = set()  # every commit then reads "not checked": an alarm too many, never one too few
    out = committed(root, since, seen)
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
    if out is None or status is None:
        return None
    for rec in status.split("\0"):
        if rec[3:].startswith(PREFIXES):
            out[rec[3:]] = "pending"
    return out


def line(root: Path, since: str | None = "HEAD") -> str | None:
    """The Georgian line; "" when no engine file changed, None when git could not answer."""
    found = changes(root, since)
    if found is None:
        return None
    groups = []
    for state, said in STATES:
        names = list(dict.fromkeys(words(f) for f in sorted(found) if found[f] == state))
        if names:
            groups.append(f"{said}: {', '.join(names)}")
    return "🔧 ძრავა შეიცვალა — " + "; ".join(groups) + "." if groups else ""


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="the session's engine line (ADR-0015)")
    ap.add_argument("--root", default=".")
    ap.add_argument("--since", default="HEAD", help="the commit the session started from; '-' = before the first commit")
    a = ap.parse_args(argv)
    text = line(Path(a.root).resolve(), None if a.since == "-" else a.since)
    if text is None:
        print("ENGINE-LINE INCONCLUSIVE: git could not say what changed — nothing is claimed", file=sys.stderr)
        return 2
    if text:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
