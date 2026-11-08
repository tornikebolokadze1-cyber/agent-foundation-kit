#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One Georgian line when the project's work is only on this computer: the current branch holds commits that no
remote copy has — more than UNPUSHED_MAX of them beside the branch's copy, or any at all when the branch has no copy or
the project no remote. Information, not a lock: uploading (`git push`) is the person's yes.

  bash .claude/hooks/py.sh tools/backup_line.py [--root DIR]

No network: HEAD is compared with the remote-tracking branches as git last saw them, and the line says when that was
(the newest fetch or push git recorded). A commit counts as uploaded when any remote-tracking branch holds it, so work
already in another uploaded branch is not counted. The branch's copy is its upstream, else a remote branch of the same
name (a branch pushed without `-u` has no upstream). Read-only: no fetch, no change to any git setting (L-005).
The session's start brief carries the line as a fact, and `episodic.py status` hands it to /session-close.
Prints nothing when every commit is uploaded, when no more than the threshold wait beside a copy, and in a repository
with no commit yet. Exit 0, or 2 when git could not answer — git missing, or a folder it cannot read as a repository —
and nothing is claimed then.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

UNPUSHED_MAX = 20  # more commits than this beside the branch's copy → the line; this is its one place
NAME_CHARS = 60    # a branch or copy name in the line: the brief's facts are never cut, so the line stays short


def git(root: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def short(name: str) -> str:
    return name if len(name) <= NAME_CHARS else name[:NAME_CHARS - 1] + "…"


def copy_of(root: Path, branch: str) -> str | None:
    """The current branch's remote copy as a full ref name — its upstream, else a remote-tracking branch of the same
    name (origin first) —, or None."""
    up = (git(root, "rev-parse", "--symbolic-full-name", "@{upstream}") or "").strip()
    if up.startswith("refs/remotes/"):
        return up
    refs = (git(root, "for-each-ref", "--format=%(refname)", "refs/remotes") or "").split()
    same = sorted((r for r in refs if r.count("/") >= 3 and r.split("/", 3)[3] == branch),
                  key=lambda r: r.split("/")[2] != "origin")
    return same[0] if same else None


def last_seen(root: Path) -> str:
    """When git last learned what a remote holds — the newest of FETCH_HEAD and the remote-tracking branches' logs
    (a fetch or a push writes them) — in the person's words."""
    times = []
    for name in ("FETCH_HEAD", "logs/refs/remotes"):
        where = (git(root, "rev-parse", "--git-path", name) or "").strip()
        if not where:
            continue
        p = Path(where) if Path(where).is_absolute() else root / where
        try:
            files = [p] if p.is_file() else [q for q in p.rglob("*") if q.is_file()] if p.is_dir() else []
            times += [q.stat().st_mtime for q in files]
        except OSError:
            continue
    if not times:
        return "fetch-ის ან push-ის კვალი არ ჩანს"
    return "ბოლო fetch ან push — " + datetime.fromtimestamp(max(times)).strftime("%Y-%m-%d %H:%M")


def line(root: Path) -> str | None:
    """The Georgian line; "" when there is nothing to say, None when git could not answer."""
    if git(root, "rev-parse", "--git-dir") is None:
        return None  # git is missing, or this folder is not a repository it can read
    if git(root, "rev-parse", "--verify", "-q", "HEAD") is None:
        return ""  # a repository with no commit yet: nothing to back up
    branch = (git(root, "rev-parse", "--abbrev-ref", "HEAD") or "").strip()
    remotes = git(root, "remote")
    count = git(root, "rev-list", "--count", "HEAD", "--not", "--remotes")
    if not branch or remotes is None or count is None or not count.strip().isdigit():
        return None
    n = int(count)
    if n == 0:
        return ""
    shown = f"ბრანჩის `{short(branch)}`" if branch != "HEAD" else "ამ commit-ის (detached HEAD)"
    if not remotes.split():
        return (f"💾 ბექაფი: {shown} ატვირთული ასლი არ ჩანს — პროექტს დისტანციური ასლი (remote) არ აქვს, ამიტომ {n} "
                "commit მხოლოდ ამ კომპიუტერზეა.")
    copy = copy_of(root, branch) if branch != "HEAD" else None
    seen = f"{last_seen(root)}; ქსელით არ შემოწმებულა"
    if copy is None:
        return f"💾 ბექაფი: {shown} ატვირთული ასლი არ ჩანს — {n} commit მხოლოდ ამ კომპიუტერზეა ({seen})."
    if n > UNPUSHED_MAX:
        return (f"💾 ბექაფი: {n} commit მხოლოდ ამ კომპიუტერზეა (ზღვარი — {UNPUSHED_MAX}): {shown} ატვირთული ასლი "
                f"(`{short(copy.removeprefix('refs/remotes/'))}`) მათ არ შეიცავს ({seen}).")
    return ""


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="the backup line")
    ap.add_argument("--root", default=".")
    a = ap.parse_args(argv)
    text = line(Path(a.root).resolve())
    if text is None:
        print("BACKUP-LINE INCONCLUSIVE: git could not say what is uploaded — nothing is claimed", file=sys.stderr)
        return 2
    if text:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
