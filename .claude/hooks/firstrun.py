#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""First run of the engine in a new project (ADR-0011): make the folder a git repository, switch on the commit checks
and look at what is missing — so a person who has just installed the engine can start straight from their idea.

SessionStart hook (startup, resume, clear). It runs `git init` when the folder is not a repository, sets
core.hooksPath = .githooks in this repository only, and checks git itself, git's name and e-mail, Python 3.12 and
gitleaks; a project inside another repository, or a core.hooksPath of the person's own, is reported and left alone.
Silent when everything is in place; otherwise one short Georgian note for the agent: what was done and what is
missing. It never touches the global git config (L-005), never installs anything (installing a tool is the person's
yes) and never fails the session — it always exits 0. Missing tools are reported once per repository (a marker
inside .git/); commit checks that are not running are reported at every session start, and with no repository of its
own (git missing, or an enclosing repository) every note repeats on purpose.

  FIRSTRUN_ROOT   the project folder (default: CLAUDE_PROJECT_DIR, else the project this file belongs to)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
# Windows looks for a program in the current folder before PATH unless this is set. Here the current folder is the
# project, where a planted git.bat would otherwise run at every session start (review S4).
os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "tools" / "gates"))
MARKER = "engine-firstrun"  # inside .git/: the notes about missing tools that were already given


def project_root() -> Path:
    env = os.environ.get("FIRSTRUN_ROOT") or os.environ.get("CLAUDE_PROJECT_DIR")
    return Path(env).resolve() if env else HERE.parents[2]


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """git in the project. A git that cannot start reads as a failed command (exit 127), never as an exception."""
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(["git", *args], 127, "", str(e))


def repo_top(root: Path) -> Path | None:
    r = git(root, "rev-parse", "--show-toplevel")
    return Path(r.stdout.strip()).resolve() if r.returncode == 0 and r.stdout.strip() else None


def gitleaks_note() -> str | None:
    """None when the secrets gate will find gitleaks; otherwise what the agent should tell the person."""
    try:
        from gate import find_gitleaks  # the same search the secrets gate makes
    except Exception as e:  # e.g. a Python without tomllib — say so, never guess
        return f"gitleaks-ის შემოწმება ვერ გაეშვა ({type(e).__name__}: {e})"
    if find_gitleaks():
        return None
    explicit = os.environ.get("GITLEAKS_BIN")
    if explicit:  # the gate treats a named but missing gitleaks as INCONCLUSIVE, not as "not installed"
        return (f"`GITLEAKS_BIN` ფაილზე მიუთითებს, რომელიც არ არსებობს ({explicit}) — საიდუმლოების შემოწმება "
                "INCONCLUSIVE-ით ჩერდება; ჰკითხე ადამიანს, გაასწოროს ეს ცვლადი თუ წაშალოს")
    return ("gitleaks არ არის — საიდუმლოებს commit-ზე ძრავის საკუთარი სკანერი ამოწმებს (უფრო სუსტია: git-ის "
            "ისტორიას არ ამოწმებს); შესთავაზე ადამიანს gitleaks-ის დაყენება მისი „კი“-თ "
            "(Windows: `winget install Gitleaks.Gitleaks`)")


def setup(root: Path) -> tuple[list[str], list[str], list[str]]:
    """Put the repository and its commit checks in place.
    -> (what was done, what is missing — told once, why the commit checks are not running — told every session)."""
    done: list[str] = []
    missing: list[str] = []
    gate_off: list[str] = []
    if shutil.which("git") is None:
        return done, ["git არ არის დაყენებული — შენახვის წერტილები (commit) და commit-ის შემოწმებები ვერ იმუშავებს; "
                      "შესთავაზე ადამიანს დაყენება (Windows: `winget install Git.Git`) და დაელოდე მის „კი“-ს"], gate_off
    top = repo_top(root)
    if top is None:
        r = git(root, "init", "-q")
        if r.returncode != 0:
            return done, [f"`git init` ვერ შესრულდა: {(r.stderr or r.stdout).strip()[-200:]}"], gate_off
        done.append("საქაღალდე git-ის რეპოდ იქცა (`git init`): ყოველი ნაბიჯი შენახვის წერტილით (commit) შეინახება")
    elif top != root:
        return done, [f"პროექტი სხვა git-რეპოს შიგნითაა ({top}) — მის პარამეტრებს ძრავა არ ეხება; "
                      "ჰკითხე ადამიანს, ცალკე რეპო ხომ არ სჯობს"], gate_off
    hook = root / ".githooks" / "pre-commit"
    hooks = git(root, "config", "--get", "core.hooksPath").stdout.strip()  # this repository's, else the person's own
    if not hooks and hook.is_file():
        if git(root, "config", "--local", "core.hooksPath", ".githooks").returncode == 0:
            done.append("commit-ის შემოწმებები ჩაირთო (`core.hooksPath = .githooks`, მხოლოდ ამ რეპოში)")
        else:
            gate_off.append("`core.hooksPath` ვერ ჩაიწერა — commit-ის შემოწმებები არ მუშაობს")
    elif hooks and hooks.replace("\\", "/").rstrip("/") != ".githooks":
        gate_off.append(f"`core.hooksPath = {hooks[:120]}` — ძრავის commit-ის შემოწმებები არ მუშაობს; ჰკითხე ადამიანს, "
                        "შეიცვალოს თუ არა ამ რეპოში `.githooks`-ით")
    elif not hook.is_file():  # git skips a missing hook without a word
        gate_off.append("`.githooks/pre-commit` არ არის — commit-ის შემოწმებები არ მუშაობს")
    who = [key for key in ("user.name", "user.email") if not git(root, "config", "--get", key).stdout.strip()]
    if who:
        missing.append(f"git-ს არ აქვს {' და '.join(who)} — commit (შენახვის წერტილი) ვერ შეიქმნება; ჰკითხე ადამიანს "
                       "სახელი და ელფოსტა და მისი პასუხით ჩაწერე მხოლოდ ამ რეპოში (`git config --local user.name …`, "
                       "`git config --local user.email …`; საჯარო რეპოსთვის GitHub-ის დამალული მისამართი "
                       "`…@users.noreply.github.com` სჯობს)")
    if sys.version_info < (3, 12):
        missing.append(f"Python {sys.version_info.major}.{sys.version_info.minor} — ძრავას 3.12 სჭირდება; შესთავაზე "
                       "ადამიანს დაყენება (Windows: `winget install Python.Python.3.12`)")
    note = gitleaks_note()
    if note:
        missing.append(note)
    return done, missing, gate_off


def marker_path(root: Path) -> Path | None:
    """The told-once marker inside this project's own .git/ — None without a repository of its own."""
    if repo_top(root) != root:
        return None
    r = git(root, "rev-parse", "--absolute-git-dir")
    return Path(r.stdout.strip()) / MARKER if r.returncode == 0 and r.stdout.strip() else None


def was_told(marker: Path | None, text: str) -> bool:
    try:
        return marker is not None and marker.is_file() and marker.read_text(encoding="utf-8") == text
    except OSError:
        return False


def record_told(marker: Path | None, text: str) -> None:
    if marker is None:
        return
    try:
        marker.write_text(text, encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    if os.environ.get("EPISODIC_NESTED") == "1":
        return 0  # a nested model call made by a tool: not a person's session
    root = project_root()
    try:
        done, missing, gate_off = setup(root)
        marker, text = marker_path(root), "\n".join(missing)
        if was_told(marker, text):
            missing = []  # a missing tool is said once; commit checks that are off are said every session
        if not done and not missing and not gate_off:
            return 0
        record_told(marker, text)
    except Exception as e:  # never break the session start
        done, missing, gate_off = [], [f"პირველი გაშვების შემოწმება ვერ შესრულდა: {type(e).__name__}: {e}"], []
    lines = ["## პირველი გაშვება — ძრავა თავად ეწყობა (`.claude/hooks/firstrun.py`, ADR-0011)"]
    lines += [f"- გაკეთდა: {d}" for d in done]
    lines += [f"- აკლია: {m}" for m in gate_off + missing]
    lines.append("- ადამიანს ეს ერთი-ორი უბრალო წინადადებით უთხარი; setup-ს ნუ სთხოვ და მის იდეაზე მუშაობას ნუ შეაჩერებ.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "\n".join(lines)}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
