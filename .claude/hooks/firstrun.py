#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""First run of the engine in a new project (ADR-0011): make the folder a git repository, switch on the commit checks
and look at the tools — so a person who has just installed the engine can start straight from their idea.

SessionStart hook (startup, resume, clear). Silent when everything is already in place; otherwise one short Georgian
note for the agent: what was done and what is missing. It never touches the global git config (L-005), never
installs anything (installing a tool is the person's yes) and never fails the session — it always exits 0. A missing
tool is reported once per repository (a marker inside .git/), not at every session start.

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

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "tools" / "gates"))
MARKER = "engine-firstrun"  # inside .git/: the notes about missing tools that were already given


def project_root() -> Path:
    env = os.environ.get("FIRSTRUN_ROOT") or os.environ.get("CLAUDE_PROJECT_DIR")
    return Path(env).resolve() if env else HERE.parents[2]


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=30)


def gitleaks_found() -> bool:
    try:
        from gate import find_gitleaks  # the same search the secrets gate makes
    except Exception:
        return shutil.which("gitleaks") is not None
    return find_gitleaks() is not None


def setup(root: Path) -> tuple[list[str], list[str]]:
    """Put the repository and its commit checks in place. -> (what was done, what is missing)."""
    done: list[str] = []
    missing: list[str] = []
    if shutil.which("git") is None:
        return done, ["git არ არის დაყენებული — შენახვის წერტილები (commit) და commit-ის შემოწმებები ვერ იმუშავებს; "
                      "შესთავაზე ადამიანს დაყენება (Windows: `winget install Git.Git`) და დაელოდე მის „კი“-ს"]
    top = git(root, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        r = git(root, "init", "-q")
        if r.returncode != 0:
            return done, [f"`git init` ვერ შესრულდა: {(r.stderr or r.stdout).strip()[-200:]}"]
        done.append("საქაღალდე git-ის რეპოდ იქცა (`git init`): ყოველი ნაბიჯი შენახვის წერტილით (commit) შეინახება")
    elif Path(top.stdout.strip()).resolve() != root:
        return done, [f"პროექტი სხვა git-რეპოს შიგნითაა ({top.stdout.strip()}) — მის პარამეტრებს ძრავა არ ეხება; "
                      "ჰკითხე ადამიანს, ცალკე რეპო ხომ არ სჯობს"]
    hooks = git(root, "config", "--local", "--get", "core.hooksPath").stdout.strip()
    if not hooks:
        if not (root / ".githooks" / "pre-commit").is_file():
            missing.append("`.githooks/pre-commit` არ არის — commit-ის შემოწმებები ვერ ჩაირთო")
        elif git(root, "config", "--local", "core.hooksPath", ".githooks").returncode == 0:
            done.append("commit-ის შემოწმებები ჩაირთო (`core.hooksPath = .githooks`, მხოლოდ ამ რეპოში)")
        else:
            missing.append("`core.hooksPath` ვერ ჩაიწერა — commit-ის შემოწმებები არ მუშაობს")
    elif hooks.replace("\\", "/").rstrip("/") != ".githooks":
        missing.append(f"`core.hooksPath = {hooks}` — ძრავის commit-ის შემოწმებები არ მუშაობს; ჰკითხე ადამიანს, "
                       "შეიცვალოს თუ არა `.githooks`-ით")
    who = [key for key in ("user.name", "user.email") if not git(root, "config", "--get", key).stdout.strip()]
    if who:
        missing.append(f"git-ს არ აქვს {' და '.join(who)} — commit (შენახვის წერტილი) ვერ შეიქმნება; ჰკითხე ადამიანს "
                       "სახელი და ელფოსტა და მისი პასუხით ჩაწერე მხოლოდ ამ რეპოში (`git config --local user.name …`, "
                       "`git config --local user.email …`; საჯარო რეპოსთვის GitHub-ის დამალული მისამართი სჯობს)")
    if sys.version_info < (3, 12):
        missing.append(f"Python {sys.version_info.major}.{sys.version_info.minor} — ძრავას 3.12 სჭირდება; შესთავაზე "
                       "ადამიანს დაყენება (Windows: `winget install Python.Python.3.12`)")
    if not gitleaks_found():
        missing.append("gitleaks არ არის — საიდუმლოებს commit-ზე ძრავის საკუთარი სკანერი ამოწმებს (უფრო სუსტია: "
                       "git-ის ისტორიას არ ამოწმებს); შესთავაზე ადამიანს gitleaks-ის დაყენება მისი „კი“-თ "
                       "(Windows: `winget install Gitleaks.Gitleaks`)")
    return done, missing


def already_told(root: Path, missing: list[str]) -> bool:
    """True when exactly these missing-tool notes were given before in this repository (and records them now).
    Only the project's own repository gets the marker — never an enclosing one."""
    top = git(root, "rev-parse", "--show-toplevel")
    r = git(root, "rev-parse", "--absolute-git-dir")
    if top.returncode != 0 or r.returncode != 0 or Path(top.stdout.strip()).resolve() != root:
        return False
    marker = Path(r.stdout.strip()) / MARKER
    text = "\n".join(missing)
    try:
        if marker.is_file() and marker.read_text(encoding="utf-8") == text:
            return True
        marker.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return False


def main() -> int:
    if os.environ.get("EPISODIC_NESTED") == "1":
        return 0  # a nested model call made by a tool: not a person's session
    root = project_root()
    try:
        done, missing = setup(root)
        if not done and (not missing or already_told(root, missing)):
            return 0
        if done:
            already_told(root, missing)
    except Exception as e:  # never break the session start
        done, missing = [], [f"პირველი გაშვების შემოწმება ვერ შესრულდა: {type(e).__name__}: {e}"]
    lines = ["## პირველი გაშვება — ძრავა თავად ეწყობა (`.claude/hooks/firstrun.py`, ADR-0011)"]
    lines += [f"- გაკეთდა: {d}" for d in done]
    lines += [f"- აკლია: {m}" for m in missing]
    lines.append("- ადამიანს ეს ერთი-ორი უბრალო წინადადებით უთხარი; setup-ს ნუ სთხოვ და მის იდეაზე მუშაობას ნუ შეაჩერებ.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "\n".join(lines)}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
