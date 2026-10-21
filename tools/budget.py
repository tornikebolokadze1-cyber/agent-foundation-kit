#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What every session loads before its first word, in bytes — and the budget it stays under.

Claude Code reads the project's CLAUDE.md and every file it imports with an `@path` line (five hops deep), each rule
in .claude/rules that names no `paths:`, and — for its skill and agent lists — the `description` of every agent and
the `description` and `when_to_use` of every skill. All of it is paid for in every session and again on every
prompt-cache rewrite. A line count cannot hold it: memory/LESSONS.md was 37 lines and 15,752 bytes (2026-10-20).

The budget is `max_bytes` of the `budget` gate in tools/gates/gates.toml. The guard (G7) refuses an edit that makes
the total grow past it and lets every edit that shrinks the total through (gbrain's rule); the gate fails a total
over it however it got there, and a budget above the owner's last `/approve budget <N>` row in memory/approvals.md.
Only the owner raises it. Not counted: the SessionStart brief (it is built from the documents' auto blocks) and the
person's own global files. Known gap: before the owner's first `/approve budget`, a budget raised from the shell
shows only in git history.

  bash .claude/hooks/py.sh tools/budget.py [--root DIR]   every always-loaded file, its bytes, the total and the budget

Exit 0 = within the budget · 1 = over it · 2 = no budget configured.
"""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GATES = "tools/gates/gates.toml"
LEDGER = "memory/approvals.md"
MAX_HOPS = 5  # Claude Code follows @imports five levels deep
IMPORT_RE = re.compile(r"^@(\S+)[ \t]*$", re.M)
FM_KEY_RE = re.compile(r"^([A-Za-z_][\w-]*):[ \t]*(.*)$")
PATTERNS = (".claude/rules/**/*.md", ".claude/skills/*/SKILL.md", ".claude/agents/*.md")


def norm(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def size(text: str) -> int:
    return len(norm(text).encode("utf-8"))


def frontmatter(text: str) -> dict[str, str]:
    """The top-level keys of a frontmatter block, each with its raw value (continuation lines included)."""
    lines = norm(text).split("\n")
    if not lines or lines[0].strip() != "---":
        return {}
    out: dict[str, str] = {}
    key = ""
    for ln in lines[1:]:
        if ln.strip() == "---":
            return out
        m = FM_KEY_RE.match(ln)
        if m:
            key = m.group(1)
            out[key] = m.group(2)
        elif key:
            out[key] += "\n" + ln
    return {}  # never closed: not a frontmatter block


def kind(rel: str) -> str | None:
    """How a file under .claude/ reaches every session: skill, agent, rule — or None."""
    low = rel.replace("\\", "/").lower()
    if re.fullmatch(r"\.claude/skills/[^/]+/skill\.md", low):
        return "skill"
    if re.fullmatch(r"\.claude/agents/[^/]+\.md", low):
        return "agent"
    if low.startswith(".claude/rules/") and low.endswith(".md"):
        return "rule"
    return None


def loaded(rel: str, text: str) -> int:
    """The bytes of this file that every session loads: a skill's or an agent's listing text — none for a skill only
    the person can invoke (`disable-model-invocation: true`: "Description not in context", code.claude.com/docs/en/
    skills) — a rule unless it names `paths:` (then it loads beside those files only), anything else whole."""
    k = kind(rel)
    if k in ("skill", "agent"):
        fm = frontmatter(text)
        if k == "skill" and fm.get("disable-model-invocation", "").strip().strip("\"'").lower() == "true":
            return 0
        return sum(size(fm.get(key, "")) for key in (("description", "when_to_use") if k == "skill" else ("description",)))
    if k == "rule" and "paths" in frontmatter(text):
        return 0
    return size(text)


def imported(base: str, target: str) -> str | None:
    """An @import as a path from the project root; None for one outside it (the person's own files)."""
    if target.startswith(("~", "/", "\\")) or re.match(r"[A-Za-z]:", target):
        return None
    parts: list[str] = []
    for seg in f"{Path(base).parent.as_posix()}/{target}".replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def always_loaded(root: Path, override: dict[str, str] | None = None) -> dict[str, int]:
    """{path from the root: bytes every session loads}. `override` gives files' text as an edit would leave it."""
    over = {k.replace("\\", "/").lower(): v for k, v in (override or {}).items()}

    def text(rel: str) -> str | None:
        if rel.lower() in over:
            return over[rel.lower()]
        p = root / rel
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None

    out: dict[str, int] = {}
    seen: set[str] = set()
    queue = [("CLAUDE.md", 0)]
    while queue:
        rel, hop = queue.pop(0)
        if rel.lower() in seen:
            continue
        seen.add(rel.lower())
        t = text(rel)
        if t is None:
            continue
        out[rel] = size(t)
        if hop < MAX_HOPS:
            queue += [(r, hop + 1) for r in (imported(rel, m.group(1)) for m in IMPORT_RE.finditer(norm(t))) if r]
    names = {p.relative_to(root).as_posix() for pat in PATTERNS for p in root.glob(pat) if p.is_file()}
    names |= {k.replace("\\", "/") for k in (override or {}) if kind(k)}
    for rel in sorted(names, key=str.lower):
        t = None if rel.lower() in seen else text(rel)
        n = loaded(rel, t) if t is not None else 0
        if n:
            out[rel] = n
    return out


def import_closure(root: Path) -> set[str]:
    """CLAUDE.md and what it imports, lower case — what the guard must weigh as a whole file."""
    return {k.lower() for k, _ in always_loaded(root).items() if not kind(k)}


def budget_in(text: str) -> int | None:
    """max_bytes of the `budget` gate in a gates.toml text, or None."""
    try:
        gates = tomllib.loads(text).get("gate", [])
    except tomllib.TOMLDecodeError:
        return None
    hits = [g.get("max_bytes") for g in gates if isinstance(g, dict) and g.get("id") == "budget"]
    return hits[0] if hits and isinstance(hits[0], int) else None


def budget(root: Path) -> int | None:
    p = root / GATES
    return budget_in(p.read_text(encoding="utf-8", errors="replace")) if p.is_file() else None


def owner_budget(root: Path) -> int | None:
    """The budget in the owner's last `/approve budget` row of the ledger, or None if there is none."""
    p = root / LEDGER
    last = None
    for line in (p.read_text(encoding="utf-8", errors="replace").splitlines() if p.is_file() else []):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[1].strip("` ") == "budget" and "→" in cells[2]:
            digits = re.sub(r"[^\d]", "", cells[2].split("→", 1)[1].split()[0] if cells[2].split("→", 1)[1].split() else "")
            last = int(digits) if digits else last
    return last


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="the text every session loads, in bytes, and its budget")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    root = Path(ap.parse_args(argv).root).resolve()
    files = always_loaded(root)
    total, cap = sum(files.values()), budget(root)
    for rel, n in sorted(files.items(), key=lambda kv: -kv[1]):
        print(f"{n:>9,}  {rel}{'  (listing text)' if kind(rel) in ('skill', 'agent') else ''}")
    if cap is None:
        print(f"{total:>9,}  total — no budget: the `budget` gate in {GATES} has no max_bytes")
        return 2
    print(f"{total:>9,}  total — budget {cap:,} ({'over by ' + format(total - cap, ',') if total > cap else format(cap - total, ',') + ' left'})")
    return 1 if total > cap else 0


if __name__ == "__main__":
    sys.exit(main())
