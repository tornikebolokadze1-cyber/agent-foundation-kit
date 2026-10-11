#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stop hook: before Claude hands the turn back, re-check what THIS session changed.

Runs the fast, file-local gates (those marked `stop = true` in tools/gates/gates.toml:
graph links and frontmatter, json, toml, python syntax, shell syntax, line endings) on the
files this session edited — the guard records them in <state>/touched-<session_id>.
If one FAILS, exit 2: the reason goes back to Claude, which keeps working and fixes it
before the owner ever sees a broken file.

Never loops: when `stop_hook_active` is true (Claude is already continuing because of
this hook) it exits 0. Never blames another session: only this session's own files are
checked. INCONCLUSIVE does not block here — the pre-commit gate is the hard stop.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CODE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CODE_ROOT / "tools" / "gates"))
sys.path.insert(0, str(CODE_ROOT / "tools"))
import gate  # noqa: E402

MAX_LINES = 20


def state_dir() -> Path:
    return Path(os.environ.get("GUARD_STATE_DIR") or os.environ.get("EPISODIC_STATE_DIR")
                or (Path.home() / ".claude" / "session-state"))


def touched_files(sid: str, root: Path) -> list[Path]:
    p = state_dir() / f"touched-{sid}"
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[Path] = []
    for ln in dict.fromkeys(x.strip() for x in lines if x.strip()):
        f = Path(ln)
        try:
            f.resolve().relative_to(root)
        except ValueError:
            continue
        if f.is_file():
            out.append(f.resolve())
    return out


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    if payload.get("stop_hook_active"):
        return 0
    root = Path(os.environ.get("GATE_ROOT") or CODE_ROOT).resolve()
    files = touched_files(payload.get("session_id") or "", root)
    if not files:
        return 0
    gates = [g for g in gate.load_gates() if g.get("enabled") and g.get("stop")]
    results = gate.run(root, gates, files, pre_commit=False)
    failed = [r for r in results if r.status == "FAIL"]
    if not failed:
        return 0
    lines = [f"STOP-GATE: this session's edits broke {len(failed)} check(s) — fix them before handing back:"]
    for r in failed:
        lines.append(f"  {r.gate}: {r.summary}")
        lines += [f"    {d}" for d in r.details[:MAX_LINES]]
    lines.append("(Deterministic check, tools/gates/gate.py. Re-run: py -3.12 tools/gates/gate.py --files <file>)")
    print("\n".join(lines), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
