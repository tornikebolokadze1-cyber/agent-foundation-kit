#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The drill's floor (ADR-0015): how many cases tools/gates/drill.py holds — a ratchet that replaces a permission window.

`floor` of the drill gate in tools/gates/gates.toml. The drill gate (gate.py) fails when the drill holds fewer cases
than the floor (a case was removed, or a group stopped running) and when it holds more (the floor rises with the drill,
in the same commit); a floor below the last commit's needs the owner's own `/approve floor N` row in
memory/approvals.md, written since that commit (LEDGER). A drill gate switched off, kept from the commit or removed arms
no case, so it lowers the floor to 0; once the owner's switch is committed, the floor written on that gate is what is
held, at commit (gate.py) as in G7. The guard's G7 refuses an edit that lowers, removes or switches off
the floor.
A case is ARMED here or ELSEWHERE — a case only another system can run (Windows' admin shares, macOS and Linux file
modes) — so the count is the same on Windows, macOS and Linux. The kit has no dispatcher, so its floor is its own.
The drill gate is the one gate whose builtin is "drill" (is_drill) — one rule for gate.py and the guard; gate.py refuses
a gates.toml with more than one.
"""
from __future__ import annotations

import re
import tomllib

GATES = "tools/gates/gates.toml"
LEDGER = "memory/approvals.md"
LEDGER_ID = "drill-floor"
ARMED_RE = re.compile(r"\bARMED=(\d+)\b")
ELSEWHERE_RE = re.compile(r"\bELSEWHERE=(\d+)\b")


def floor_of(gate: dict | None) -> int | None:
    """The `floor` of a drill gate's table, or None (a bool is not a number here)."""
    value = (gate or {}).get("floor")
    return value if type(value) is int else None


def is_drill(gate: object) -> bool:
    """A drill gate: a [[gate]] table whose builtin is "drill" — the gate gate.py runs the drill for, whatever its id.
    Found in use (2026-11-08): the floor used to be read from the gate whose id was "drill" while gate.py ran every builtin one, so a second
    drill gate, or a renamed one, hid the last commit's floor and it went down unseen."""
    return isinstance(gate, dict) and gate.get("builtin") == "drill"


def drill_gates(text: str | None) -> list[dict]:
    """Every drill gate of a gates.toml text ([] when it cannot be read)."""
    try:
        gates = tomllib.loads(text or "").get("gate", [])
    except tomllib.TOMLDecodeError:
        return []
    return [g for g in gates if is_drill(g)] if isinstance(gates, list) else []


def drill_gate(text: str | None) -> dict | None:
    """The table of the one drill gate in a gates.toml text, or None — none, or more than one (gate.py refuses
    those)."""
    drills = drill_gates(text)
    return drills[0] if len(drills) == 1 else None


def floor_in(text: str | None) -> int | None:
    """The floor of the one drill gate in a gates.toml text, or None."""
    return floor_of(drill_gate(text))


def runs_at_commit(gate: dict | None) -> bool:
    """A drill gate that is switched on and runs at commit, read as gate.py reads it — one that does not arms no case."""
    return bool(gate and gate.get("enabled") and gate.get("pre_commit"))


def held_in(text: str | None) -> int | None:
    """The floor a gates.toml text holds the drill to at commit: its floor, 0 when the drill gate is switched off or kept
    from the commit, None when there is no drill gate or it has no floor."""
    gate = drill_gate(text)
    floor = floor_of(gate)
    return None if floor is None else floor if runs_at_commit(gate) else 0


def cases_in(line: str) -> int | None:
    """The cases the drill's last line counts — ARMED plus ELSEWHERE —, or None when it names no count."""
    armed = ARMED_RE.search(line or "")
    if not armed:
        return None
    other = ELSEWHERE_RE.search(line)
    return int(armed.group(1)) + (int(other.group(1)) if other else 0)


def floor_rows(ledger: str | None) -> dict[str, int]:
    """{row as written: the floor it set} for every `/approve floor` row of a ledger text."""
    out: dict[str, int] = {}
    for line in (ledger or "").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[1].strip("` ") != LEDGER_ID or "→" not in cells[2]:
            continue
        digits = re.sub(r"[^\d]", "", (cells[2].split("→", 1)[1].split() or [""])[0])
        if digits:
            out[line.strip()] = int(digits)
    return out


def approved_since(ledger_now: str | None, ledger_then: str | None, floor: int) -> bool:
    """True when the ledger holds an owner's row setting exactly this floor that the earlier ledger did not have."""
    then = floor_rows(ledger_then)
    return any(value == floor and row not in then for row, value in floor_rows(ledger_now).items())
