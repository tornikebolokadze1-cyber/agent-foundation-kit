#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Where Claude Code's sandbox stands for this project (ADR-0014) — read, never changed.

Claude Code can run Bash commands in a sandbox (an isolated run: the file system and the network are restricted). It
exists on macOS, Linux and WSL2 and is off by default; on native Windows it does not exist at all. Nothing in the
status-line payload or the environment says whether it is active, so this module reads what can be read: the system,
and `sandbox.enabled` in the project's settings (`.claude/settings.local.json`, `.claude/settings.json`) or the
person's (`~/.claude/settings.json`). The status line and the first run show the result; neither switches it on —
that is the person's yes.

  ENGINE_SANDBOX_STATE   none | off | on — overrides the reading (the drill proves every text on one machine)

Run by hand or by the drill: `sandbox_state.py [ROOT] [--system Windows|macOS|Linux|WSL2]` prints the state, the system
and the status line's words; `--system` makes the settings reading the same on every machine.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

STATES = ("none", "off", "on")
SYSTEMS = ("Windows", "macOS", "Linux", "WSL2")


def platform_label() -> str:
    if os.name == "nt":
        return "Windows"
    if sys.platform == "darwin":
        return "macOS"
    try:
        if "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower():
            return "WSL2"
    except OSError:
        pass
    return "Linux"


def _enabled_in(path: Path) -> bool | None:
    """True/False when the file says sandbox.enabled, None when it does not (or cannot be read)."""
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    sandbox = cfg.get("sandbox") if isinstance(cfg, dict) else None
    if not isinstance(sandbox, dict) or "enabled" not in sandbox:
        return None
    return bool(sandbox.get("enabled"))


def sandbox_state(root: Path, system: str | None = None) -> tuple[str, str]:
    """-> (state, system). state: "none" — this system has no sandbox (native Windows); "on" — a system that has it
    and a settings file switches it on; "off" — a system that has it and no settings file switches it on. The
    project's settings win over the person's, local over shared. `system` names the system to read as (the drill);
    by default it is the one this runs on."""
    forced = (os.environ.get("ENGINE_SANDBOX_STATE") or "").strip().lower()
    system = system or platform_label()
    if forced in STATES:
        return forced, ("Windows" if forced == "none" else ("Linux" if system == "Windows" else system))
    if system == "Windows":
        return "none", system
    for p in (root / ".claude/settings.local.json", root / ".claude/settings.json",
              Path.home() / ".claude/settings.json"):
        found = _enabled_in(p)
        if found is not None:
            return ("on" if found else "off"), system
    return "off", system


def status_text(state: str, system: str) -> str:
    """The status line's words (ADR-0014): what is, not what should be."""
    if state == "none":
        return f"🛡 sandbox არ არის — {system} (WSL2-ში მუშაობს)"
    if state == "on":
        return f"🛡 sandbox ჩართულია (settings, {system})"
    return f"🛡 sandbox გამორთულია ({system})"


def firstrun_note(state: str, system: str) -> str | None:
    """What the first run tells the agent once (None when the sandbox is on)."""
    if state == "on":
        return None
    if state == "none":
        return ("sandbox (ბრძანებების იზოლირებული გაშვება: ფაილები და ქსელი შეზღუდული) ბუნებრივ Windows-ზე არ არსებობს — "
                "Claude Code ბრძანებებს იზოლაციის გარეშე უშვებს; იზოლაცია WSL2-ში მუშაობს (README — „sandbox და WSL2“). "
                "ადამიანს ეს ერთხელ უთხარი; დაყენებას ნუ სთხოვ")
    return (f"sandbox (ბრძანებების იზოლირებული გაშვება) ამ სისტემაზე ({system}) მუშაობს, მაგრამ გამორთულია — ჩართვა "
            "ადამიანის „კი“-თ: `sandbox.enabled: true` settings-ში (README — „sandbox და WSL2“); ქსელის allowlist-ი "
            "ცარიელი იწყება და ყოველ ახალ ჰოსტზე ფანჯარა იხსნება")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="where Claude Code's sandbox stands for a project (ADR-0014) — read only")
    ap.add_argument("root", nargs="?", default=".", help="the project folder (default: the current one)")
    ap.add_argument("--system", choices=SYSTEMS, help="read as this system instead of the one this runs on")
    a = ap.parse_args(argv)
    state, system = sandbox_state(Path(a.root).resolve(), a.system)
    print(state, system)
    print(status_text(state, system))
    return 0


if __name__ == "__main__":
    sys.exit(main())
