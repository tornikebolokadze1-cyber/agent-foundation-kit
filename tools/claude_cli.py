"""How the engine starts a nested Claude Code session: which `claude`, and what its process may inherit.

Used by orchestration/run.py (ADR-0005). The caller adds tools/ to sys.path.
.claude/hooks/episodic.py still has its own search for the SessionEnd summary (without Homebrew's folders); it moves
here later.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from redact import find_secrets

BREW_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")  # Homebrew's folders on macOS (Apple silicon, Intel)
KEEP_ENV = re.compile(r"^(ANTHROPIC_|CLAUDE_)|^(HTTPS?_PROXY|NO_PROXY|ALL_PROXY)$", re.I)
SECRET_ENV = re.compile(r"(^|_)(API_?KEYS?|KEYS?|TOKENS?|SECRETS?|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|AUTH|PAT|DSN"
                        r"|COOKIES?)(_|$)|PASSWORD$|PASSWD$|_PASS$|_PWD$|^OPENROUTER_", re.I)


def find_claude() -> list[str]:
    """The native install first — on Windows the `claude` on PATH can be a broken npm shim (L-009) — then PATH, then
    Homebrew's folders, which an app started from the macOS Dock does not have on PATH; the bare name last."""
    for name in (("claude.exe", "claude") if os.name == "nt" else ("claude",)):
        native = Path.home() / ".local" / "bin" / name
        if native.is_file():
            return [str(native)]
    found = shutil.which("claude")
    if found:
        return [found]
    if os.name != "nt":
        for folder in BREW_DIRS:
            if os.access(Path(folder) / "claude", os.X_OK):
                return [str(Path(folder) / "claude")]
    return ["claude"]


def nested_env() -> dict[str, str]:
    """What a nested session's process inherits: no other service's key (with read-only tools it has no shell to read
    one with anyway; this is the second wall), no CLAUDECODE, and EPISODIC_NESTED=1, so the project's hooks inside it
    write no episode of their own. A name list cannot know every name a secret goes by; a step that can run commands
    (the stage-2 codex checker, ADR-0005 §4) needs a list of what may pass instead."""
    env = {}
    for k, v in os.environ.items():
        if k == "CLAUDECODE":
            continue
        if KEEP_ENV.search(k) or not (SECRET_ENV.search(k) or find_secrets(v)):
            env[k] = v
    env["EPISODIC_NESTED"] = "1"
    return env
