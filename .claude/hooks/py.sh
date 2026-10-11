#!/usr/bin/env bash
# Run one of this project's Python scripts with Python 3.12, from the project root,
# passing stdin through (hooks receive their JSON payload on stdin).
#
#   bash .claude/hooks/py.sh <script.py relative to the project root> [args...]
#
# Every hook in .claude/settings.json goes through this file, so the interpreter is
# chosen in exactly one place. Order: $ENGINE_PYTHON, the Windows `py -3.12` launcher,
# then python3. (On Windows a bare `python3` is often the Microsoft Store shim, which is
# why `py` comes first. The launcher's extra process was measured at ~10 ms per call on
# 2026-09-19 — a hook call costs ~0.3 s either way, almost all of it Python start-up.)
#
# If no interpreter is found the script exits 1: Claude Code shows that as a visible
# hook error and lets the tool call through. That is deliberate — a missing Python
# must be loud, but must not freeze every edit in the project.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || { echo "PY-SH: cannot cd to project root $ROOT" >&2; exit 1; }

if [ -n "${ENGINE_PYTHON:-}" ]; then
  PY=("$ENGINE_PYTHON")
elif command -v py >/dev/null 2>&1; then
  PY=(py -3.12)
elif command -v python3 >/dev/null 2>&1; then
  PY=(python3)
else
  echo "PY-MISSING: no Python 3.12 found (tried \$ENGINE_PYTHON, py -3.12, python3) — project hooks are OFF until this is fixed" >&2
  exit 1
fi

export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
exec "${PY[@]}" "$@"
