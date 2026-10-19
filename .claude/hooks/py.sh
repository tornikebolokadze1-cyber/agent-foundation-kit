#!/usr/bin/env bash
# Run one of this project's Python scripts from the project root, passing stdin through
# (hooks receive their JSON payload on stdin).
#
#   bash .claude/hooks/py.sh <script.py relative to the project root> [args...]
#   bash .claude/hooks/py.sh -m <module> [args...]
#
# Every hook in .claude/settings.json, every skill and every command the agent runs goes
# through this file, so the interpreter is chosen in exactly one place, the same way on
# Windows (Git Bash), macOS and Linux. The engine needs Python 3.12 or newer on every system:
# its scripts keep a program planted in the current folder (the project) from running by setting
# NoDefaultCurrentDirectoryInExePath, which Python 3.11's shutil.which ignores on Windows
# (measured 2026-10-18), and the drill, a commit gate, uses shutil.rmtree(onexc=) from 3.12.
# Candidates, in order. Each one found by searching must answer that it is 3.12+ before it is
# used: a launcher without that version, a version manager's shim for a version that is not
# installed, and macOS's own python3 (3.9) all fail the test and are passed over.
#   1. $ENGINE_PYTHON, when it is set (taken as given);
#   2. the interpreter found last time, while it still exists ($PYSH_CACHE; by default
#      .git/engine-python, none in a git worktree), so the search and its extra Python start
#      (~0.1 s on Windows, measured 2026-10-18) happen once, not at every hook call. It is
#      trusted like .git/config: Claude Code asks before its file tools write anything in .git/.
#      What it can still stop: a note that is a link is neither read nor written (a planted link
#      would make the launcher write over the file it points at), and a note that names a
#      program whose file name is not python… is passed over — the search runs and rewrites it;
#   3. Windows: the `py` launcher (-3.12, then -3), then the folders the python.org installer
#      uses (L-020: a Claude Code process whose PATH lost the user's Python folders turned
#      every hook off). A bare `python3` there is often the Microsoft Store shim, which is
#      why it comes last;
#   4. python3.12, python3.13, python3.14, python3.15 — on PATH, then in Homebrew's folders
#      ($PYSH_EXTRA_DIRS), which an app started from the macOS Dock does not have on PATH;
#   5. python3, the same way.
# Written for bash 3.2, which is what macOS runs as `bash`.
#
# If no interpreter is found the script exits 1: Claude Code shows that as a visible
# hook error and lets the tool call through. That is deliberate — a missing Python
# must be loud, but must not freeze every edit in the project. The agent never sees a
# hook error, though, so at session start (`episodic.py start`) the script instead prints
# a notice that reaches both the person and the agent, and exits 0.
set -u
SRC="${BASH_SOURCE[0]}"
[ "${OS:-}" = "Windows_NT" ] && SRC="${SRC//\\//}"  # a Windows path may arrive with backslashes
HERE="${SRC%/*}"
[ "$HERE" = "$SRC" ] && HERE=.
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" || { echo "PY-SH: cannot cd to project root $ROOT" >&2; exit 1; }
EXTRA_DIRS="${PYSH_EXTRA_DIRS-/opt/homebrew/bin /usr/local/bin}"  # Homebrew's folders; the drill empties this
CACHE="${PYSH_CACHE-}"
if [ -z "${PYSH_CACHE+set}" ] && [ -d .git ]; then
  CACHE=".git/engine-python"
fi

resolve() {
  # The interpreter's own path when "$@" is Python 3.12+, nothing otherwise. -X utf8: a path
  # with Georgian letters must print on a Windows console code page too (L-001).
  "$@" -I -S -X utf8 -c 'import sys
if sys.version_info >= (3, 12): sys.stdout.write(sys.executable)' 2>/dev/null
}

use() {
  # Take "$@" when it answers, by its own path; remember that path for the next call. The note is written by bash's
  # own printf (no mv, no rm), so the launcher needs no program but Python itself — a PATH without the system's
  # folders still works (L-020). A reader that comes before the line is written finds the file empty and searches.
  local exe
  exe="$(resolve "$@")"
  [ -n "$exe" ] || return 1
  PY=("$exe")
  if [ -n "$CACHE" ] && [ ! -L "$CACHE" ]; then
    printf '%s\n' "$exe" 2>/dev/null > "$CACHE" || :  # 2> first: a cache that cannot be written stays silent
  fi
  return 0
}

python_name() {
  # Only an interpreter may be remembered: its file name is python, python3 or python3.N (.exe on Windows).
  local n="${1//\\//}"
  case "${n##*/}" in
    python | python3 | python3.[0-9]* | python.exe | python3.exe) return 0 ;;
  esac
  return 1
}

windows_installs() {
  # python.org puts a per-user install under %LOCALAPPDATA%, an all-users one under %ProgramFiles%.
  local la="${LOCALAPPDATA:-}" pf="${PROGRAMFILES:-}" v
  la="${la//\\//}"
  pf="${pf//\\//}"
  if [ -n "$la" ] && [ -x "$la/Programs/Python/Launcher/py.exe" ]; then
    use "$la/Programs/Python/Launcher/py.exe" -3.12 && return 0
    use "$la/Programs/Python/Launcher/py.exe" -3 && return 0
  fi
  for v in 312 313 314 315; do
    if [ -n "$la" ] && [ -x "$la/Programs/Python/Python$v/python.exe" ] && use "$la/Programs/Python/Python$v/python.exe"; then
      return 0
    fi
    if [ -n "$pf" ] && [ -x "$pf/Python$v/python.exe" ] && use "$pf/Python$v/python.exe"; then
      return 0
    fi
  done
  return 1
}

first_good() {
  # The first of the given names, on PATH or in Homebrew's folders, that is new enough.
  local name cand dir
  for name in "$@"; do
    cand="$(command -v "$name" 2>/dev/null)"
    if [ -n "$cand" ] && [ -x "$cand" ] && use "$cand"; then
      return 0
    fi
    for dir in $EXTRA_DIRS; do
      if [ -x "$dir/$name" ] && use "$dir/$name"; then
        return 0
      fi
    done
  done
  return 1
}

found=0
cached=""
if [ -n "${ENGINE_PYTHON:-}" ]; then
  PY=("$ENGINE_PYTHON")
  found=1
elif [ -n "$CACHE" ] && [ -f "$CACHE" ] && [ ! -L "$CACHE" ] && read -r cached < "$CACHE" && [ -n "$cached" ] \
  && python_name "$cached" && [ -x "$cached" ]; then
  PY=("$cached")
  found=1
elif [ "${OS:-}" = "Windows_NT" ] && command -v py >/dev/null 2>&1 && { use py -3.12 || use py -3; }; then
  found=1
elif [ "${OS:-}" = "Windows_NT" ] && windows_installs; then
  found=1
elif first_good python3.12 python3.13 python3.14 python3.15 || first_good python3; then
  found=1
fi

if [ "$found" = 0 ]; then
  if [ "${1:-}" = ".claude/hooks/episodic.py" ] && [ "${2:-}" = "start" ]; then
    # The install commands are also INSTALL["python"] in firstrun.py (bash cannot import it): change both together.
    printf '%s\n' '{"systemMessage": "⚠ ძრავა: Python 3.12 ან უფრო ახალი ვერ მოიძებნა — დარაჯი და სამუშაო მეხსიერება ამ სესიაში გამორთულია. დააყენე Python 3.12 (Windows: winget install Python.Python.3.12; Mac: brew install python@3.12; Linux: sudo apt install python3.12, სხვაგან uv python install 3.12) და თავიდან გახსენი ტერმინალი ან VS Code.", "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "PY-MISSING: no Python 3.12+ was found, so the engine hooks are OFF in this session (no guard, no sentinel, no working memory). Before any work, tell the person in Georgian to install Python 3.12 and restart the terminal or VS Code (install commands: the notice above; L-020)."}}'
    exit 0
  fi
  echo "PY-MISSING: no Python 3.12+ found (\$ENGINE_PYTHON, py, python3.12…3.15, python3) — project hooks are OFF until one is installed" >&2
  exit 1
fi

export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
exec "${PY[@]}" "$@"
