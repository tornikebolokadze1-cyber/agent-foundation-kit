#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PreToolUse guard: the owner's approvals and the project's history cannot be forged.

This is a speed bump with an audit trail, not a lock. An agent with a shell can always
find a way around a pattern check; what this file guarantees is that the obvious ways
are refused with a clear reason, and the gate (tools/context_graph.py, LEDGER check)
catches an approval status that has no owner record, whichever way it got there.

Blocks with exit 2 (the reason goes to stderr, which Claude sees):

  Edit | Write | MultiEdit | NotebookEdit
    G1  memory/approvals.md           only tools/approve.py (the owner's /approve) writes it — here, or in
                                      another copy of the project outside this folder (a worktree)
    G2  a generated file              memory/episodes/INDEX.md (episodic.py) · .git/engine-python (py.sh)
    G3  another session's episode     history is append-only; only needs_reconcile and
                                      reconciled_* may change (so /session-close can reconcile)
    G4  an owner-only status          intent accepted · spec approved/superseded ·
                                      plan approved · adr accepted/rejected/superseded
    G5  a frozen document             accepted intent / approved spec: only "reopen" (status
                                      back to draft, nothing else changed) · decided ADR:
                                      nothing · approved plan: tick boxes, append under
                                      "## გადახრები", approved→in-progress→done, or reopen
    G6  a secret file                 .env (not .env.example), *.pem, *.key, secrets/, ~/.ssh/… — never written
    S2  a redaction marker in content the sentinel hid a credential from the model; writing the marker
                                      back would destroy the real value (edit the other lines instead)
    G7  always-loaded text over its   an edit that makes what every session loads (CLAUDE.md and its imports,
        byte budget                   unscoped rules, skill and agent listings — tools/budget.py) grow past
                                      `max_bytes` of the budget gate; a shrinking edit always passes; raising
                                      `max_bytes` in tools/gates/gates.toml is the owner's (`/approve budget N`)
    G8  git's own configuration       .git/config (a worktree's, a submodule's): core.hooksPath and include.path
                                      live there — change it with `git config`, which asks the owner
  A file outside the project still gets S2, G6, G8 and G1 (by its name); another name for the project folder
  (//localhost/c$/…, //127.0.0.1/c$/…, a //?/C:/… long path) is read as the project itself.
  Bash | PowerShell
    B1  approve.py / approvals.md in a command that is not read-only
    B2  skipping git hooks: --no-verify (and its abbreviation --no-veri…), `commit -n`,
        core.hooksPath override (-c, --config-env, GIT_CONFIG_* variables) or a config include that
        can carry one (include.path, includeIf…); a shell write to the launcher's .git/engine-python or to
        git's own .git/config
    B3  force push: -f, --force, --force-with-lease, +refspec
    B2/B3 also refuse a word the shell makes up where git reads options — an expansion ($…, `…`, $(…)), a
        glob or brace list that starts the word, a PowerShell splat — in front of any subcommand and among
        the arguments of one that runs hooks (commit, merge, push, rebase, pull, am): the guard cannot see
        whether it turns into -n, --force or core.hooksPath. Inside an option's value (`-m "$(…)"`) it is
        allowed, unless an unquoted $(…) could split into more words; an unquoted variable given as a value
        (`-m $F`) is a known blind spot.
    B4  a secret file in any command that could read or stage it (cat, type, Get-Content,
        grep, python -c "open('.env')", git add …) — the permission deny list only covers
        the Read tool, so the shell route is closed here; also a process's /proc/…/environ, and a
        password read from the system's secret store (macOS `security find-generic-password -w`,
        Linux `secret-tool lookup`)
    S1  printing the environment, where API keys live once a program loads them: env / printenv / bare
        set / export -p / declare -p (with or without a secret-named variable), PowerShell env: listings,
        os.environ / process.env dumps, and expanding a secret-named variable ($OPENAI_API_KEY,
        ${X_TOKEN}, $env:…, %…%) — `test -n "$X"` is fine
  The shell is parsed the way the shell runs it: every line is its own command, and ( ) < > split words
  as they do in bash; git behind a wrapper (`env git …`, `xargs git …`, `flock f git …`) is checked like
  bare git; a command handed to a nested shell (`bash -c "…"`, `pwsh -Command "…"`, `cmd /c …`,
  `flock -c "…"`) or run by a substitution (`$(…)`, backticks, `<(…)`) is checked like a command of its
  own. A heredoc is read the way bash reads it: the body of `cat <<'EOF'` (quoted word — the
  commit-message idiom) is inert text and is skipped; in `cat <<EOF` (bare word) bash still runs $(…)
  and backticks and expands $VAR, so those are checked; a heredoc fed to anything else is code and
  stays in; a `<<` inside quotes or a comment is no heredoc at all. In a PowerShell (or cmd) command a
  backslash is a path separator, not an escape. The last-resort checks also read the text with the
  escapes a program decodes (`\x67it`, `\147it` → git).

Also records each file the session edits in <state>/touched-<session_id>, so the Stop
gate checks only what THIS session changed (another session in the same folder is
never blamed for someone else's broken link).

An unparseable payload is let through (exit 0) and logged: a guard that cannot read its
input must not freeze all work — but it must not be silent either.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
from pathlib import Path

for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CODE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CODE_ROOT / "tools"))
from budget import GATES as BUDGET_FILE, always_loaded, budget, budget_in, import_closure, kind as loaded_kind  # noqa: E402
from context_graph import OWNER_STATUSES, PENDING_STATUSES, status_of, type_for_path  # noqa: E402
from redact import MARKER_RE  # noqa: E402

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}
LEDGER = "memory/approvals.md"
EP_INDEX = "memory/episodes/INDEX.md"
# The launcher's note of the interpreter it found (.claude/hooks/py.sh): pointed at another program, every hook
# would run that program instead of Python.
ENGINE_PYTHON_NOTE = ".git/engine-python"
# git's own configuration — the repository's, a worktree's, a submodule's: core.hooksPath and include.path live there,
# so a hand-written line switches the commit checks off (review 2026-10-22 H3). As a path an edit names, and inside a
# shell command.
GIT_CONFIG_RE = re.compile(r"(?:^|/)\.git/(?:[^/]+/)*config(?:\.worktree)?$", re.IGNORECASE)
GIT_CONFIG_IN_CMD_RE = re.compile(r"\.git[\\/]+(?:[\w.-]+[\\/]+)*config(?:\.worktree)?(?![\w.-])", re.IGNORECASE)
FOREIGN_EPISODE_MUTABLE = {"needs_reconcile", "reconciled_at", "reconciled_by"}
CREATABLE = PENDING_STATUSES  # a new approvable document may only start in a "waiting for the owner" status
# Secret-bearing paths. `.env.example` / `.sample` / `.template` are documentation, not secrets.
SECRET_RE = re.compile(
    r"(?<![\w.-])\.env(?![\w-])(?!\.(?:example|sample|template)\b)"
    r"|\.(?:pem|key|p12|pfx|jks)\b"
    r"|(?<![\w-])(?:secrets|\.ssh|\.aws)[\\/]"
    r"|\b(?:credentials|serviceAccountKey)[\w.-]*\.json\b"
    r"|\bid_(?:rsa|ed25519|ecdsa)\b"
    r"|(?<![\w.-])(?:\.npmrc|\.netrc|_netrc|\.git-credentials|\.pgpass)\b"  # tokens live here too, often in $HOME
    r"|/proc/[^\s]*environ\b",  # a running program's environment, its API keys included (Linux; any depth)
    re.IGNORECASE)
# Commands that can name a secret path without reading or staging its content.
SECRET_SAFE_CMDS = {"ls", "dir", "stat", "test", "[", "echo", "printf", "test-path"}
# SECRET_RE reads only the literal words of a command, so a name the shell makes up — a glob (`.en?`, `.e*`,
# `.e[n]v`), a brace list (`.en{v,x}`) or a command substitution (`$(printf .en)v`) — passes B4 unseen
# (Claude Security F1, 2026-10-28). computed_secret_path() matches such a word against these samples, which mirror
# SECRET_RE's file kinds and secret directories; the guard drill proves both the literal and the computed path.
SECRET_FILE_SAMPLES = (".env", ".env.local", "x.pem", "x.key", "x.p12", "x.pfx", "x.jks", "credentials.json",
                       "serviceaccountkey.json", "id_rsa", "id_ed25519", "id_ecdsa", ".npmrc", ".netrc", "_netrc",
                       ".git-credentials", ".pgpass")
SECRET_DIRS = ("secrets", ".ssh", ".aws")
FROZEN = {"intent": {"accepted"}, "spec": {"approved", "superseded"},
          "plan": {"approved", "in-progress", "done"}, "adr": {"accepted", "rejected", "superseded"}}
REOPENABLE = {"intent": {"accepted"}, "spec": {"approved"}, "plan": {"approved", "in-progress", "done"}}
PLAN_MOVES = {("approved", "in-progress"), ("in-progress", "done")}
DEVIATIONS_HEADING = "## გადახრები"

READ_ONLY_CMDS = {"cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "wc", "ls", "stat",
                  "file", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "bat", "jq", "sed",
                  "get-content", "gc", "type", "select-string", "sls", "get-item", "test-path"}
GIT_SAFE_SUBCMDS = {"add", "commit", "diff", "log", "show", "status", "blame", "grep", "ls-files"}
SEGMENT_OPS = {";", "&&", "||", "|", "&", "\n"}
# Punctuation shlex splits off. ( ) < > are metacharacters in bash: `(git commit -n) >/dev/null` is the command
# `git commit -n`, whatever word the ) or the redirection is glued to.
PUNCTUATION = ";&|()<>"
# One fused run of operators (`;>`, `(>`, `&&>`) split into its pieces, so the separator ends the command and the
# redirect piece is skipped like any redirect (review C4). Separator runs first, then the redirect operators.
PUNCT_PIECE_RE = re.compile(r"[;&|()]+|&>>?|>>?&?|<<?<?|<&|>\||<>|[<>]")
SEPARATOR_CHARS = set(";&|()")  # a token made only of these ends a command; < > only redirect
# A redirection operator on its own (`>`, `2>&1` gives `2`, `>&`, `1`): it and its target are not the command.
REDIRECT_RE = re.compile(r"^(?:<<?<?|>>?|>&|<&|&>>?|>\||<>)$")
# Commands that run another command: `env git commit -n` is a git commit.
WRAPPERS = {"env", "command", "builtin", "exec", "nice", "nohup", "time", "sudo", "doas", "xargs",
            "stdbuf", "timeout", "winpty", "call", "start-process",
            "caffeinate", "arch", "setsid", "ionice", "flock", "script", "chrt", "taskset", "runuser"}  # macOS, Linux
# Shells that take a whole command line as one argument, and the flag that introduces it.
NESTED_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "pwsh", "powershell", "cmd"}
NESTED_FLAG_RE = re.compile(r"^(?:-[A-Za-z]*c|-command|/c|/k)$", re.IGNORECASE)
# Programs whose -c takes a command line and runs it through a shell: `flock /tmp/l -c "…"`, `script -c "…" log`,
# `su -c "…"`.
C_RUNNERS = {"flock", "script", "su", "runuser"}
# Where the command line handed on is PowerShell or cmd: there a backslash separates folders, it escapes nothing.
PS_RUNNERS = {"pwsh", "powershell", "cmd", "iex", "invoke-expression", "invoke-command"}
# Shell grammar in front of a command word: the command still runs. `for …; do git commit -n; done`,
# `if …; then …`, `! …` and `{ …; }` got past the guard until 2026-10-07. A subshell `( … )`, a case branch
# `x) …` and a function body `f() { …; }` need nothing here: ( and ) end a command in segments().
SHELL_KEYWORDS = {"!", "{", "do", "then", "else", "elif", "if", "while", "until"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
# git accepts any unambiguous prefix of a long option; `--no-ve` is still ambiguous (--no-verbose).
NO_VERIFY_RE = re.compile(r"^--no-veri(?:f|fy)?$", re.IGNORECASE)
# The git subcommands that run hooks `--no-verify` skips (pre-commit, commit-msg, pre-merge-commit, pre-push,
# pre-rebase, applypatch-msg), and their options that take the next word as their value. An optional value must
# be glued on (`-S<keyid>`, `--gpg-sign=<keyid>`, `-uno`), so those options never take the next word:
# `git commit -S -n` skips the hooks.
HOOK_VALUE_OPTS = {
    "commit": {"-m", "-F", "-C", "-c", "-t", "--message", "--file", "--template", "--author", "--date", "--fixup",
               "--squash", "--cleanup", "--trailer", "--reuse-message", "--reedit-message", "--pathspec-from-file"},
    "merge": {"-m", "-F", "-s", "-X", "--message", "--file", "--strategy", "--strategy-option", "--into-name"},
    "push": {"-o", "--push-option", "--repo", "--receive-pack", "--exec"},
    "rebase": {"-s", "-X", "-x", "--onto", "--strategy", "--strategy-option", "--exec"},
    "pull": {"-s", "-X", "--strategy", "--strategy-option", "--depth", "--deepen", "--shallow-since",
             "--shallow-exclude", "--upload-pack"},
    "am": {"--directory", "--exclude", "--include", "--patch-format", "--resolvemsg"},
}
GLUED_ONLY = {"commit": set("Su"), "merge": {"S"}, "push": set(), "rebase": {"S"}, "pull": {"S"}, "am": {"S"}}
# A word the shell makes up before git sees it — an expansion ($…, backticks), a glob or brace list at its start, a
# PowerShell splat — may turn out to be any option: `git commit -m x $(printf -- -n)`, `git push origin $(echo +main)`.
HIDDEN_WORD_RE = re.compile(r"[$`]|^[*?\[{]|^@\w")
# A char the shell expands or computes, ANYWHERE in the word — for an option name `--no-ve{rify,rify}` or
# `--for{ce,ce}`, where the brace list is not at the start (review S3).
COMPUTED_RE = re.compile(r"[$`*?\[{]")
UNQUOTED_SUB = "$__SUB__"  # mask_substitutions(): word splitting may break an unquoted $(…) into several words
MAX_NESTING = 3
HOOK_SUBCMDS = {"commit", "push", "merge", "rebase", "pull", "am"}  # git subcommands that run hooks (review S6)
PS_ENV_BRACE_RE = re.compile(r"\$\{env:([A-Za-z_]\w*)", re.IGNORECASE)
# A heredoc operator and its word: bash ends the body at a line equal to the word with its quotes taken out, and a
# quote anywhere in the word (<<'EOF', <<"EOF", <<E'OF', <<\EOF) leaves the body unexpanded.
HEREDOC_OP_RE = re.compile(r"<<(-?)[ \t]*((?:[^\s;&|()<>'\"\\]|\\.|'[^'\n]*'|\"[^\"\n]*\")+)")
CAT_BEFORE_RE = re.compile(r"(?:^|[\s;&|(`])cat[ \t]+$")  # the heredoc is cat's: `cat <<EOF`, `$(cat <<'EOF'`
BASH_VAR_RE = re.compile(r"(?<!\\)\$\{?([A-Za-z_]\w*)")  # what bash expands in an unquoted heredoc body
# Escapes printf, echo -e and sed decode before the text reaches a shell: \x67 \147 \o147 \d103 \u0067, and a
# backslash-newline that only continues a line.
ESCAPE_RE = re.compile(r"\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{4})|0?([0-7]{1,3})|o([0-7]{1,3})|d(\d{1,3})|(\n)|(.))",
                       re.S)
ANSI_C_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
ANSI_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
                  "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
# A shell reading its program from stdin may receive text a later pipeline stage rewrote
# (`printf x | sed 's/x/git commit -n/' | sh`), so with such a shell the phrase alone is enough.
HOOK_SKIP_RE = re.compile(r"\bgit\b.*?\bcommit\b.*?(?:\s-[A-Za-z]*n|--no-veri)|\bgit\b.*?--no-veri", re.S | re.I)
# S1 — a variable is secret-named when one `_`-separated part of its name is one of these (OPENAI_API_KEY,
# GITHUB_TOKEN, DB_PASS); PWD, SSH_AUTH_SOCK and GIT_ASKPASS are not.
SECRET_NAME_PARTS = {"KEY", "KEYS", "APIKEY", "TOKEN", "TOKENS", "SECRET", "SECRETS", "PASSWORD", "PASSWORDS",
                     "PASSWD", "PASS", "CREDENTIAL", "CREDENTIALS", "PAT"}
VAR_REF_RE = re.compile(r"\$env:([A-Za-z_]\w*)|\$\{?([A-Za-z_]\w*)|%([A-Za-z_]\w*)%", re.IGNORECASE)
# S1 — bash indirect expansion: `${!v}` reads the variable whose NAME is held in v, and `${!pre*}`/`${!pre@}` list
# variable names. VAR_REF_RE needs a name character right after `${`, so `${!…}` slips past it; a command can assign a
# secret variable's name to v (`v=AWS_SECRET_ACCESS_KEY`) and then print the value with `${!v}` (Claude Security F2).
INDIRECT_RE = re.compile(r"\$\{!")
PS_ENV_RE = re.compile(r"(?i)\b(?:get-childitem|gci|dir|ls|get-item|gi|get-content|gc)\b(?:\s+-\w+)*\s+env:")
CODE_ENV_DUMP_RE = re.compile(r"(?i)\[(?:system\.)?environment\]::getenvironmentvariables\b"
                              r"|\bos\.environ\b(?!\s*(?:\[|\.get\b))|\bprocess\.env\b(?!\s*[.\[])")
CODE_ENV_READ_RE = re.compile(r"""(?i)(?:\bos\.environ\s*\[|\bos\.environ\.get\(|\bos\.getenv\(|\bprocess\.env\[|"""
                              r"""\]::getenvironmentvariable\()\s*['"]?([A-Za-z_]\w*)|\bprocess\.env\.([A-Za-z_]\w*)""")
TEST_WORDS = {"test", "[", "[["}
# Commands that show code without running it: `grep -rn os.environ src/` is a search, not a dump.
QUOTING_WORDS = READ_ONLY_CMDS | {"echo", "printf", "git", "findstr", "ag", "ack"}
ENV_VALUE_OPTS = {"-u", "--unset", "-C", "--chdir"}


def root_dir() -> Path:
    for cand in (os.environ.get("GUARD_ROOT"), os.environ.get("CLAUDE_PROJECT_DIR")):
        if cand:
            return Path(cand).resolve()
    return CODE_ROOT


def state_dir() -> Path:
    p = Path(os.environ.get("GUARD_STATE_DIR") or os.environ.get("EPISODIC_STATE_DIR")
             or (Path.home() / ".claude" / "session-state"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def log(msg: str) -> None:
    try:  # errors="replace": a lone surrogate from $'\udxxx' must not raise here — a crash would let the call run
        with (state_dir() / "guard.log").open("a", encoding="utf-8", errors="replace") as fh:
            fh.write(msg + "\n")
    except OSError:
        pass


def block(code: str, msg: str) -> int:
    print(f"GUARD[{code}]: {msg}", file=sys.stderr)
    log(f"BLOCK {code}: {msg}")
    return 2


# ── file edits ───────────────────────────────────────────────────────────────
def resolved(file_path: str, cwd: str | None, root: Path) -> Path:
    p = Path(file_path)
    if not p.is_absolute():
        p = Path(cwd or root) / p
    return p.resolve()


def rel_path(file_path: str, cwd: str | None, root: Path) -> str | None:
    """The path inside the project (posix), or None outside it. Another name for the project folder counts as the
    project: Windows reaches the same folder as \\\\localhost\\c$\\…, //127.0.0.1/c$/… or \\\\?\\C:\\… — the start
    of the path differs, the folders after it do not (review A5)."""
    p = resolved(file_path, cwd, root)
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        pass
    tail, root_tail = p.parts[1:], root.parts[1:]
    if p.anchor.lower() != root.anchor.lower() and root_tail and len(tail) > len(root_tail) \
            and [s.lower() for s in tail[:len(root_tail)]] == [s.lower() for s in root_tail]:
        return "/".join(tail[len(root_tail):])
    return None


def read_norm(p: Path) -> str | None:
    """A file read with every newline form (CRLF and a lone CR) flattened — the graph reads it the same way,
    so a status line the guard splits on must not be hidden behind a lone CR (review S10)."""
    return p.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n") \
        if p.exists() else None


def simulate(tool: str, ti: dict, before: str | None) -> str | None:
    """Content of the file after the tool call, or None if it cannot be computed."""
    if tool == "Write":
        return str(ti.get("content") or "").replace("\r\n", "\n").replace("\r", "\n")
    if before is None:
        return None
    text = before
    edits = ti.get("edits") if tool == "MultiEdit" else [ti]
    for e in edits or []:
        old = str(e.get("old_string") or "").replace("\r\n", "\n").replace("\r", "\n")
        new = str(e.get("new_string") or "").replace("\r\n", "\n").replace("\r", "\n")
        if not old or old not in text:
            return None  # the tool itself will fail on this edit
        text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
    return text


def without_fm_keys(text: str, keys: set[str]) -> str:
    """Text with the given frontmatter lines removed (body untouched)."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return text
    out = [lines[0]]
    i = 1
    while i < len(lines) and lines[i].strip() != "---":
        m = re.match(r"^([A-Za-z_][\w-]*):", lines[i])
        if not (m and m.group(1) in keys):
            out.append(lines[i])
        i += 1
    return "\n".join(out + lines[i:])


def normalise_plan(text: str) -> tuple[str, str]:
    """(plan without its deviations section and with all boxes unticked, deviations section)."""
    text = re.sub(r"(?m)^(\s*[-*] )\[[xX]\]", r"\1[ ]", text)
    idx = text.find("\n" + DEVIATIONS_HEADING)
    if idx == -1:
        return text.rstrip(), ""
    return text[:idx].rstrip(), text[idx:].strip()


def check_edit(tool: str, ti: dict, payload: dict, root: Path) -> int:
    path = ti.get("file_path") or ti.get("notebook_path") or ""
    if not path:
        return 0
    rel = rel_path(path, payload.get("cwd"), root)
    # Outside the project the rules that protect any file still hold (review A5): a marker written anywhere destroys a
    # real value, a key file is a key file in any folder, and a ledger is the owner's in any copy of the project.
    where = rel if rel is not None else resolved(path, payload.get("cwd"), root).as_posix()
    if rel is not None:
        record_touched(payload.get("session_id") or "", root / rel)
    if MARKER_RE.search(new_content(tool, ti)):
        return block("S2", f"{where}: ჩასაწერ ტექსტში დგას დაფარვის ნიშანი — sentinel-მა ამ ადგილას ნამდვილი საიდუმლო "
                           "დაგიმალა, და ნიშნის ჩაწერა ფაილში ნამდვილ მნიშვნელობას სამუდამოდ წაშლიდა. შეცვალე მხოლოდ "
                           "სხვა ხაზები (Edit), საიდუმლოიან ხაზს ნუ შეეხები; თუ ის ხაზიც უნდა შეიცვალოს, სთხოვე მფლობელს.")
    if SECRET_RE.search(where) or (rel is None and SECRET_RE.search(path.replace("\\", "/"))):
        return block("G6", f"{where} საიდუმლოების ფაილია — აგენტი მას არ წერს და არ კითხულობს (ADR-0007). "
                           "ცვლადის სახელი და PLACEHOLDER ჩაწერე .env.example-ში; ნამდვილ მნიშვნელობას მფლობელი ჩასვამს.")
    if GIT_CONFIG_RE.search(where):
        return block("G8", f"{where} git-ის საკუთარი კონფიგურაციაა: core.hooksPath და include იქ ინახება, და ხელით "
                           "ჩაწერილი ხაზი commit-ის შემოწმებებს თიშავს. პარამეტრი `git config`-ით შეცვალე — ის ჯერ "
                           "მფლობელს ეკითხება.")
    low = where.lower()
    if low == LEDGER or (rel is None and low.endswith("/" + LEDGER)):
        return block("G1", f"{LEDGER} ჩაწერა მხოლოდ მფლობელის `/approve`-ით შეიძლება (tools/approve.py) — ამ "
                           "პროექტში თუ მის სხვა ასლში. Only the owner's /approve writes the approval ledger.")
    if rel is None:
        return 0
    if low == EP_INDEX.lower():
        return block("G2", "memory/episodes/INDEX.md გენერირებულია — გაუშვი "
                           "`bash .claude/hooks/py.sh .claude/hooks/episodic.py index`.")
    if low == ENGINE_PYTHON_NOTE:
        return block("G2", f"{ENGINE_PYTHON_NOTE} გენერირებულია — მას მხოლოდ `.claude/hooks/py.sh` წერს (ნაპოვნი Python-ის "
                           "გზა). სხვა პროგრამაზე მითითება ყველა hook-ს Python-ის ნაცვლად იმ პროგრამით გაუშვებდა.")
    over = check_budget(tool, ti, root, rel)
    if over:
        return over
    if fnmatch.fnmatchcase(low, "memory/episodes/ep-*.md"):
        return check_episode(tool, ti, payload, root, rel)
    typ = type_for_path(rel, ignore_case=True)  # Windows: ADR-0001 and adr-0001 are the same file
    if typ not in FROZEN:
        return 0
    return check_approvable(tool, ti, root / rel, typ)


def check_budget(tool: str, ti: dict, root: Path, rel: str) -> int:
    """G7: what every session loads must not grow past its byte budget; shrinking always passes (gbrain's
    rule), and only the owner raises the budget."""
    low = rel.lower()
    if low != BUDGET_FILE and not loaded_kind(rel) and low not in import_closure(root) | {"claude.md"}:
        return 0
    before = read_norm(root / rel)
    after = simulate(tool, ti, before)
    if after is None:
        return 0  # the edit cannot apply; the tool reports that itself
    if low == BUDGET_FILE:
        b0, b1 = budget_in(before or ""), budget_in(after)
        if b0 is not None and (b1 is None or b1 > b0):
            return block("G7", f"{rel}: ბიუჯეტს ({b0:,} ბაიტი ყოველთვის ჩატვირთულ ტექსტზე) მხოლოდ მფლობელი ზრდის ან "
                               "აუქმებს — `/approve budget <N>`. შემცირება შეიძლება; სხვა ცვლილებისთვის max_bytes "
                               "უცვლელი დატოვე.")
        return 0
    cap = budget(root)
    if cap is None:
        return 0  # no budget configured: nothing to hold (the gate says so at commit)
    now = sum(always_loaded(root).values())
    files = always_loaded(root, {rel: after})
    total = sum(files.values())
    if total <= cap or total <= now:
        return 0
    largest = " · ".join(f"{f} {n:,}" for f, n in sorted(files.items(), key=lambda kv: -kv[1])[:3])
    return block("G7", f"{rel}: ყოველ სესიაში ჩატვირთული ტექსტი {now:,}-დან {total:,} ბაიტამდე გაიზრდებოდა — ბიუჯეტი "
                       f"{cap:,}-ია, ზედმეტი {total - cap:,}. შეამოკლე ეს ან სხვა ყოველთვის ჩატვირთული ფაილი (უდიდესები: "
                       f"{largest}): დეტალი გადაიტანე ფაილში, რომელიც მხოლოდ საჭიროებისას იკითხება, და აქ ერთხაზიანი "
                       "მითითება დატოვე. შემცირება ყოველთვის გადის; ბიუჯეტს მხოლოდ მფლობელი ზრდის — `/approve budget "
                       "<N>`. სია: `bash .claude/hooks/py.sh tools/budget.py`.")


def check_episode(tool: str, ti: dict, payload: dict, root: Path, rel: str) -> int:
    sid = (payload.get("session_id") or "")[:8].lower()
    stem = Path(rel).stem.lower()
    if sid and stem.endswith(sid):
        return 0
    p = root / rel
    before = read_norm(p)
    after = simulate(tool, ti, before)
    if before is not None and after is not None and \
            without_fm_keys(before, FOREIGN_EPISODE_MUTABLE) == without_fm_keys(after, FOREIGN_EPISODE_MUTABLE):
        return 0
    return block("G3", f"{rel} სხვა სესიის ეპიზოდია — ისტორია მხოლოდ ემატება. შეგიძლია შეცვალო მხოლოდ "
                       f"{', '.join(sorted(FOREIGN_EPISODE_MUTABLE))}; ახალი ფაქტი ჩაწერე შენი სესიის ეპიზოდში "
                       "ან memory/LESSONS.md-ში.")


def check_approvable(tool: str, ti: dict, p: Path, typ: str) -> int:
    before = read_norm(p)
    after = simulate(tool, ti, before)
    if after is None:
        return 0  # the edit cannot apply; the tool will report that itself
    s0, s1 = status_of(before), status_of(after)
    name = p.name
    owner_only = OWNER_STATUSES.get(typ, set())
    if before is None:
        if s1 and s1 not in CREATABLE[typ]:
            return block("G4", f"{name}: ახალი დოკუმენტი სტატუსით `{s1}` ვერ შეიქმნება — დაიწყე "
                               f"`{sorted(CREATABLE[typ])[0]}`-ით; დამტკიცება მხოლოდ მფლობელის `/approve`-ით.")
        return 0
    if s1 != s0 and s1 in owner_only:
        return block("G4", f"{name}: სტატუსს `{s1}` მხოლოდ მფლობელი ანიჭებს (`/approve`). "
                           "შეგიძლია შეახსენო მფლობელს, თავად ვერ დაამტკიცებ.")
    if s0 not in FROZEN[typ]:
        if typ == "plan" and s1 in ("in-progress", "done"):
            return block("G4", f"{name}: გეგმა `{s0}` სტატუსიდან პირდაპირ `{s1}`-ზე ვერ გადავა — ჯერ მფლობელის "
                               "`/approve plan <N>` უნდა მოხდეს.")
        return 0
    # before is frozen
    if typ == "adr":
        return block("G5", f"{name}: გადაწყვეტილი ADR (`{s0}`) არ იცვლება. დაწერე ახალი ADR ველით "
                           f"`supersedes: \"[[{p.stem}]]\"` და სთხოვე მფლობელს `/approve`.")
    if s1 == "draft" and s0 in REOPENABLE.get(typ, set()):
        if without_fm_keys(before, {"status", "updated"}) == without_fm_keys(after, {"status", "updated"}):
            return 0  # a clean reopen: status back to draft, nothing else touched
        return block("G5", f"{name}: ხელახლა გახსნა (status → draft) ცალკე ნაბიჯია — ჯერ მხოლოდ სტატუსი "
                           "შეცვალე, შინაარსი შემდეგ ედიტში.")
    if typ == "plan":
        if s1 != s0 and (s0, s1) not in PLAN_MOVES:
            return block("G5", f"{name}: დამტკიცებული გეგმის სტატუსი `{s0}` → `{s1}` არ დაიშვება "
                               "(დაშვებულია approved→in-progress→done ან draft-ზე დაბრუნება).")
        b_main, b_dev = normalise_plan(without_fm_keys(before, {"status", "updated"}))
        a_main, a_dev = normalise_plan(without_fm_keys(after, {"status", "updated"}))
        if b_main == a_main and a_dev.startswith(b_dev):
            return 0
        return block("G5", f"{name}: დამტკიცებულ გეგმაში შეიძლება მხოლოდ ჩამონათვალის მონიშვნა, ჩანაწერის დამატება "
                           f"სექციაში „{DEVIATIONS_HEADING}“ და სტატუსის წინ წაწევა. სხვა ცვლილებისთვის გახსენი "
                           "(status: draft) და სთხოვე მფლობელს ხელახლა დამტკიცება.")
    return block("G5", f"{name}: დამტკიცებული დოკუმენტი (`{s0}`) გაყინულია. შესაცვლელად ჯერ გახსენი "
                       "(მხოლოდ status: draft), მერე შეცვალე და სთხოვე მფლობელს ხელახლა `/approve`.")


def new_content(tool: str, ti: dict) -> str:
    """The text an edit tool is about to put into the file."""
    if tool == "Write":
        return str(ti.get("content") or "")
    if tool == "NotebookEdit":
        return str(ti.get("new_source") or "")
    if tool == "MultiEdit":
        return "\n".join(str(e.get("new_string") or "") for e in ti.get("edits") or [])
    return str(ti.get("new_string") or "")


def record_touched(sid: str, p: Path) -> None:
    if not sid:
        return
    try:
        with (state_dir() / f"touched-{sid}").open("a", encoding="utf-8") as fh:
            fh.write(str(p) + "\n")
    except OSError:
        pass


# ── shell commands ───────────────────────────────────────────────────────────
def heredoc_body(cmd: str, i: int, word: str, tabs: bool, quoted: bool) -> tuple[str, int] | None:
    """The body that starts at cmd[i] and the index past its terminator line, or None when no line ends it (bash
    would read to the end; the guard then keeps every line as a command — review A2). In a body with a bare word a
    backslash-newline joins two lines before the terminator is looked for, as bash does (`E\\⏎O\\⏎F` is EOF)."""
    body: list[str] = []
    while i < len(cmd):
        line = ""
        while True:  # one logical line
            j = cmd.find("\n", i)
            part = cmd[i:] if j == -1 else cmd[i:j]
            i = len(cmd) if j == -1 else j + 1
            if not quoted and (len(part) - len(part.rstrip("\\"))) % 2 and i < len(cmd):
                line += part[:-1]
                continue
            line += part
            break
        if (line.lstrip("\t") if tabs else line).rstrip("\r") == word:
            return "\n".join(body), i
        body.append(line)
    return None


def heredocs(cmd: str) -> tuple[str, list[tuple[bool, str]]]:
    """Read cmd the way bash does and take out the body of every `cat <<WORD` heredoc.

    Returns the command without those bodies and, for each one, (quoted, body). A quoted WORD leaves the body inert
    text; with a bare WORD bash still runs $(…) and backticks in it and expands $VAR, so the caller checks those. A
    heredoc fed to anything else (`py - <<EOF`, `bash <<EOF`) is code and stays in the text. A `<<` inside quotes or a
    comment is no operator: the lines after `# cat <<EOF` or `echo "cat <<EOF"` are commands (review A2)."""
    out: list[str] = []
    bodies: list[tuple[bool, str]] = []
    pending: list[tuple[str, bool, bool, bool]] = []  # (word, <<-, quoted, cat's)
    stack: list[str] = []  # open contexts: '"' double quotes · ')' a $( or ( · '`' backticks
    i, n = 0, len(cmd)
    while i < n:
        c, ctx = cmd[i], (stack[-1] if stack else "")
        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c == "\n" and ctx != '"':
            out.append(c)
            i += 1
            for word, tabs, quoted, cat in pending:
                found = heredoc_body(cmd, i, word, tabs, quoted)
                if found is None:
                    break  # unterminated: everything after stays in as commands
                body, end = found
                if cat:
                    bodies.append((quoted, body))
                else:
                    out.append(cmd[i:end])
                i = end
            pending = []
            continue
        if ctx == '"':
            if c == '"':
                stack.pop()
            elif cmd.startswith("$(", i):
                stack.append(")")
                out.append("$")
                i += 1
                c = "("
            elif c == "`":
                stack.append("`")
            out.append(c)
            i += 1
            continue
        if c == "'":
            j = cmd.find("'", i + 1)
            j = n if j == -1 else j + 1
            out.append(cmd[i:j])
            i = j
            continue
        if cmd.startswith("$'", i):
            m = ANSI_C_RE.match(cmd, i)
            j = m.end() if m else i + 2
            out.append(cmd[i:j])
            i = j
            continue
        if c == '"':
            stack.append('"')
        elif c == "`":
            if ctx == "`":
                stack.pop()
            else:
                stack.append("`")
        elif c == "(":
            stack.append(")")
        elif c == ")" and ctx == ")":
            stack.pop()
        elif c == "#" and (i == 0 or cmd[i - 1] in " \t\n;&|()`"):
            j = cmd.find("\n", i)
            j = n if j == -1 else j
            out.append(cmd[i:j])  # a comment: kept as text, normalize() drops it later
            i = j
            continue
        elif cmd.startswith("<<", i) and not cmd.startswith("<<<", i) and (i == 0 or cmd[i - 1] != "<"):
            m = HEREDOC_OP_RE.match(cmd, i)
            if m:
                raw = m.group(2)
                word = re.sub(r"\\(.)", r"\1", re.sub(r"'([^']*)'|\"([^\"]*)\"", lambda q: q.group(1) or q.group(2) or "", raw))
                cat = bool(CAT_BEFORE_RE.search("".join(out[-40:])))
                pending.append((word, m.group(1) == "-", any(ch in raw for ch in "'\"\\"), cat))
                out.append(m.group(0))
                i = m.end()
                continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def unescaped(text: str) -> str:
    """The text as a program that decodes escapes passes it on: `\\x67it`, `\\147it` and `\\git` are all git to
    printf %b, echo -e or sed (ECC corpus, 2026-10-19), and a backslash-newline only continues the line."""
    def one(m: re.Match[str]) -> str:
        x, u, octal, o, d, newline, other = m.groups()
        try:
            for value, base in ((x, 16), (u, 16), (octal, 8), (o, 8), (d, 10)):
                if value:
                    return chr(int(value, base))
        except (ValueError, OverflowError):
            return ""
        return "" if newline else ANSI_C_ESCAPES.get(other, other)
    return ESCAPE_RE.sub(one, text)


def quoted_end(cmd: str, i: int) -> int:
    """Index just past the quoted string that starts at cmd[i] (' or ")."""
    if cmd[i] == "'":
        j = cmd.find("'", i + 1)
        return len(cmd) if j == -1 else j + 1
    j = i + 1
    while j < len(cmd) and cmd[j] != '"':
        if cmd[j] == "\\":
            j += 2
        elif cmd[j] == "$" and cmd.startswith("(", j + 1):  # a message may hold $(echo "nested") — one unit
            c = close_paren(cmd, j + 2)
            j = len(cmd) if c is None else c + 1
        elif cmd[j] == "`":
            k = cmd.find("`", j + 1)
            j = len(cmd) if k == -1 else k + 1
        else:
            j += 1
    return min(j + 1, len(cmd))


def ansi_c(body: str) -> str:
    """bash's $'…' string, decoded and re-quoted in double quotes, which shlex understands."""
    def esc(m: re.Match[str]) -> str:
        s = m.group(1)
        try:  # `$'\x'`, `$'\8'` or `$'\UFFFFFFFF'` must not crash the guard: a crash lets the call through
            if s[0] in "xuU" and len(s) > 1:
                return chr(int(s[1:], 16))
            if s[0] in "01234567":
                return chr(int(s, 8))
        except (ValueError, OverflowError):
            pass
        return ANSI_C_ESCAPES.get(s, "\\" + s)
    text = re.sub(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)", esc, body, flags=re.S)
    return '"' + re.sub(r'(["\\$`])', r"\\\1", text) + '"'


def normalize(cmd: str) -> str:
    """Rewrite the bash quoting shlex reads differently: ANSI-C `$'git'` becomes "git", and an unquoted `#`
    that starts a word drops the rest of its line (a comment), while `foo#bar` stays one word — shlex would
    have ended the line there and hidden `echo foo#bar; git commit -n` (ECC corpus, 2026-10-07)."""
    out, i, n = [], 0, len(cmd)
    esc = False  # the previous source character was backslash-escaped: a `#` after it is not a comment (C6)
    while i < n:
        c = cmd[i]
        if c == "\\":
            out.append(cmd[i:i + 2])
            i += 2
            esc = True
            continue
        elif c in "'\"":
            j = quoted_end(cmd, i)
            out.append(cmd[i:j])
            i = j
        elif cmd.startswith("$'", i):
            m = ANSI_C_RE.match(cmd, i)
            out.append(ansi_c(m.group(1)) if m else c)
            i = m.end() if m else i + 1
        elif c == "#" and not esc and (i == 0 or cmd[i - 1] in " \t\n;&|()"):
            j = cmd.find("\n", i)
            i = n if j == -1 else j  # the newline stays: it still ends the command
        else:
            out.append(c)
            i += 1
        esc = False
    return "".join(out)


def close_paren(cmd: str, j: int) -> int | None:
    """Index of the `)` that closes a `$(` whose body starts at j — skipping quoted text, and the `)` that ends
    a case pattern (`$(case x in x) …;; esac)`), which bash does not count."""
    depth, cases = 1, 0
    while j < len(cmd):
        c = cmd[j]
        boundary = j == 0 or cmd[j - 1] in " \t\n;&|("
        if c == "\\":
            j += 2
            continue
        if c in "'\"":
            j = quoted_end(cmd, j)
            continue
        if boundary and re.match(r"case\b", cmd[j:]):
            cases += 1
        elif boundary and re.match(r"esac\b", cmd[j:]):
            cases = max(0, cases - 1)
        elif c == "(":
            depth += 1
        elif c == ")" and not cases:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def substitutions(cmd: str) -> list[str]:
    """Command lines inside $(…), <(…), >(…) and `…`: the shell runs them, so they are checked too."""
    out, i = [], 0
    while i < len(cmd):
        if cmd[i] in "$<>" and cmd.startswith("(", i + 1):
            j = close_paren(cmd, i + 2)
            out.append(cmd[i + 2:j] if j is not None else cmd[i + 2:])
            i = j + 1 if j is not None else len(cmd)
        elif cmd[i] == "`":
            j = cmd.find("`", i + 1)
            out.append(cmd[i + 1:j] if j != -1 else cmd[i + 1:])
            i = j + 1 if j != -1 else len(cmd)
        else:
            i += 1
    return [s for s in out if s.strip()]


def mask_dquote(span: str) -> str:
    """A double-quoted span with each $(…) / `…` inside it replaced by a quote-free marker: shlex then reads the
    whole span as one token even when the substitution holds its own quotes (review C10). A quoted substitution
    is an allowed option value; substitutions() still extracts and checks the real command from the raw text."""
    out, i, n = [], 0, len(span)
    while i < n:
        c = span[i]
        if c == "\\":
            out.append(span[i:i + 2])
            i += 2
        elif c in "$<>" and span.startswith("(", i + 1):
            j = close_paren(span, i + 2)
            out.append("QSUBQ")
            i = n if j is None else j + 1
        elif c == "`":
            k = span.find("`", i + 1)
            out.append("QSUBQ")
            i = n if k == -1 else k + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def mask_substitutions(text: str) -> str:
    """Each unquoted $(…), <(…), >(…) and `…` as one opaque word: its parens/backticks are not grammar to the line
    around it (`git $(echo commit) -n` is still one command), and a backtick body holds a space that would otherwise
    split the word (``base64 `echo .e`nv`` is one word the shell builds into .env — Claude Security F1). substitutions()
    checks what runs inside either form."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            out.append(text[i:i + 2])
            i += 2
        elif c == "'":
            j = quoted_end(text, i)
            out.append(text[i:j])
            i = j
        elif c == '"':
            j = quoted_end(text, i)
            out.append(mask_dquote(text[i:j]))  # keep the "…" one token; a $(…) inside it is an allowed value (C10)
            i = j
        elif c in "$<>" and text.startswith("(", i + 1):
            j = close_paren(text, i + 2)
            out.append(UNQUOTED_SUB)
            i = len(text) if j is None else j + 1
        elif c == "`":  # the older substitution form, same as $(…): one opaque word (the space inside must not split it)
            k = text.find("`", i + 1)
            out.append(UNQUOTED_SUB)
            i = len(text) if k == -1 else k + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def segments(cmd: str, ps: bool = False) -> list[list[str]]:
    # A newline ends a command (backslash- and backtick-newline only continue the line), so each line
    # is its own segment: `echo hi⏎git commit -n` must not hide the commit behind `echo`. ( and ) end a command
    # too, glued to a word or not: `(git commit -am x -n) >/dev/null` is `git commit -am x -n` (review A4).
    text = normalize(cmd.replace("\r", "")).replace("\\\n", "").replace("`\n", " ").replace("\n", " ; ")
    text = mask_substitutions(text)
    punct = ";&|<>" if ps else PUNCTUATION  # PowerShell: ( ) group, they do not end a command (review S2/S12)
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=punct)
        lex.whitespace_split = True
        lex.commenters = ""  # normalize() has removed the real comments; `#` inside a word is a character
        tokens = list(lex)
    except ValueError:  # unbalanced quotes: split on blanks and operators, never on blanks alone
        tokens = re.findall(r"[;&|()<>]+|[^\s;&|()<>]+", text)
    tokens = [p for tok in tokens for p in (PUNCT_PIECE_RE.findall(tok)
                                            if tok and set(tok) <= set(";&|()<>") and len(tok) > 1 else [tok])]
    segs, cur = [], []
    for t in tokens:
        if ps:  # ( ) group a word in PowerShell: strip them so `(git)` / `& ('git')` read as the command (review S2/S12)
            t = t[2:] if t.startswith("@(") else (t[1:] if t.startswith("(") else t)
            t = t[:-1] if t.endswith(")") and "(" not in t else t
        # a token emptied by the PowerShell paren-strip above (a bare `(`/`)` grouping paren) is a segment
        # boundary, not an empty command word — so no `t and` guard here, or `( git commit -n )` would slip through
        if t in SEGMENT_OPS or set(t) <= SEPARATOR_CHARS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def first_word(seg: list[str]) -> tuple[str, int]:
    """The command this segment runs, past VAR=value prefixes and the shell grammar in front of it."""
    i = 0
    while i < len(seg):
        t = seg[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in SHELL_KEYWORDS:
            i += 1
        elif REDIRECT_RE.match(t):
            i += 2  # a redirection in front of the command, and its target: `>/dev/null git commit -n`
        elif t.isdigit() and i + 1 < len(seg) and REDIRECT_RE.match(seg[i + 1]):
            i += 3  # `2> err git commit -n`
        elif t == "function":
            i += 2  # `function f { …` — the name is not a command
        else:
            break
    if i >= len(seg):
        return "", i
    return Path(seg[i].lstrip("(")).name.lower().removesuffix(".exe"), i


def strip_redirects(args: list[str]) -> list[str]:
    """args without redirect operators and their targets: `> "$LOG"`, `2>$null`, `&>f` are not the command's
    own words (review C5/C8). shlex splits each operator into its own token, so a target is the token after it."""
    out, i = [], 0
    while i < len(args):
        if REDIRECT_RE.match(args[i]):
            i += 2
        elif args[i].isdigit() and i + 1 < len(args) and REDIRECT_RE.match(args[i + 1]):
            i += 3
        else:
            out.append(args[i])
            i += 1
    return out


def git_subcommand(seg: list[str], start: int) -> tuple[str, list[str], list[str]]:
    """(subcommand, its arguments, the config overrides given to git itself: -c / --config-env)."""
    i, confs = start + 1, []
    while i < len(seg):
        t = seg[i]
        if t in ("-C", "-c", "--config-env", "--git-dir", "--work-tree", "--namespace"):
            if t in ("-c", "--config-env") and i + 1 < len(seg):
                confs.append(seg[i + 1])
            i += 2
            continue
        if t.startswith("-"):
            if t.startswith("-c") and len(t) > 2:
                confs.append(t[2:])
            elif t.startswith("--config-env="):
                confs.append(t.split("=", 1)[1])
            i += 1
            continue
        return t.lower(), seg[i + 1:], confs
    return "", [], confs


def git_hides_option(sub: str, options: list[str], confs: list[str]) -> str | None:
    """A word in front of the subcommand that the guard cannot read, because the shell makes it up: the subcommand
    itself (`c=commit; git $c -n`, `git $(echo -c) core.hooksPath=… commit`), an option or a config key
    (`git -c $(echo core.hooksPath=…) commit`), or an unquoted $(…) given as a value, which word splitting can break
    into more options (`git -C $(printf '. -c core.hooksPath=…') commit`)."""
    if COMPUTED_RE.search(sub):  # COMPUTED_RE, not HIDDEN_WORD_RE: a glob/brace after the leading `-` is still a
        return sub               # computed word the guard cannot read — `-[c]` → -c, `p[u]sh` → push (review S6)
    for t in options:
        if UNQUOTED_SUB in t or (t.startswith("-") and COMPUTED_RE.search(t.partition("=")[0])):
            return t
    return next((c for c in confs if COMPUTED_RE.search(c.partition("=")[0])), None)


def hook_skip(sub: str, args: list[str]) -> tuple[str, str] | None:
    """(word, why) for the argument of a hook-running subcommand that skips its hooks — commit's -n (= --no-verify),
    alone or in a cluster (`-anm`): why "n" — or that the shell makes up where git reads options, so the guard cannot
    see it (`git commit -m x $(printf -- -n)`, `git push origin $(echo +main)`): why "hidden". A value given to an
    option may hide text (`-m "$(cat <<'EOF'` …), unless it is an unquoted $(…), which word splitting can break into
    options."""
    takes_value = HOOK_VALUE_OPTS[sub]
    letters = {o[1] for o in takes_value if len(o) == 2}
    i = 0
    while i < len(args):
        t, nxt = args[i], (args[i + 1] if i + 1 < len(args) else "")
        if t == "--" and sub != "push":  # only paths and commits from here on; a push refspec may still be +ref
            return None
        if t in takes_value:
            if UNQUOTED_SUB in nxt:
                return nxt, "hidden"
            i += 2
            continue
        if re.match(r"-[^-]", t):  # short options, perhaps clustered and with a glued value: -anm, -m"$(…)", -S<key>
            for k, ch in enumerate(t[1:], 1):
                if sub == "commit" and ch == "n":
                    return t, "n"
                if ch in letters or ch in GLUED_ONLY[sub]:  # the rest of the word is its value …
                    if UNQUOTED_SUB in t[k + 1:]:
                        return t, "hidden"
                    if k == len(t) - 1 and ch in letters:  # … or else the next word is
                        if UNQUOTED_SUB in nxt:
                            return nxt, "hidden"
                        i += 1
                    break
                if not ch.isalpha():  # `-$(…)`, `-{n,}`: the shell makes up the option letters
                    if HIDDEN_WORD_RE.search(t[k:]):
                        return t, "hidden"
                    break
        elif t.startswith("--"):
            name, _, value = t.partition("=")
            if COMPUTED_RE.search(name) or UNQUOTED_SUB in value:
                return t, "hidden"
        elif HIDDEN_WORD_RE.search(t):  # a path, a commit, a remote or a refspec
            return t, "hidden"
        i += 1
    return None


def hidden_block(code: str, word: str) -> int:
    word = word.replace(UNQUOTED_SUB, "$(…)")
    return block(code, f"`{word}` — ამ სიტყვას git-ისთვის shell-ი ქმნის ($…, `…`, glob, {{…}}) და guard ვერ ხედავს, "
                       "რა გამოვა: შეიძლება -n, --no-verify, --force, +refspec ან core.hooksPath იყოს. ოფციები, "
                       "ქვებრძანება და სახელები პირდაპირ ჩაწერე (მაგ. `git push -u origin <ტოტი>`); ოფციის მნიშვნელობაში "
                       "გაშლა დასაშვებია ბრჭყალებში: `git commit -m \"$(cat <<'EOF' …)\"`.")


def check_git(seg: list[str], start: int) -> int:
    sub, args, confs = git_subcommand(seg, start)
    before_git = " ".join(seg[:start]).lower()  # VAR=value prefixes and wrapper arguments (`env GIT_CONFIG_KEY_0=…`)
    if "hookspath" in before_git or any(c.lower().startswith("core.hookspath") for c in confs):
        return block("B2", "core.hooksPath-ის გადაფარვა (-c, --config-env, GIT_CONFIG_*) თიშავს pre-commit "
                           "კარიბჭეებს — აკრძალულია.")
    # A config include given on the command line is read at the command line's precedence, so a file it names can
    # set core.hooksPath over the repository's own (ECC corpus, 2026-10-19).
    if any(c.lower().startswith("alias.") for c in confs):
        return block("B2", "git-ის alias (`-c alias.…`) ჰუკ-გამშვებ ქვებრძანებას სხვა სახელით გაუშვებს — "
                           "guard მას ვერ ცნობს, ამიტომ აკრძალულია. ქვებრძანება პირდაპირ ჩაწერე.")
    if any(c.lower().startswith(("include.", "includeif.")) for c in confs) or \
            ("include" in before_git and "git_config" in before_git):
        return block("B2", "git-ის კონფიგურაციის ჩართვა ბრძანების ხაზიდან (include.path, includeIf) core.hooksPath-ს "
                           "გადაფარავს და pre-commit კარიბჭეებს თიშავს — აკრძალულია.")
    # What git reads in front of the subcommand: everything after `git` up to the subcommand itself.
    hidden = git_hides_option(sub, seg[start + 1:len(seg) - len(args) - bool(sub)], confs)
    if hidden:
        return hidden_block("B2", hidden)
    args = strip_redirects(args)  # a redirect target is not git's argument (review C5)
    if any(NO_VERIFY_RE.match(a) for a in args):
        return block("B2", "`--no-verify` გამოტოვებს კარიბჭეებს (gates) — აკრძალულია. გაასწორე ის, რაც ჩავარდა.")
    found = hook_skip(sub, args) if sub in HOOK_VALUE_OPTS else None
    if found and found[1] == "n":
        return block("B2", f"`git commit {found[0]}` შეიცავს -n-ს (= --no-verify) — აკრძალულია.")
    if found:
        return hidden_block("B3" if sub == "push" else "B2", found[0])
    if sub == "push":
        for t in args:
            if t in ("-f", "--force", "--force-with-lease", "--force-if-includes") or t.startswith("--force") \
                    or re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", t) or t.startswith("+"):
                return block("B3", "force push აკრძალულია (-f / --force / +refspec) — ისტორია არ გადაიწერება.")
    if sub == "config" and any(a.lower() in ("core.hookspath", "core") for a in args):
        if any(a in ("--unset", "--unset-all", "--remove-section", "--rename-section") for a in args):
            return block("B2", "core.hooksPath-ის წაშლა კარიბჭეებს თიშავს (git `.git/hooks`-ს დაუბრუნდება) — აკრძალულია.")
        vals = [a for a in args if not a.startswith("-") and a.lower() not in ("core.hookspath", "core")]
        if vals and vals[-1].rstrip("/") != ".githooks":
            return block("B2", "core.hooksPath უნდა დარჩეს `.githooks` — სხვა მნიშვნელობა თიშავს კარიბჭეებს.")
    return 0


def without_commit_message(args: list[str]) -> list[str]:
    """`git commit` arguments minus the message text: a message may mention `.env`, a pathspec may not."""
    out, i = [], 0
    while i < len(args):
        t = args[i]
        if t in ("-m", "--message") or re.fullmatch(r"-[A-Za-z]*m", t):
            i += 2
            continue
        if not (t.startswith("--message=") or re.fullmatch(r"-[A-Za-z]*m.+", t, re.S)):
            out.append(t)
        i += 1
    return out


COMPUTED_PART_RE = re.compile(r"[*?\[]")  # a glob metachar; a brace list and a substitution are handled apart
BRACE_LIST_RE = re.compile(r"(?<!\$)\{[^{}]*(?:,|\.\.)[^{}]*\}")  # shell brace expansion needs a comma or `..`


def _comp_hits(comp: str, target: str, dot_ok: bool) -> bool:
    """A glob/substitution path component `comp` can expand to `target`. The shell does not expand a leading
    wildcard (`*`, `?`, `[`) to a leading-dot name, so a dot target needs a literal dot or a substitution first."""
    if target.startswith(".") and not dot_ok and comp[:1] in "*?[":
        return False
    return fnmatch.fnmatchcase(target, comp)


def _dot_capable(comp: str) -> bool:
    """The original component can begin with a dot: a literal dot, or a substitution / brace list whose output the
    shell does not glob (so a leading dot is allowed)."""
    return comp[:1] == "." or comp.startswith((UNQUOTED_SUB, "$(", "`", "{"))


def _to_glob(comp: str) -> str:
    """A component with every shell-computed part turned into a `*`; real glob metachars stay so the dotfile rule
    still applies to them."""
    c = comp.replace(UNQUOTED_SUB, "*")
    c = re.sub(r"\$\([^()]*\)|`[^`]*`", "*", c)
    return BRACE_LIST_RE.sub("*", c)


def computed_secret_path(word: str) -> bool:
    """A word the shell builds that could become a secret file, or a path inside a secret directory — a glob, a
    brace list or a command substitution, which SECRET_RE (literal words only) never sees (Claude Security F1). A
    plain `$VAR` alone is not flagged: that is how the agent names a path it computed, and flagging it would refuse
    an ordinary `cat $f` (L-014)."""
    w = word.replace("\\", "/")
    if not (COMPUTED_PART_RE.search(w) or UNQUOTED_SUB in w or re.search(r"\$\(|`", w) or BRACE_LIST_RE.search(w)):
        return False
    comps = w.split("/")
    last = len(comps) - 1
    for i, oc in enumerate(comps):
        g = _to_glob(oc)
        if not COMPUTED_PART_RE.search(g):  # nothing computed in this component
            continue
        # the finding is a computed part GLUED TO literal text (`$(printf .en)v`, `.en?`); a component that is all
        # wildcards (a bare `$(…)` or a bare `*`) is too unconstrained to tie to a secret — the shell may expand it
        # to anything, and flagging it would refuse `cat $(…)` and `git commit -- $(git diff --name-only)`
        if not re.sub(r"\[[^\]]*\]|[*?]", "", g):
            continue
        pool = SECRET_FILE_SAMPLES if i == last else SECRET_DIRS
        if any(_comp_hits(g, t, _dot_capable(oc)) for t in pool):
            return True
    return False


def check_secret_read(seg: list[str], word: str, start: int, extra: str = "") -> int:
    """B4: a secret path named in a command that could read it, copy it or stage it."""
    named = seg
    if word == "git":
        sub, args, _ = git_subcommand(seg, start)
        if sub in ("status", "check-ignore", "ls-files"):
            return 0
        if sub == "commit":
            named = seg[:len(seg) - len(args)] + without_commit_message(args)
    # extra: the segment's $(…) bodies (review S1). A word the shell computes into a secret path (a glob, a brace
    # list, a substitution) is caught too, so `cat .en?` / `base64 .e*` / `cat $(printf .en)v` no longer pass B4 (F1).
    if not SECRET_RE.search(" ".join(named) + " " + extra) and not any(computed_secret_path(t) for t in named):
        return 0
    # `echo "$(cat .env)"` runs cat: a redirect or a command/process substitution makes any command unsafe.
    if word in SECRET_SAFE_CMDS and not any(m in t for t in seg for m in (">", "<", "$(", "`")):
        return 0
    return block("B4", "ბრძანება საიდუმლოების ფაილს (.env, *.pem, *.key, secrets/ …) კითხულობს ან git-ში ამატებს — "
                       "აგენტს ეს ეკრძალება. საჭირო ცვლადის სახელი `.env.example`-შია; მნიშვნელობა მხოლოდ მფლობელმა იცის.")


def check_secret_store(seg: list[str], word: str, start: int) -> int:
    """B4: a password read out of the system's secret store — macOS Keychain (`security find-generic-password -w`,
    `-g`, `dump-keychain -d`, `export`) and the Linux Secret Service (`secret-tool lookup`)."""
    if word in WRAPPERS:  # `sudo security …`
        j = unwrap(seg, start)
        if start < j < len(seg):
            return check_secret_store(seg, Path(seg[j]).name.lower().removesuffix(".exe"), j)
    args = [a.lower() for a in seg[start + 1:]]
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    reads = (word == "security" and (
        (any(a in ("find-generic-password", "find-internet-password") for a in args) and ("w" in flags or "g" in flags))
        or ("dump-keychain" in args and "d" in flags) or "export" in args)) \
        or (word == "secret-tool" and "lookup" in args)
    if not reads:
        return 0
    return block("B4", "ბრძანება სისტემის საიდუმლოების საცავიდან (macOS Keychain, Linux Secret Service) პაროლს ან "
                       "გასაღებს კითხულობს — აგენტს ეს ეკრძალება. საჭიროების შემთხვევაში მფლობელმა გასაღები `.env`-ში "
                       "თავად ჩაწეროს.")


def secret_name(name: str) -> bool:
    return any(part in SECRET_NAME_PARTS for part in name.upper().split("_"))


def first_secret_ref(pattern: re.Pattern[str], text: str) -> str | None:
    """The first match of `pattern` whose captured variable name is secret-named."""
    for m in pattern.finditer(text):
        name = next((g for g in m.groups() if g), "")
        if secret_name(name):
            return m.group(0)
    return None


def env_prints(args: list[str]) -> bool:
    """`env` with no command after its options prints the whole environment; `env X=1 git log` does not."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith(("-S", "--split-string")):
            return False  # `env -S 'cmd …'` runs the command the string holds (nested_command checks it)
        if a in ENV_VALUE_OPTS:
            i += 2
        elif a.startswith("-") or ("=" in a and not a.startswith("=")):
            i += 1
        else:
            return False
    return True


def unwrap(seg: list[str], start: int) -> int:
    """Skip a chain of wrappers (`env VAR=v`, `timeout 5`, `nice -n 10`, `sudo`, `nohup` …) to the command
    they run, so `env printenv KEY` is read as `printenv KEY`. A wrapper option that itself takes a value
    (`sudo -u NAME`) is a known blind spot."""
    i, hops = start, 0
    while i < len(seg) and hops < len(seg):
        if Path(seg[i]).name.lower().removesuffix(".exe") not in WRAPPERS:
            return i
        i += 1
        while i < len(seg) and (seg[i].startswith("-") or ("=" in seg[i] and not seg[i].startswith("="))
                                or re.fullmatch(r"\d+(?:[.,]\d+)?[smhd]?", seg[i])):
            i += 1  # wrapper flags, VAR=value prefixes, and a bare duration (`timeout 5`)
        hops += 1
    return i


def check_env_exposure(seg: list[str], word: str, start: int, extra: str = "") -> int:
    """S1: printing the environment, or a secret-named variable, puts API keys in front of the model."""
    seg = seg[:start + 1] + strip_redirects(seg[start + 1:])  # a redirect is not a name/command (review C8)
    if word in WRAPPERS:  # `env printenv KEY`, `timeout 5 printenv KEY`: resolve past the wrapper first
        j = unwrap(seg, start)
        if start < j < len(seg):
            return check_env_exposure(seg, Path(seg[j]).name.lower().removesuffix(".exe"), j)
    args = seg[start + 1:]
    text = " ".join(seg) + " " + extra  # extra: the segment's $(…) bodies (review S1)
    if INDIRECT_RE.search(text):  # ${!v}: reads the variable NAMED by v — a secret var reached past VAR_REF_RE (F2)
        return env_block("${!…}")
    what: str | None = None
    names = [a for a in args if not a.startswith("-")]
    printing = any("p" in a.lstrip("-") for a in args if a.startswith("-"))
    if word == "printenv" or (word == "env" and env_prints(args)) or (word == "set" and not args):
        what = word
    elif word in ("export", "declare", "typeset") and not names:
        what = " ".join([word, *args])
    elif word in ("export", "declare", "typeset") and printing and any(secret_name(n.split("=", 1)[0]) for n in names):
        what = " ".join([word, *args])  # `declare -p OPENAI_API_KEY` prints the value (review A4)
    elif m := PS_ENV_RE.search(text):
        what = m.group(0)
    elif word not in QUOTING_WORDS:
        dump = CODE_ENV_DUMP_RE.search(text)
        what = dump.group(0) if dump else first_secret_ref(CODE_ENV_READ_RE, text)
    if not what and word not in TEST_WORDS:
        what = first_secret_ref(VAR_REF_RE, text)
    return env_block(what) if what else 0


def env_block(what: str) -> int:
    return block("S1", f"ბრძანება ({what}) გარემოს ცვლადებს ბეჭდავს ან საიდუმლო ცვლადს შლის — იქ API გასაღებები "
                       "ინახება. აგენტი საიდუმლოს მნიშვნელობას არასდროს ხედავს: პროგრამამ ის თავად წაიკითხოს გარემოდან. "
                       "თუ მხოლოდ ის გინდა გაიგო, დაყენებულია თუ არა: `test -n \"$NAME\" && echo set`.")


def git_index(seg: list[str], word: str, start: int) -> int | None:
    """Where git starts in this segment: bare `git …`, or git behind a wrapper (`env git …`)."""
    if word == "git":
        return start
    if word in WRAPPERS:
        for i in range(start + 1, len(seg)):
            if Path(seg[i]).name.lower().removesuffix(".exe") == "git":
                return i
    return None


def nested_command(seg: list[str], word: str, start: int) -> str | None:
    """The command line handed to a nested shell: `bash -c "…"`, `pwsh -Command "…"`, `cmd /c …`, and the
    ones `eval …` and `find … -exec … ;` run."""
    if word in ("eval", "iex", "invoke-expression"):  # PowerShell iex / Invoke-Expression run a string as code
        return " ".join(seg[start + 1:]) or None
    if word in C_RUNNERS:  # `flock /tmp/l -c "…"`, `script -q -c "…" log`, `su -c "…" user`
        at = next((i for i in range(start + 1, len(seg) - 1) if seg[i] in ("-c", "--command")), None)
        return seg[at + 1] if at is not None else None
    if word == "env":  # `env -S 'git commit -n'` splits the string into a command and runs it
        for i in range(start + 1, len(seg)):
            t = seg[i]
            if t in ("-S", "--split-string") and i + 1 < len(seg):
                return seg[i + 1]
            if t.startswith("--split-string="):
                return t.split("=", 1)[1]
            if t.startswith("-S") and len(t) > 2:
                return t[2:]
        return None
    if word == "invoke-command":  # Invoke-Command -ScriptBlock { … } runs the braced body
        body = seg[start + 1:]
        if "{" in body:
            body = body[body.index("{") + 1:]
        if "}" in body:
            body = body[:body.index("}")]
        return " ".join(body) or None
    if word == "find":
        at = next((i for i in range(start + 1, len(seg)) if seg[i] in FIND_EXEC), None)
        if at is None:
            return None
        body = []
        for t in seg[at + 1:]:
            if t in (";", "\\;", "+", "{}+"):
                break
            body.append(t)
        return " ".join(body) or None
    if word not in NESTED_SHELLS:
        return None
    for i in range(start + 1, len(seg)):
        if NESTED_FLAG_RE.match(seg[i]):
            rest = seg[i + 1:]
            return " ".join(rest[1:] if rest[:1] == ["--"] else rest) or None  # `bash -c -- '…'`
    return None


def stdin_programs(cmd: str) -> list[str] | None:
    """A shell that reads its program from stdin runs the text fed to it: `echo '…' | bash`, `printf … | sh`,
    `bash <<< '…'`, `cat <<EOF | bash`. Returns the echo/printf arguments and here-strings to check as command
    lines, or None when no shell here reads stdin (ECC's bypass corpus; all four got past the guard until
    2026-10-07)."""
    fed, texts = False, []
    for seg in segments(cmd):
        word, start = first_word(seg)
        k = shell_behind(seg, word, start)
        if k is not None:
            shell, args = Path(seg[k]).name.lower().removesuffix(".exe"), seg[k + 1:]
            here = next((i for i, a in enumerate(args) if a.startswith("<<<")), None)
            if here is not None:  # `bash <<< '…'`, and glued `bash <<<'…'` should a fallback split leave it whole
                texts += [args[here][3:]] if args[here] != "<<<" else args[here + 1:][:1]
                fed = True
            elif word == "xargs" or any(a in ("-s", "-") for a in args) or (nested_command(seg, shell, k) in (None, "-")
                                     and all(a.startswith("-") for a in args)):
                fed = True  # bare `bash`, `sudo sh -s`, `pwsh -Command -`, `xargs … bash -c CMD`: stdin is the program
        elif word in ("echo", "printf"):
            texts += seg[start + 1:] + [" ".join(seg[start + 1:])]
    # printf and echo -e decode escapes before the shell reads the text (`printf '\x67it commit -n' | sh`); plain echo
    # does not, and the shell then reads `-\n` as `-n` — so both readings are checked.
    return texts + [d for d in map(unescaped, texts) if d not in texts] if fed else None


def shell_behind(seg: list[str], word: str, start: int) -> int | None:
    """Where the shell starts in this segment: bare `bash`, or behind a wrapper (`sudo bash`, `xargs … sh`).
    `script` with nothing to run starts a shell that reads stdin too."""
    shells = (NESTED_SHELLS - {"cmd"}) | {"script"}
    if word in shells:
        return start
    if word in WRAPPERS:
        return next((i for i in range(start + 1, len(seg))
                     if Path(seg[i]).name.lower().removesuffix(".exe") in shells), None)
    return None


OWNER_ONLY = ("`approve.py` / `approvals.md` მხოლოდ მფლობელის ხელშია: approve.py-ს გაშვება/შეცვლა და ledger-ში ჩაწერა "
              "აგენტს არ შეუძლია. სთხოვე მფლობელს `/approve …`.")
PROTECTED_NAMES = (
    ("approve.py", "B1", OWNER_ONLY),
    ("tools.approve", "B1", OWNER_ONLY),  # `-m tools.approve` reaches the same script (review S5)
    ("approvals.md", "B1", OWNER_ONLY),
    (Path(ENGINE_PYTHON_NOTE).name, "B2", f"`{ENGINE_PYTHON_NOTE}`-ს მხოლოდ `.claude/hooks/py.sh` წერს (ნაპოვნი Python-ის გზა): სხვა "
                            "პროგრამაზე მითითება ყველა hook-სა და კარიბჭეს Python-ის ნაცვლად იმ პროგრამით გაუშვებდა — "
                            "აკრძალულია."),
    (GIT_CONFIG_IN_CMD_RE, "B2", "`.git/config`-ში core.hooksPath და include ინახება: shell-ით ჩაწერილი ხაზი commit-ის "
                                 "შემოწმებებს თიშავს — აკრძალულია. პარამეტრი `git config`-ით შეცვალე, ის ჯერ მფლობელს "
                                 "ეკითხება."),
)


# A redirection that writes a file (`> f`, `>> f`, `&> f`, `>| f`, `<> f`, `>& f`) — not a duplication like `2>&1`.
WRITE_REDIRECTS = {">", ">>", "&>", "&>>", ">|", "<>"}
# A name directly in memory/ — where the approval ledger lives — that the shell makes up ($…, `…`, a glob or a brace
# list); a variable in front of memory/ (`$S/memory/episodes`) or a glob in a folder below it (episodes/*.md) is not one.
MADE_UP_IN_MEMORY_RE = re.compile(r"(?:^|[\\/])memory[\\/][^\s\\/]*[$`*?\[{]", re.IGNORECASE)


def redirect_targets(seg: list[str]) -> list[str]:
    return [seg[i + 1] for i, t in enumerate(seg[:-1])
            if t in WRITE_REDIRECTS or (t == ">&" and not seg[i + 1].isdigit() and seg[i + 1] != "-")]


def read_only_command(seg: list[str], word: str, start: int) -> bool:
    if word == "sed":  # in-place (-i, clustered -Ei, --in-place) or a w/W command writes the file (review S8)
        inplace = any(re.match(r"-[A-Za-z]*i", x) or x.startswith("--in-place") for x in seg)
        wcmd = any(("w " in x or x.rstrip().endswith("w")) for x in seg if not x.startswith("-"))
        return not (inplace or wcmd)
    if word == "git":
        sub, _, _ = git_subcommand(seg, start)
        return sub in GIT_SAFE_SUBCMDS
    if word in ("set-content", "add-content", "out-file", "tee", "tee-object"):
        return False
    if word in ("for", "select"):  # a loop's header runs nothing: its words are a list
        return not any(">" in t for t in seg)
    return word in READ_ONLY_CMDS and not any(">" in t for t in seg)


def writes_protected(seg: list[str], word: str, start: int, extra: str = "") -> int:
    """B1/B2: a command that is not read-only names the ledger, the approval script, the launcher's note or git's own
    configuration — or a read-only one redirects its output into one of them (`git show … > memory/approvals.md`).
    B1 also refuses a file in memory/ whose name the shell makes up (`memory/${v}als.md`, `memory/appro*.md`): the
    guard cannot see whether it is the ledger (review 2026-10-22 M5)."""
    joined = (" ".join(seg) + " " + extra).lower()  # extra: the segment's $(…) bodies (review S1)
    targets = " ".join(redirect_targets(seg)).lower()
    for name, code, why in PROTECTED_NAMES:
        if not (name.search(joined) if isinstance(name, re.Pattern) else name in joined):
            continue
        written = name.search(targets) if isinstance(name, re.Pattern) else name in targets
        if written or not read_only_command(seg, word, start):
            return block(code, why)
    made_up = [t for t in seg if MADE_UP_IN_MEMORY_RE.search(t)]
    if made_up and (set(made_up) & set(redirect_targets(seg)) or not read_only_command(seg, word, start)):
        return block("B1", f"`{made_up[0]}` — memory/-ში ფაილის სახელს shell-ი ქმნის ($…, `…`, glob), და guard ვერ ხედავს, "
                           "დამტკიცებების ჟურნალი ხომ არ არის — აკრძალულია. ფაილის სახელი პირდაპირ ჩაწერე.")
    return 0


def check_heredoc_bodies(bodies: list[tuple[bool, str]], depth: int) -> int:
    """In `cat <<EOF` with a bare word bash still runs $(…) and backticks and expands $VAR (review A2)."""
    for quoted, body in bodies:
        if quoted:
            continue
        for inner in substitutions(body) if depth < MAX_NESTING else []:
            rc = check_shell(inner, depth + 1)
            if rc:
                return rc
        if INDIRECT_RE.search(body):  # `${!v}` in an unquoted heredoc body is expanded too (F2)
            return env_block("${!…}")
        ref = first_secret_ref(BASH_VAR_RE, body)
        if ref:
            return env_block(ref)
    return 0


def check_ps_env(cmd: str) -> int:
    """A failed PowerShell call's output cannot be redacted (sentinel R2), so a secret read in PowerShell is refused
    here, scanned on the whole command — grouping parens would otherwise split
    `[Environment]::GetEnvironmentVariable('KEY')` across segments (review S2/S13)."""
    m = CODE_ENV_DUMP_RE.search(cmd) or PS_ENV_RE.search(cmd)
    if m:
        return env_block(m.group(0))
    for rx in (CODE_ENV_READ_RE, PS_ENV_BRACE_RE, VAR_REF_RE):
        ref = first_secret_ref(rx, cmd)
        if ref:
            return env_block(ref)
    return 0


def check_shell(cmd: str, depth: int = 0, ps: bool = False) -> int:
    """ps: the command is PowerShell (or cmd), where a backslash separates folders and escapes nothing (review A3)."""
    if ps:
        cmd = cmd.replace("\\", "/")
        rc = check_ps_env(cmd)  # a PowerShell env read, scanned whole so grouping parens cannot split it (S2)
        if rc:
            return rc
    if depth >= MAX_NESTING:  # too deep to keep parsing: if anything still nests, fail closed (review S7)
        if substitutions(cmd) or stdin_programs(cmd) or any(nested_command(s, *first_word(s)) for s in segments(cmd)):
            return block("B2", "ბრძანება ძალიან ღრმად არის ჩალაგებული (eval / ჩადგმული shell / $(…)) — guard "
                               "ბოლომდე ვერ კითხულობს, ამიტომ აკრძალულია. ჩაალაგე უფრო მარტივად.")
    fed = stdin_programs(cmd) if depth < MAX_NESTING else None
    for text in fed or []:
        rc = check_shell(text, depth + 1)
        if rc:
            return rc
    if fed is not None and (HOOK_SKIP_RE.search(cmd) or HOOK_SKIP_RE.search(unescaped(cmd))):
        return block("B2", "ბრძანება stdin-ით shell-ს აწვდის ტექსტს, რომელიც ჰუკებს გამოტოვებს (-n / --no-verify) — "
                           "აკრძალულია.")
    if fed is None:  # a `cat <<EOF` body is text — unless it is piped into a shell, which runs it
        cmd, bodies = heredocs(cmd)
        rc = check_heredoc_bodies(bodies, depth)
        if rc:
            return rc
    if depth < MAX_NESTING:
        for inner in substitutions(cmd):  # `echo "$(git commit -n)"` runs the commit
            rc = check_shell(inner, depth + 1, ps)
            if rc:
                return rc
    subtext = " ".join(substitutions(cmd)) if depth < MAX_NESTING else ""  # the command's $(…) bodies (review S1)
    for seg in segments(cmd, ps):
        word, start = first_word(seg)
        nword = word
        nested = nested_command(seg, word, start) if depth < MAX_NESTING else None
        if nested is None and word in WRAPPERS and depth < MAX_NESTING:  # `timeout 5 bash -c …` (review C7)
            j = unwrap(seg, start)
            if start < j < len(seg):
                nword = Path(seg[j]).name.lower().removesuffix(".exe")
                nested = nested_command(seg, nword, j)
        if nested:
            rc = check_shell(nested, depth + 1, ps=nword in PS_RUNNERS or (ps and nword == "find"))
            if rc:
                return rc
        gi = git_index(seg, word, start)
        if gi is not None:
            rc = check_git(seg, gi)
            if rc:
                return rc
        elif start < len(seg) and HIDDEN_WORD_RE.search(seg[start]) and any(h in seg for h in HOOK_SUBCMDS):
            return block("B2", "ბრძანების სიტყვას shell-ი ქმნის ($…, `…`) და მას ჰუკ-გამშვები ქვებრძანება "
                               "(commit, push…) მოსდევს — git შეიძლება იმალებოდეს; აკრძალულია. პირდაპირ ჩაწერე.")
        extra = subtext if (subtext and UNQUOTED_SUB in " ".join(seg)) else ""
        rc = (check_secret_read(seg, word, start, extra) or check_secret_store(seg, word, start)
              or check_env_exposure(seg, word, start, extra) or writes_protected(seg, word, start, extra))
        if rc:
            return rc
    # Safety net for forms the parser above does not follow (a variable set in one segment, used in the next), read
    # as written and with the escapes a program decodes (`sed 's/x/\x67it commit --no-verify/e'`). A GIT_CONFIG_*
    # variable whose key or value the shell makes up (`GIT_CONFIG_KEY_0=${K}Path`) may be core.hooksPath.
    for lowered in {cmd.lower(), unescaped(cmd).lower()}:
        if "git" in lowered and ("--no-veri" in lowered or ("git_config" in lowered and (
                "hookspath" in lowered or "include" in lowered or "$" in lowered or "`" in lowered))):
            return block("B2", "`--no-verify`, core.hooksPath-ის გადაფარვა, კონფიგურაციის ჩართვა (include) ან "
                               "GIT_CONFIG_* ცვლადი, რომლის მნიშვნელობასაც shell-ი ქმნის, აკრძალულია — კარიბჭეები "
                               "არ გამოიტოვება.")
    return 0


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        log(f"UNPARSEABLE payload let through: {raw[:200]!r}")
        return 0
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    root = root_dir()
    try:
        if tool in EDIT_TOOLS:
            return check_edit(tool, ti, payload, root)
        if tool in SHELL_TOOLS:
            return check_shell(str(ti.get("command") or ""), ps=tool == "PowerShell")
    except Exception as e:  # a crash must be visible, and must not freeze the session
        print(f"GUARD-ERROR: {type(e).__name__}: {e} — call let through", file=sys.stderr)
        log(f"ERROR {type(e).__name__}: {e} on {tool}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
