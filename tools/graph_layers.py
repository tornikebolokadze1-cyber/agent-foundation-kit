#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The agentic graph's bridges (ADR-0018 §2): what git and the project's own files already record, read by strict
patterns and never by a model.

  a commit           → the files it changed, and the task its first line names (D-NNN, or PLAN-NNNN T<n>)
  a task line        → its receipt (✓ YYYY-MM-DD · <commit | file>) and the decisions, specs and proposals it names
  a plan's task T<n> → the spec's requirement and criterion it names (REQ-…, AC-…); a requirement → the intent's goal G<n>
  a code comment     → the decision, spec, plan or task it names (ADR-, SPEC-, PLAN-, D-NNN)
  an episode         → the files its session changed and read, the commits it made (its actions block, ADR-0018 §3)
  a code file        → the project files it imports (the code layer, ADR-0018 §4)

A leaf module: the standard library and engine_line only. context_graph.py turns what these readers return into nodes
and links; gate.py takes its commit and path checks from here, so the tasks gate, the memory gate and the graph ask git
the same way (one implementation — ADR-0018 §2).

An id inside a code span (`ADR-0100`) is a name, not a bridge, as a wikilink inside one is not a link. Engine files
(engine_line.PREFIXES) bridge ADR ids only: their task, plan and spec numbers belong to the workshop the engine is built
in, and in a project made from the kit they would point at that project's own, unrelated records.
"""
from __future__ import annotations

import ast
import bisect
import io
import os
import posixpath
import re
import subprocess
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import engine_line

# ── One implementation of "does it exist" (gate.py imports these) ──────────────────────────────────────────────────────
TASK_LINE_RE = re.compile(r"^\s*[-*] \[([ xX])\] (.*)$")
TASK_ID_RE = re.compile(r"^(D-\d{3,}) — \S")
TASK_DONE_RE = re.compile(r"✓ (\d{4}-\d{2}-\d{2})(?: · (.+))?$")
# A commit is a word of its own with a digit in it: not the session part of an episode's name (EP-…-515c117b.md), a
# piece of a path or a link, or an English word made of the letters a–f, such as `defaced` (review M6).
SHA_RE = re.compile(r"(?<![\w./:#-])(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}(?![\w/:#-]|\.\w)")
PATH_LIKE_RE = re.compile(r"[\w.-]+(?:/[\w.-]*)+")
PLACEHOLDERS = ("NNN", "YYYY", "XXXX")
CODE_SPAN_RE = re.compile(r"`[^`\n]*`")
# episodic.py's detached summarizer asks git through here (tools/observe.py's session_commits): on Windows a console
# program a process with no console starts gets a window of its own unless told not to.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def git_answers(repo: Path, *args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    return r.returncode, r.stdout.strip()


def commit_exists(root: Path, sha: str) -> bool | None:
    try:
        r = subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.returncode == 0


def exists_exact(base: Path, token: str) -> bool:
    """The path exists with exactly this spelling — Windows and macOS would find `Memory/x.md` for `memory/x.md`, Linux
    would not; one verdict on every system (L-025). A note may be named without its `.md`."""
    def walk(segments: list[str]) -> bool:
        cur = base
        for seg in segments:
            try:
                if seg not in os.listdir(cur):
                    return False
            except OSError:
                return False
            cur = cur / seg
        return True
    segments = [s for s in token.split("/") if s]
    return walk(segments) or (not token.endswith("/") and walk(segments[:-1] + [segments[-1] + ".md"]))


def path_claim(token: str, top: set[str]) -> bool:
    """A word that names a file or folder of the project: one that starts with an entry of the project's root, or one
    that ends in a file name with an extension or in a slash — never a placeholder, a command or a web address."""
    if not PATH_LIKE_RE.fullmatch(token) or any(p in token for p in PLACEHOLDERS):
        return False
    parts = token.rstrip("/").split("/")
    if ".." in parts or "." in parts or not parts[0]:
        return False
    if parts[0] in top:
        return True
    if "." in parts[0] and not parts[0].startswith("."):  # github.com/…
        return False
    return token.endswith("/") or "." in parts[-1].lstrip(".")


def path_status(root: Path, repo: Path, token: str, at_commit: bool) -> bool | None:
    """Whether a claimed path exists, with exactly this spelling, in the tree being checked — None when git could not
    tell. At commit that tree is the next commit's (the staged files): git's own folder and a file git ignores never reach
    a commit, so for those the repository's disk is all there is of them."""
    if exists_exact(root, token):
        return True
    if at_commit and token.split("/")[0] == ".git":
        return exists_exact(repo, token)
    if at_commit:
        rc, _ = git_answers(repo, "check-ignore", "-q", "--", token.rstrip("/"))
        if rc == 0 and exists_exact(repo, token):
            return True
        if rc not in (0, 1):
            return None
    return False


# ── Commits ─────────────────────────────────────────────────────────────────────────────────────────────────────────
SUBJECT_TASK_RE = re.compile(r"(?<![\w-])(?:(D-\d{3,})(?!\d)|(PLAN-\d{4}) (T\d+)(?!\d))")
MAX_COMMITS = 5000
CODE_SUFFIXES = {".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".html", ".htm",
                 ".vue", ".svelte", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".swift", ".c", ".h", ".cpp", ".cs"}


@dataclass
class Commit:
    sha: str
    short: str
    date: str
    subject: str
    files: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)  # "D-NNN" or "PLAN-NNNN Tn", as the first line names them


def subject_tasks(subject: str) -> list[str]:
    out = []
    for m in SUBJECT_TASK_RE.finditer(subject):
        task = m.group(1) or f"{m.group(2)} {m.group(3)}"
        if task not in out:
            out.append(task)
    return out


def is_code(path: str) -> bool:
    return Path(path).suffix.lower() in CODE_SUFFIXES or path.startswith(".githooks/")


def same_folder(a: str | Path, b: str | Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def read_commits(repo: Path, limit: int = MAX_COMMITS) -> tuple[list[Commit] | None, str]:
    """The history HEAD reaches, newest first, at most `limit` commits — or (None, why) when git could not read it: no
    repository, or one whose top folder is above the project (its paths would not be the project's). A repository without
    a commit yet has an empty history: ([], "")."""
    rc, top = git_answers(repo, "rev-parse", "--show-toplevel")
    if rc != 0:
        return None, f"no git repository at {repo}"
    if not same_folder(top, repo):
        return None, f"the git repository's top folder is {top}, not the project's"
    if git_answers(repo, "rev-parse", "--verify", "-q", "HEAD")[0] != 0:
        return [], ""
    try:
        r = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", "log", "--no-color", "--no-renames",
                            f"--max-count={limit}", "--date=short", "--pretty=format:%x1e%H%x1f%h%x1f%ad%x1f%s",
                            "--name-only", "-z"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"git log could not run ({type(e).__name__})"
    if r.returncode != 0:
        return None, "git log failed: " + r.stderr.decode("utf-8", "replace").strip()[:120]
    commits = []
    for rec in r.stdout.decode("utf-8", "replace").split("\x1e"):
        head, _, rest = rec.partition("\n")
        fields = head.strip("\0").split("\x1f")
        if len(fields) != 4:
            continue
        sha, short, day, subject = fields
        files = [f for f in rest.split("\0") if f]
        commits.append(Commit(sha, short, day, subject, files, subject_tasks(subject)))
    return commits, ""


def changed_paths(repo: Path, at_commit: bool) -> set[str] | None:
    """The files the commit being made changes: at commit, what the index holds that HEAD does not; otherwise every file
    that differs from HEAD, staged or not, and every new file — what the next commit would take. None: git could not
    tell (the caller treats every file as changed)."""
    if at_commit:
        has_head = git_answers(repo, "rev-parse", "--verify", "-q", "HEAD")[0] == 0
        args = (["diff", "--cached", "--name-only", "--no-renames", "-z"] if has_head else ["ls-files", "-z"])
    else:
        args = ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames"]
    try:
        r = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", *args], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    names = [n for n in r.stdout.decode("utf-8", "replace").split("\0") if n]
    return {n[3:] if not at_commit else n for n in names}


# ── Lines in the project's own records ──────────────────────────────────────────────────────────────────────────────
NAMED_RE = re.compile(r"(?<![\w-])(?:(ADR-\d{4}|SPEC-\d{4}|P-\d{3,})(?!\d)|(PLAN-\d{4})(?: (T\d+))?(?![\d-]))")
PROPOSAL_RE = re.compile(r"^\s*[-*] \[([ xX])\] \*\*(P-\d{3,})\*\*\s*(.*)$")
PLAN_TASK_RE = re.compile(r"^\s*[-*] \[([ xX])\] (T\d+) — (.*)$")
ROW_ID_RE = re.compile(r"^\|\s*\**((?:REQ|AC)-\d+|G\d+)\**\s*\|")
REQ_AC_RE = re.compile(r"(?<![\w-])((?:REQ|AC)-\d+)(?!\d)")
GOAL_RE = re.compile(r"(?<![\w-])(G\d+)(?![\d-])")


@dataclass
class Entry:
    """One line of a register or a document that the graph makes a node: a task, a proposal, a plan's task, a spec's
    requirement or criterion, an intent's goal."""
    id: str
    path: str
    line: int
    done: bool
    title: str
    receipt: str = ""                                    # what follows "✓ YYYY-MM-DD · "
    named: list[tuple[str, int]] = field(default_factory=list)  # (id, line) the entry names


def plain(line: str) -> str:
    """The line as a reader of bridges sees it: code spans removed — an id in one is a name, not a bridge."""
    return CODE_SPAN_RE.sub("", line)


def short_title(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def named_ids(line: str) -> list[str]:
    out = []
    for m in NAMED_RE.finditer(plain(line)):
        ident = m.group(1) or (f"{m.group(2)} {m.group(3)}" if m.group(3) else m.group(2))
        if ident not in out:
            out.append(ident)
    return out


def read_task_lines(rel: str, text: str) -> list[Entry]:
    """tasks/*.md: every `- [ ] D-NNN — …` line, as the tasks gate reads it — a receipt only on a ticked line."""
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = TASK_LINE_RE.match(line)
        if not m:
            continue
        body = m.group(2).strip()
        mid = TASK_ID_RE.match(body)
        if not mid:
            continue
        ticked = m.group(1) != " "
        done = TASK_DONE_RE.search(body)
        receipt = (done.group(2) or "") if done and ticked else ""
        head = body[:done.start()].rstrip(" —") if done else body  # the title without the " — " before the receipt
        out.append(Entry(mid.group(1), rel, n, ticked, short_title(head[len(mid.group(1)) + 3:]),
                         receipt, [(i, n) for i in named_ids(head)]))
    return out


def read_proposals(rel: str, text: str) -> list[Entry]:
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = PROPOSAL_RE.match(line)
        if m:
            out.append(Entry(m.group(2), rel, n, m.group(1) != " ", short_title(m.group(3))))
    return out


def read_plan_tasks(rel: str, text: str) -> list[Entry]:
    """A plan's `- [ ] T<n> — … (REQ-…, AC-…)` lines: each names the spec's requirements and criteria it carries out."""
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = PLAN_TASK_RE.match(line)
        if m:
            refs = [(i, n) for i in dict.fromkeys(REQ_AC_RE.findall(plain(m.group(3))))]
            out.append(Entry(m.group(2), rel, n, m.group(1) != " ", short_title(m.group(3)), named=refs))
    return out


def read_rows(rel: str, text: str) -> list[Entry]:
    """Table rows that start with an id — a spec's REQ-/AC- rows, the intent's G rows. A requirement row names its goals
    in its other cells."""
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = ROW_ID_RE.match(line.strip())
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        goals = [(g, n) for g in dict.fromkeys(GOAL_RE.findall(plain("|".join(cells[1:]))))] if m.group(1).startswith("REQ") else []
        out.append(Entry(m.group(1), rel, n, False, short_title(cells[1] if len(cells) > 1 else ""), named=goals))
    return out


def receipt_parts(receipt: str, top: set[str]) -> tuple[list[str], list[str]]:
    """(commits, paths) a receipt names: `✓ 2026-01-02 · 1a2b3c4`, `· docs/adr/ADR-0007-x.md`, `· მფლობელი`."""
    shas = SHA_RE.findall(receipt)
    paths = []
    for token in re.split(r"[\s·,;()]+", CODE_SPAN_RE.sub(lambda m: " " + m.group(0)[1:-1] + " ", receipt)):
        token = token.strip("`'\".")
        if token and path_claim(token, top) and token not in paths:
            paths.append(token)
    return shas, paths


# ── Comments in code files ──────────────────────────────────────────────────────────────────────────────────────────
# Which comments the reader understands, by file suffix; a .githooks/ file is a shell script without one.
COMMENT_STYLES = {".py": "python", ".toml": "hash", ".sh": "hash", ".bash": "hash", ".html": "html", ".htm": "html",
                  ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".scss": "js",
                  ".css": "css"}
CITED_RE = re.compile(r"(?<![\w-])(?:(ADR-\d{4}|SPEC-\d{4}|D-\d{3,})(?!\d)|(PLAN-\d{4})(?: (T\d+))?(?![\d-]))")
ENGINE_CITED_RE = re.compile(r"(?<![\w-])(ADR-\d{4})(?!\d)")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


def is_engine(rel: str) -> bool:
    return rel.startswith(engine_line.PREFIXES)


def comment_style(rel: str) -> str | None:
    return COMMENT_STYLES.get(Path(rel).suffix.lower()) or ("hash" if rel.startswith(".githooks/") else None)


DOC_HOLDERS = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def _python_comments(text: str) -> list[tuple[int, str]]:
    return _comment_tokens(text) + _docstrings(ast.walk(ast.parse(text)))


def _comment_tokens(text: str) -> list[tuple[int, str]]:
    return [(tok.start[0], tok.string) for tok in tokenize.generate_tokens(io.StringIO(text).readline)
            if tok.type == tokenize.COMMENT]


def _docstrings(nodes) -> list[tuple[int, str]]:
    out = []
    for node in nodes:
        if isinstance(node, DOC_HOLDERS) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                out.append((first.lineno, first.value.value))
    return out


def _hash_comment(line: str) -> str | None:
    """The `#` comment of one line of TOML or shell, outside its quoted strings."""
    quote, i = "", 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[i:]
        i += 1
    return None


def comments(rel: str, text: str) -> list[tuple[int, str]] | None:
    """(line, text) of each comment and docstring in a code file; None when the file could not be read as its language
    (it is counted as unread, never as a file without comments)."""
    style = comment_style(rel)
    if style == "python":
        try:
            return _python_comments(text)
        except (SyntaxError, ValueError, tokenize.TokenError):
            return None
    if style == "hash":
        found = ((n, _hash_comment(line)) for n, line in enumerate(text.splitlines(), start=1))
        return [(n, c) for n, c in found if c]
    if style == "html":
        return [(text.count("\n", 0, m.start()) + 1, m.group(1)) for m in HTML_COMMENT_RE.finditer(text)]
    if style in ("js", "css"):
        return _scan(text, js=style == "js")[1]
    return []


def cited_ids(rel: str, found: list[tuple[int, str]]) -> list[tuple[str, int]]:
    """(id, line) each comment names, outside its code spans. Engine files: ADR ids only (see the module's docstring)."""
    engine = is_engine(rel)
    out = []
    for start, comment in found:
        body = plain(comment)  # a code span holds no newline, so the line count below stays right
        for m in (ENGINE_CITED_RE if engine else CITED_RE).finditer(body):
            if engine:
                ident = m.group(1)
            else:
                ident = m.group(1) or (f"{m.group(2)} {m.group(3)}" if m.group(3) else m.group(2))
            line = start + body.count("\n", 0, m.start())
            if (ident, line) not in out:
                out.append((ident, line))
    return out


# ── The code layer: a code file → the project files it imports (ADR-0018 §4) ────────────────────────────────────────
# Python is read by `ast`. JavaScript and TypeScript, HTML and CSS by a careful reader that knows only the explicit forms
# — `import … from` (with `export … from` and a bare `import "x"`), `require("…")`, `<script src>`, `<link href>`,
# `@import` — written in code, never in a comment or a string. A dynamic import (`import(…)`, importlib) and an alias
# path (`@/…`) are counted, never followed; a package (`react`, `json`) is no project file. Other languages' files are
# nodes without import links. An import links only to a file the graph holds.
IMPORT_READERS = {".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
                  ".html": "html", ".htm": "html", ".css": "css"}
JS_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
SCHEME_RE = re.compile(r"^[A-Za-z][\w+.-]*:")
# the search for `from` stops where the next import or export statement starts, so a file of many export lines without
# a semicolon or a quote is read in one pass, not once per line to its end
JS_STATIC_RE = re.compile(r"(?:^|[;}])[ \t]*(?:import|export)\b"
                          r"(?:(?!^[ \t]*(?:import|export)\b|\}[ \t]*(?:import|export)\b)[^;'\"`])*?"
                          r"\bfrom[ \t]*(['\"])", re.M)
JS_BARE_RE = re.compile(r"(?:^|[;}])[ \t]*import[ \t]*(['\"])", re.M)
JS_CALL_RE = re.compile(r"(?<![\w$.])(import|require)[ \t]*\(")
JS_LITERAL_ARG_RE = re.compile(r"[ \t]*(['\"])")
JS_CALL_END_RE = re.compile(r"[ \t]*\)")
HTML_TAG_RE = re.compile(r"<(script|link)\b([^>]*)>", re.I)
HTML_ATTR_RE = re.compile(r"""(?<![\w-])(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""", re.I)
CSS_IMPORT_RE = re.compile(r"@import\s+(?:url\(\s*)?(?:(['\"])|([^\s'\"();]+))", re.I)
# what stands before a slash that opens a regular expression and not a division: an operator, an opening bracket, or
# one of these words
JS_REGEX_AFTER = frozenset("(,=:[!&|?{};+-*%<>~^")
JS_REGEX_WORDS = frozenset({"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                            "else", "yield", "await"})
SCAN_JS_RE, SCAN_CSS_RE = re.compile(r"[/'\"`]"), re.compile(r"/\*|['\"]")
WORD_END_RE = re.compile(r"[\w$]+$")
# Python calls that load a module by a name only known when the code runs
DYNAMIC_CALLS = frozenset({"__import__", "import_module", "spec_from_file_location", "run_path", "run_module"})
PATH_CALLS = frozenset({"Path", "PurePath", "PosixPath", "WindowsPath", "str", "fspath", "abspath", "realpath",
                        "normpath"})


@dataclass(frozen=True)
class Known:
    """The files an import may link to — those the graph holds — and the folders they are in."""
    files: frozenset[str]
    dirs: frozenset[str]

    @staticmethod
    def of(paths) -> "Known":
        files = frozenset(paths)
        dirs = {""}
        for f in files:
            d = posixpath.dirname(f)
            while d not in dirs:
                dirs.add(d)
                d = posixpath.dirname(d)
        return Known(files, frozenset(dirs))


@dataclass
class CodeRead:
    """What the readers found in one code file."""
    readable: bool = True                                           # False: not readable as its language (syntax error)
    comments: list[tuple[int, str]] = field(default_factory=list)   # (line, text) of each comment and docstring
    imports: list[tuple[str, int]] = field(default_factory=list)    # (project file, line) of each import that resolves
    dynamic: int = 0     # import(…), a require of a computed name, importlib, __import__ — not followed
    alias: int = 0       # @/…, ~/…, #…: a path a bundler's alias resolves — not followed
    unresolved: int = 0  # a relative path that names no file the graph holds

    def add(self, rel: str, target: str | None, line: int) -> None:
        if target is None:
            self.unresolved += 1
        elif target != rel and all(target != t for t, _ in self.imports):
            self.imports.append((target, line))


def import_reader(rel: str) -> str | None:
    return IMPORT_READERS.get(Path(rel).suffix.lower())


def read_code(rel: str, text: str, known: Known, base: str = "") -> CodeRead:
    """One code file's comments and the project files it imports. `base`: the folder a path that starts with "/" starts
    from — the product's code folder the file is in, the project's root otherwise."""
    reader = import_reader(rel)
    if reader == "python":
        return _read_python(rel, text, known)
    if reader == "js":
        masked, found = _scan(text, js=True)
        return _read_js(rel, text, masked, CodeRead(comments=found), known, base)
    if reader == "css":
        masked, found = _scan(text, js=False)
        return _read_css(rel, text, masked, CodeRead(comments=found), known, base)
    if reader == "html":
        return _read_html(rel, text, known, base)
    found = comments(rel, text)
    return CodeRead(readable=False) if found is None else CodeRead(comments=found)


def _liner(text: str):
    """The line a text offset is on."""
    breaks = [m.start() for m in re.finditer("\n", text)]
    return lambda offset: bisect.bisect_left(breaks, offset) + 1


def _scan(text: str, js: bool = True) -> tuple[str, list[tuple[int, str]]]:
    """JavaScript or TypeScript (js=True) or CSS as a careful reader sees it: the text with each comment, and the inside of
    each string, template and regular expression, blanked — newlines kept, so every offset and line stays where it was
    — and the comments with their lines. A slash opens a regular expression or a division by what stands before it, the
    usual way; a line that fools it can hide an import from the reader."""
    out = list(text)
    found: list[tuple[int, str]] = []
    line_of = _liner(text)
    special = SCAN_JS_RE if js else SCAN_CSS_RE
    n, i, prev, word = len(text), 0, "", ""

    def blank(a: int, b: int) -> None:
        b = min(b, n)
        out[a:b] = ["\n" if c == "\n" else " " for c in text[a:b]]

    while True:
        m = special.search(text, i)
        if m is None:
            break
        before = text[i:m.start()].rstrip()
        if before:
            prev = before[-1]
            w = WORD_END_RE.search(before[-32:])  # a keyword is short; searching a long run from each position is not
            word = w.group(0) if w else ""
        i = m.start()
        ch, nxt = text[i], text[i + 1:i + 2]
        if ch == "/" and nxt in ("*", "/") and (nxt == "*" or js):
            end = text.find("*/" if nxt == "*" else "\n", i + 2)
            stop = n if end < 0 else end + (2 if nxt == "*" else 0)
            found.append((line_of(i), text[i + 2:n if end < 0 else end]))
            blank(i, stop)
            i = stop
            continue
        if ch == "/" and not (not prev or prev in JS_REGEX_AFTER or word in JS_REGEX_WORDS):
            prev, word, i = "/", "", i + 1  # a division
            continue
        j, klass = i + 1, False  # a string, a template or a regular expression: its inside blanked, its quotes kept
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "\n" and ch != "`":
                break  # an unclosed string ends with its line
            if ch == "/" and c in "[]":
                klass = c == "["
            elif c == ch and not klass:
                break
            j += 1
        blank(i + 1, j)
        prev, word, i = ch, "", j + 1
    return "".join(out), found


def _quoted(text: str, masked: str, q: int) -> str | None:
    """The literal the quote at offset q opens, read from the text — None when it does not close on its line."""
    close = masked.find(masked[q], q + 1)
    if close < 0 or "\n" in masked[q:close]:
        return None
    return text[q + 1:close]


def _kind(spec: str, js: bool) -> str:
    """external (a web address, an anchor), alias, package — or path, a file of the project."""
    if not spec or SCHEME_RE.match(spec) or spec.startswith("//") or (spec.startswith("#") and not js):
        return "external"
    if spec.startswith(("./", "../", "/")) or spec in (".", ".."):
        return "path"
    if js:
        return "alias" if spec.startswith(("@/", "~/", "#")) else "package"
    return "path"  # in HTML and CSS a bare name is a file next to this one


def _join(folder: str | None, part: str) -> str | None:
    """folder/part from the project's root ("" = the root) — None when it leaves the project."""
    if folder is None:
        return None
    joined = posixpath.normpath(posixpath.join(folder, part.replace("\\", "/")))
    if joined == ".":
        return ""
    return None if joined == ".." or joined.startswith(("../", "/")) else joined


def _up(path: str | None, levels: int) -> str | None:
    for _ in range(levels):
        if not path:
            return None  # above the project's root
        path = posixpath.dirname(path)
    return path


def _file_target(rel: str, spec: str, known: Known, base: str, js: bool) -> str | None:
    """The project file a path names, from this file's folder, or from `base` when it starts with "/". JavaScript tries
    what a bundler tries: the name with each extension, the folder's index file, and `.ts` behind `.js`."""
    clean = unquote(spec.split("?", 1)[0].split("#", 1)[0])
    path = _join(base, clean.lstrip("/")) if clean.startswith("/") else _join(posixpath.dirname(rel), clean)
    if path is None:
        return None
    tries = [path]
    if js:
        stem, suffix = posixpath.splitext(path)
        if suffix in (".js", ".jsx", ".mjs", ".cjs"):
            tries += [stem + ".ts", stem + ".tsx"]
        tries += [path + s for s in JS_EXTS] + [f"{path}/index{s}" for s in JS_EXTS]
    return next((t for t in tries if t in known.files), None)


def _follow(out: CodeRead, rel: str, spec: str, line: int, known: Known, base: str, js: bool) -> None:
    kind = _kind(spec.strip(), js)
    if kind == "alias":
        out.alias += 1
    elif kind == "path":
        out.add(rel, _file_target(rel, spec.strip(), known, base, js), line)


def _read_js(rel: str, text: str, masked: str, out: CodeRead, known: Known, base: str) -> CodeRead:
    line_of = _liner(text)
    for rx in (JS_STATIC_RE, JS_BARE_RE):
        for m in rx.finditer(masked):
            spec = _quoted(text, masked, m.start(1))
            if spec is not None:
                _follow(out, rel, spec, line_of(m.start(1)), known, base, js=True)
    for m in JS_CALL_RE.finditer(masked):
        arg = JS_LITERAL_ARG_RE.match(masked, m.end()) if m.group(1) == "require" else None
        spec = _quoted(text, masked, arg.start(1)) if arg else None
        if arg is None or spec is None or not JS_CALL_END_RE.match(masked, arg.end(1) + len(spec) + 1):
            out.dynamic += 1  # import(…) — or a require whose argument is not one literal
            continue
        _follow(out, rel, spec, line_of(m.start()), known, base, js=True)
    out.imports.sort(key=lambda x: x[1])
    return out


def _read_html(rel: str, text: str, known: Known, base: str) -> CodeRead:
    line_of = _liner(text)
    found = [(line_of(m.start()), m.group(1)) for m in HTML_COMMENT_RE.finditer(text)]
    out = CodeRead(comments=found)
    masked = HTML_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    for m in HTML_TAG_RE.finditer(masked):
        want = "src" if m.group(1).lower() == "script" else "href"
        for a in HTML_ATTR_RE.finditer(m.group(2)):
            if a.group(1).lower() == want:
                spec = next(g for g in a.groups()[1:] if g is not None)
                _follow(out, rel, spec, line_of(m.start(2) + a.start()), known, base, js=False)
                break
    return out


def _read_css(rel: str, text: str, masked: str, out: CodeRead, known: Known, base: str) -> CodeRead:
    line_of = _liner(text)
    for m in CSS_IMPORT_RE.finditer(masked):
        spec = _quoted(text, masked, m.start(1)) if m.group(1) else m.group(2)
        if spec is not None:
            _follow(out, rel, spec, line_of(m.start()), known, base, js=False)
    return out


def _read_python(rel: str, text: str, known: Known) -> CodeRead:
    """`ast` reads every import statement, the lazy ones inside functions too. An absolute import names a project file
    from the folders this file's own sys.path lines add, its own folder, its package's top and the project's root; a
    relative one from its package — one that names nothing is counted. A file nested deeper than the parser, `ast` or
    Python's own stack holds is counted as unread; the graph is still built."""
    try:
        tree = ast.parse(text)
        tokens = _comment_tokens(text)
    except (SyntaxError, ValueError, tokenize.TokenError, RecursionError, MemoryError):  # MemoryError: the parser's stack
        return CodeRead(readable=False)
    folder = posixpath.dirname(rel)
    statements, calls, holders = [], [], []
    for node in ast.walk(tree):  # one walk: the imports, the calls and the docstrings' holders
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            statements.append(node)
        elif isinstance(node, ast.Call):
            calls.append(node)
        elif isinstance(node, DOC_HOLDERS):
            holders.append(node)
    out = CodeRead(comments=tokens + _docstrings(holders))
    try:
        bases = _python_bases(rel, tree, calls, known)
    except RecursionError:  # a path expression nested deeper than Python's stack lets _path_value follow
        return CodeRead(readable=False)
    for node in sorted(statements, key=lambda s: s.lineno):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found = _module(bases, alias.name, known)
                if found:
                    out.add(rel, found, node.lineno)
            continue
        home = [_up(folder, node.level - 1)] if node.level else bases
        if node.level and home[0] is None:
            out.add(rel, None, node.lineno)  # climbs above the project
            continue
        found = _module(home, node.module or "", known) if node.module else (
            f"{home[0]}/__init__.py".lstrip("/") if f"{home[0]}/__init__.py".lstrip("/") in known.files else None)
        targets = []
        for alias in node.names:  # `from pkg import mod`: the submodule when there is one
            sub = _module(home, f"{node.module}.{alias.name}" if node.module else alias.name, known)
            if sub or found:
                targets.append(sub or found)
        for t in targets:
            out.add(rel, t, node.lineno)
        if node.level and not targets:
            out.add(rel, None, node.lineno)  # a relative import that names no file the graph holds: one path, counted
    out.dynamic = sum(1 for c in calls if _call_name(c) in DYNAMIC_CALLS)
    return out


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _module(bases: list[str | None], dotted: str, known: Known) -> str | None:
    if not dotted:
        return None
    rel = dotted.replace(".", "/")
    for b in bases:
        if b is None:
            continue
        stem = f"{b}/{rel}" if b else rel
        for cand in (stem + ".py", stem + "/__init__.py"):
            if cand in known.files:
                return cand
    return None


def _python_bases(rel: str, tree: ast.Module, calls: list[ast.Call], known: Known) -> list[str | None]:
    """Where an absolute import is looked for: the folders this file's `sys.path.insert` / `append` lines add — when
    their path is one the module's own names spell from `__file__` (Path(__file__).resolve().parents[2] / "tools") —,
    its own folder, the folder above its package, and the project's root."""
    env: dict[str, str] = {}
    for st in tree.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            value = _path_value(st.value, env, rel)
            if value is not None:
                env[st.targets[0].id] = value
    added = []
    for c in calls:
        f = c.func
        if (isinstance(f, ast.Attribute) and f.attr in ("insert", "append") and isinstance(f.value, ast.Attribute)
                and f.value.attr == "path" and isinstance(f.value.value, ast.Name) and f.value.value.id == "sys"):
            arg = c.args[1] if f.attr == "insert" and len(c.args) == 2 else c.args[0] if len(c.args) == 1 else None
            value = _path_value(arg, env, rel) if arg is not None else None
            if value is not None and value in known.dirs:
                added.append(value)
    folder = posixpath.dirname(rel)
    top = folder
    while top and f"{top}/__init__.py" in known.files:
        top = posixpath.dirname(top)
    return list(dict.fromkeys([*added, folder, top, ""]))


def _path_value(node: ast.AST, env: dict[str, str], here: str) -> str | None:
    """The project path (from its root, "" = the root) a simple path expression spells: `__file__` and what Path(),
    .resolve(), .parent, .parents[N], / "x", str() and os.path's dirname and join make of it, through the module's own
    names; for `A or B`, the fallback B. None for anything else — an environment variable, an argument, a path outside
    the project."""
    if isinstance(node, ast.Name):
        return here if node.id == "__file__" else env.get(node.id)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _up(_path_value(node.value, env, here), 1)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
        k = node.slice
        if isinstance(k, ast.Constant) and isinstance(k.value, int) and not isinstance(k.value, bool) and k.value >= 0:
            return _up(_path_value(node.value.value, env, here), k.value + 1)
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        r = node.right
        return _join(_path_value(node.left, env, here), r.value) if isinstance(r, ast.Constant) and isinstance(r.value, str) else None
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return _path_value(node.values[-1], env, here)
    if not isinstance(node, ast.Call):
        return None
    name, f, args = _call_name(node), node.func, node.args
    if isinstance(f, ast.Attribute) and name in ("resolve", "absolute") and not args:
        return _path_value(f.value, env, here)
    if name in PATH_CALLS and len(args) == 1:
        return _path_value(args[0], env, here)
    if name == "dirname" and len(args) == 1:
        return _up(_path_value(args[0], env, here), 1)
    if name == "joinpath" and isinstance(f, ast.Attribute):
        value, parts = _path_value(f.value, env, here), args
    elif name == "join" and args:
        value, parts = _path_value(args[0], env, here), args[1:]
    else:
        return None
    for a in parts:
        value = _join(value, a.value) if isinstance(a, ast.Constant) and isinstance(a.value, str) else None
    return value


# ── An episode's actions block (ADR-0018 §3) ────────────────────────────────────────────────────────────────────────
# tools/observe.py writes it from the session's transcript (episodic.py, at SessionEnd and in /session-close); the graph
# reads it back here. One format — these markers and line heads — for the writer and the reader.
ACTIONS_START, ACTIONS_END = "<!-- auto: actions:start -->", "<!-- auto: actions:end -->"
ACTIONS_HEAD = "## მოქმედებები"
CHANGED_HEAD, READ_HEAD, COMMITS_HEAD = "- შეცვლილი ფაილები", "- წაკითხული ფაილები", "- commit-ები"
UNREAD_HEAD = "- ⚠ ჩანაწერი ვერ წავიკითხე"
SPAN_ITEM_RE = re.compile(r"`([^`\n]+)`")
HEX_RE = re.compile(r"[0-9a-f]{7,40}")


@dataclass
class Actions:
    """What an episode's actions block says its session did, each item with its line in the episode."""
    line: int                                                    # the block's first line
    readable: bool                                               # False: the transcript was not read, or the block is cut
    changed: list[tuple[str, int]] = field(default_factory=list)  # (path, line) of the files the session changed
    read: list[tuple[str, int]] = field(default_factory=list)     # … the files it read (the block names the most read)
    commits: list[tuple[str, int]] = field(default_factory=list)  # (hash, line) of the commits it made


def read_actions(text: str) -> Actions | None:
    """An episode's actions block, or None when it has none (a session from before ADR-0018 §3). A block without its end
    marker is read as not readable — never as a session that did nothing."""
    lines = text.splitlines()
    start = next((i for i, x in enumerate(lines) if x.strip() == ACTIONS_START), None)
    if start is None:
        return None
    acts = Actions(start + 1, True)
    for n in range(start + 1, len(lines)):
        line = lines[n]
        if line.strip() == ACTIONS_END:
            return acts
        if line.startswith(UNREAD_HEAD):
            acts.readable = False
        for head, into in ((CHANGED_HEAD, acts.changed), (READ_HEAD, acts.read), (COMMITS_HEAD, acts.commits)):
            if line.startswith(head):
                into += [(item, n + 1) for item in SPAN_ITEM_RE.findall(line)
                         if head != COMMITS_HEAD or HEX_RE.fullmatch(item)]
    return Actions(start + 1, False)
