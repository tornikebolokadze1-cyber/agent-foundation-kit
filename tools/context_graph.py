#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Context graph of the project's knowledge files: one source, two views, one check.

The source is the Markdown itself: YAML frontmatter (id, type, status, relations)
plus links ([[wikilinks]] and relative [text](path.md) links). Obsidian draws these
same links as its graph view for the owner; this script builds the same graph for
the agent, and checks it mechanically.

  bash .claude/hooks/py.sh tools/context_graph.py build                write memory/graph/graph.json + CONTEXT-MAP.md
  bash .claude/hooks/py.sh tools/context_graph.py check [FILE ...]     integrity check; with FILEs, report only
                                                                       issues that involve those files
  bash .claude/hooks/py.sh tools/context_graph.py query ID [--depth N] one node's neighbourhood (ID or file stem)
  bash .claude/hooks/py.sh tools/context_graph.py why ID [--depth N]   why it is so: file → commit → task → spec → goal
  bash .claude/hooks/py.sh tools/context_graph.py impact ID [--depth N] what relies on it: links, tasks, comments, commits
  bash .claude/hooks/py.sh tools/context_graph.py pending              documents waiting for the owner's /approve
  bash .claude/hooks/py.sh tools/context_graph.py stage                where the project stands (F1–F6) and what comes next
  bash .claude/hooks/py.sh tools/context_graph.py brief                SessionStart hook: rebuild + stage + short brief

Every command but `pending` and `stage` also reads the bridges between the layers (ADR-0018 §2, tools/graph_layers.py):
the commits git holds, the task lines, the plans' tasks, the specs' requirements and the ids code comments cite — the
sessions (§3): each episode's actions block names the files its session changed and read and the commits it made — and
the code (§4): every code file, the engine's hooks included, with the project files it imports. A bridge whose target is
gone fails `check` in a file the commit being made changes and warns in an older one; every answer ends with a coverage
line — what was read and what was not.

Exit codes (check): 0 = no errors, 1 = errors found, 2 = inconclusive (nothing
was scanned, or the root is wrong) — a check that saw nothing must not pass.

Standard library only. Frontmatter is a documented YAML subset: `key: value`,
quoted strings, inline lists `[a, b]`, `- item` block lists, `#` comments.
A wikilink inside frontmatter must be quoted ("[[x]]"), exactly as Obsidian needs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Vault scope ──────────────────────────────────────────────────────────────
# The vault is every non-hidden folder (the same set Obsidian indexes: it skips
# dot-folders such as .claude, .git, .obsidian). Links are validated everywhere
# EXCEPT in foreign folders — material written by other sessions or copied in
# from outside, which may link however it likes. Foreign files still exist as
# nodes, so links TO them resolve.
FOREIGN_PREFIXES = ("research/",)
SKIP_DIRS = {"memory/graph"}
# Dependency and build folders are skipped at any depth — a site in site/ has its own node_modules (D-044).
SKIP_NAMES = {"node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
# A folder below the root that holds its own code project is the product's: its Markdown (a site's posts, a
# package's README) follows the product's rules, not the vault's, so it is foreign — a node, never checked.
CODE_MARKERS = ("package.json", "pyproject.toml")
LINKABLE_SUFFIXES = {".md", ".html", ".json", ".jsonl", ".py", ".toml", ".txt", ".csv", ".png", ".jpg", ".svg", ".pdf"}
# The engine's own code sits in dot-folders the vault walk skips; the code layer reads it there too (ADR-0018 §4)
CODE_DOT_DIRS = (".claude/hooks", ".githooks")

# ── Document types ───────────────────────────────────────────────────────────
# A file in one of these locations MUST declare this type in its frontmatter.
PATH_TYPES: list[tuple[str, str]] = [
    ("intent.md", "intent"),
    ("plan.md", "roadmap"),
    ("progress.md", "progress"),
    ("docs/specs/SPEC-*.md", "spec"),
    ("docs/plans/PLAN-*.md", "plan"),
    ("docs/adr/ADR-*.md", "adr"),
    ("docs/domain/*.md", "domain"),
    ("docs/guides/*.md", "guide"),
    ("memory/episodes/EP-*.md", "episode"),
    ("memory/lessons/L-*.md", "lesson"),  # one lesson's story; its rule is its line in memory/LESSONS.md (ADR-0017)
]

SCHEMA: dict[str, dict] = {
    "intent":   {"required": ("id", "type", "title", "status", "updated"), "status": ("draft", "accepted")},
    "roadmap":  {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "progress": {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "spec":     {"required": ("id", "type", "title", "status", "created", "updated", "intent"),
                 "status": ("draft", "review", "approved", "superseded")},
    "plan":     {"required": ("id", "type", "title", "status", "created", "updated", "spec"),
                 "status": ("draft", "approved", "in-progress", "done", "live")},
    "adr":      {"required": ("id", "type", "title", "status", "date"),
                 "status": ("proposed", "accepted", "rejected", "superseded")},
    "domain":   {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "episode":  {"required": ("id", "type", "session", "date", "status"), "status": ("open", "closed")},
    "memory":   {"required": ("id", "type", "title", "status"), "status": ("living", "generated")},
    "guide":    {"required": ("id", "type", "title"), "status": None},
    "lesson":   {"required": ("id", "type", "title", "status"), "status": ("living",)},
}

ID_PATTERNS = {
    "spec": r"SPEC-\d{4}",
    "plan": r"PLAN-\d{4}",
    "adr": r"ADR-\d{4}",
    "episode": r"EP-\d{4}-\d{2}-\d{2}-[0-9a-z]{8}",
    "lesson": r"L-\d{3,}",
}

# Statuses only the owner may set (through tools/approve.py, never an agent).
OWNER_STATUSES = {
    "intent": {"accepted"},
    "spec": {"approved", "superseded"},
    "plan": {"approved", "live"},  # live: the owner saw it working and the pilot is over — `/approve live N` (ADR-0013)
    "adr": {"accepted", "rejected", "superseded"},
}
# The statuses an agent may write — exactly the ones that mean "waiting for the owner".
# One set, three readers: the guard (what a new document may start as), approve.py (what
# the owner can approve from) and `pending` (what the owner is reminded about).
PENDING_STATUSES = {"intent": {"draft"}, "spec": {"draft", "review"}, "plan": {"draft"}, "adr": {"proposed"}}
# An ADR's `scope`: none or "project" = this project's own decision; "engine" = the engine's own rule, which the
# engine's author decides and which never holds up a project's stages (ADR-0011).
SCOPES = ("engine", "project")
# intent.md's `kind`: what is being built. Each kind has its guide, docs/guides/<kind>.md — interview questions,
# stack options with their commands, the first version's scope and how to show the result (D-044).
KINDS = ("website", "game", "agent", "automation", "other")
# Relation fields: which type each one must point to (None = any).
RELATION_TYPES = {"intent": "intent", "spec": "spec", "supersedes": None, "superseded_by": None,
                  "adrs": "adr", "depends_on": None, "related": None, "source": None}
# Bridges between the layers (ADR-0018 §2, tools/graph_layers.py): the link kinds add_layers() writes —
#   changed: commit → file it changed · task: commit → the task its first line names · receipt: task → its ✓ commit or file
#   names: task line → ADR / SPEC / PLAN (T<n>) / P-NNN · req, ac: plan's T<n> → spec's REQ- / AC- · goal: REQ- → G<n>
#   cites: code comment → ADR / SPEC / PLAN / D-NNN · in: a task line or an id inside a file → that file
#   edited, read, made: an episode's session → a file it changed / read, a commit it made (its actions block, §3)
#   imports: a code file → a project file it imports (the code layer, §4)
BRIDGE_KINDS = {"changed", "task", "receipt", "names", "req", "ac", "goal", "cites", "in", "edited", "read", "made",
                "imports"}
# A bridge whose target is not there, and the check's code for it: an error in a file the commit being made changes, a
# warning in an older one (a squash may legally remove a commit); BRIDGE-GIT — git could not tell — is always a warning.
BRIDGE_PROBLEMS = {"no-commit": "BRIDGE-COMMIT", "no-file": "BRIDGE-FILE", "no-id": "BRIDGE-ID", "unchecked": "BRIDGE-GIT"}
PROPOSALS_PATH = "memory/PROPOSALS.md"

LEDGER_PATH = "memory/approvals.md"

WIKILINK_RE = re.compile(r"!?\[\[([^\]\|#\n]*)(#[^\]\|\n]*)?(\|[^\]\n]*)?\]\]")
MDLINK_RE = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
# Text taken from a document — an id, a title, a path — reaches the model (the brief) and a terminal (the status line,
# `stage`, `pending`). A control character (an ANSI escape, a carriage return) or a hidden Unicode one (tags,
# bidirectional controls) reaches neither (review S5); a value never holds a newline — frontmatter is read by lines.
# Built with chr() so this file stays plain ASCII (the `instructions` gate).
UNPRINTABLE_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-"
                            + chr(0x2069) + chr(0xE0000) + "-" + chr(0xE007F) + "]")


def printable(text: str) -> str:
    return UNPRINTABLE_RE.sub("", text)


# ── Data model ───────────────────────────────────────────────────────────────
@dataclass
class Link:
    target: str          # raw target text
    line: int            # 1-based line in the file
    kind: str            # "link", a frontmatter relation name, or a bridge (BRIDGE_KINDS, ADR-0018)
    resolved: str | None = None   # node key (vault-relative posix path) or None
    problem: str | None = None    # "broken" | "ambiguous" | "outside" (leaves the project, review M2) | BRIDGE_PROBLEMS
    src: str = ""        # the file the link is written in, when its node is not a file (a task line, a plan's task)


@dataclass
class Node:
    path: str                     # vault-relative posix path — the node key; a bridge node's key (ADR-0018 §2):
    fm: dict | None = None        # "commit:<sha>", "task:D-NNN", or "<file>#<id>" for an id inside a file
    fm_error: str | None = None
    body_line: int = 1
    links: list[Link] = field(default_factory=list)
    foreign: bool = False
    layer: str = "file"           # "file", or a bridge node: "commit", "task", "anchor"
    origin: str = ""              # where a bridge node is written: "tasks/todo.md:70", "git"

    @property
    def stem(self) -> str:
        if self.layer != "file":
            return self.id
        return Path(self.path).stem if self.path.endswith(".md") else Path(self.path).name

    @property
    def type(self) -> str:
        return str((self.fm or {}).get("type") or "")

    @property
    def status(self) -> str:
        return str((self.fm or {}).get("status") or "")

    @property
    def id(self) -> str:
        return str((self.fm or {}).get("id") or self.stem)

    @property
    def title(self) -> str:
        return str((self.fm or {}).get("title") or "")

    @property
    def scope(self) -> str:
        return str((self.fm or {}).get("scope") or "")

    @property
    def kind(self) -> str:
        return str((self.fm or {}).get("kind") or "")


@dataclass
class Issue:
    level: str   # "error" | "warning"
    code: str
    path: str
    line: int
    message: str
    involves: tuple[str, ...] = ()

    def fmt(self) -> str:
        return f"{self.level.upper():7} {self.code:18} {self.path}:{self.line}  {self.message}"


@dataclass
class Graph:
    root: Path
    nodes: dict[str, Node]
    by_stem: dict[str, list[str]]
    ledger: dict[str, list[str]]  # id -> the statuses the owner ledger records for that document as it is now
    layers: bool = False          # the bridges were read (add_layers, ADR-0018)
    changed: set[str] | None = None  # files the commit being made changes; None = git could not tell
    coverage: dict = field(default_factory=dict)  # what the bridge readers read and what they could not
    code_dirs: tuple[str, ...] = ()  # the product's code folders (code_folders): foreign for links, read for code

    def edges(self) -> list[tuple[str, str, str]]:
        out = []
        for n in self.nodes.values():
            for ln in n.links:
                if ln.resolved:
                    out.append((n.path, ln.resolved, ln.kind))
        return out

    def knowledge_edges(self) -> list[tuple[str, str, str]]:
        """The links the knowledge files themselves write — what an index, an orphan or the context map counts."""
        return [(a, b, k) for a, b, k in self.edges() if k not in BRIDGE_KINDS and self.nodes[a].layer == "file"]

    def find(self, ident: str) -> Node | None:
        """Look a node up by vault path, file stem, or id (case-insensitive) — a bridge node by its id too: D-141, a
        commit's hash or the start of it, `PLAN-0001 T1`, `G1`."""
        ident = ident.strip().removesuffix(".md")
        for key in (ident, ident + ".md", "task:" + ident.upper()):
            if key in self.nodes:
                return self.nodes[key]
        lo = ident.lower()
        for n in self.nodes.values():
            if n.stem.lower() == lo or n.id.lower() == lo:
                return n
        if re.fullmatch(r"[0-9a-f]{7,40}", lo):
            return next((n for n in self.nodes.values() if n.layer == "commit" and str((n.fm or {}).get("sha", "")).startswith(lo)), None)
        return None


# ── Frontmatter (documented YAML subset) ─────────────────────────────────────
def _scalar(raw: str):
    v = raw.strip()
    if not v:
        return ""
    if v[0] in "\"'":
        q, i = v[0], 1
        while i < len(v):
            if q == '"' and v[i] == "\\":
                i += 2
                continue
            if v[i] == q:
                break
            i += 1
        else:
            raise ValueError(f"unterminated quote in {raw!r}")
        return v[1:i].replace('\\"', '"') if q == '"' else v[1:i]
    if v.startswith("[["):
        raise ValueError("UNQUOTED-LINK")
    if v.startswith("["):
        if not v.endswith("]"):
            raise ValueError(f"unterminated list {raw!r}")
        inner = v[1:-1].strip()
        return [_scalar(x) for x in _split_commas(inner)] if inner else []
    if " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    if v in ("true", "false"):
        return v == "true"
    return v


def _split_commas(s: str) -> list[str]:
    parts, cur, quote = [], "", None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def split_frontmatter(text: str) -> tuple[list[str] | None, int]:
    """Return (frontmatter lines, 1-based line where the body starts)."""
    text = text.lstrip("﻿")
    lines = text.split("\n")
    if not lines or lines[0].rstrip() != "---":
        return None, 1
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            return lines[1:i], i + 2
    return None, 1


def parse_frontmatter(text: str) -> tuple[dict | None, int, str | None]:
    fm_lines, body_line = split_frontmatter(text)
    if fm_lines is None:
        if text.lstrip("﻿").startswith("---"):
            return None, 1, "frontmatter opened with --- but never closed"
        return None, 1, None
    data: dict = {}
    key = None
    for n, line in enumerate(fm_lines, start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][\w-]*):(.*)$", line)
        if m:
            key = m.group(1)
            try:
                data[key] = _scalar(m.group(2))
            except ValueError as e:
                if str(e) == "UNQUOTED-LINK":
                    return data, body_line, f"line {n}: wikilink in `{key}` must be quoted, e.g. {key}: \"[[...]]\""
                return data, body_line, f"line {n}: {e}"
            continue
        m = re.match(r"^\s*-\s*(.*)$", line)
        if m and key is not None:
            if data.get(key) in ("", None):
                data[key] = []
            if not isinstance(data[key], list):
                return data, body_line, f"line {n}: list item under non-list key `{key}`"
            try:
                data[key].append(_scalar(m.group(1)))
            except ValueError as e:
                if str(e) == "UNQUOTED-LINK":
                    return data, body_line, f"line {n}: wikilink in `{key}` must be quoted"
                return data, body_line, f"line {n}: {e}"
            continue
        return data, body_line, f"line {n}: unsupported frontmatter syntax: {line.strip()[:60]!r}"
    return data, body_line, None


def _quote(value) -> str:
    s = re.sub(r"[\r\n]+", " ", str(value)).strip()  # a frontmatter value is one physical line (review S15)
    if s == "" or re.search(r"[:#\[\]{}\"',]|^\s|\s$", s):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def set_field(text: str, key: str, value) -> str:
    """Set one frontmatter field (inserting it before the closing --- if absent)."""
    fm_lines, body_line = split_frontmatter(text)
    if fm_lines is None:
        raise ValueError("file has no frontmatter")
    lines = text.lstrip("﻿").split("\n")
    new_line = f"{key}: {_quote(value)}"
    for i in range(1, body_line - 2 + 1):
        if re.match(rf"^{re.escape(key)}:", lines[i]):
            lines[i] = new_line
            return "\n".join(lines)
    lines.insert(body_line - 2, new_line)
    return "\n".join(lines)


STATUS_LINE_RE = re.compile(r"^status:[ \t]*['\"]?([^\s'\"#]+)")


def status_of(text: str | None) -> str | None:
    """The frontmatter status of a document's text, or None (no text, no frontmatter, empty status). A line the reader
    cannot parse stops it, so then the `status:` line is looked for on its own: a broken line above `status: accepted`
    must not hide an approval from the guard (review M3)."""
    if text is None:
        return None
    fm, _, err = parse_frontmatter(text)
    v = (fm or {}).get("status")
    if v in (None, "") and err:
        lines, _ = split_frontmatter(text)
        if lines is None:  # opened with --- and never closed: any line may still be frontmatter
            lines = text.lstrip("﻿").split("\n")[1:]
        v = next((m.group(1) for m in map(STATUS_LINE_RE.match, lines) if m), None)
    return None if v in (None, "") else str(v)


def type_for_path(rel: str, ignore_case: bool = False) -> str | None:
    """The document type a vault-relative path requires. ignore_case=True for the guard:
    on Windows `docs/adr/adr-0001-x.md` is the same file as `docs/adr/ADR-0001-x.md`."""
    probe = rel.lower() if ignore_case else rel
    for pattern, typ in PATH_TYPES:
        if fnmatch.fnmatchcase(probe, pattern.lower() if ignore_case else pattern):
            return typ
    return None


# ── Scanning ─────────────────────────────────────────────────────────────────
def default_root() -> Path:
    env = os.environ.get("CONTEXT_ROOT")
    return Path(env) if env else Path(__file__).resolve().parents[1]


def _is_skipped_dir(rel_dir: str) -> bool:
    parts = [p for p in rel_dir.split("/") if p]
    if any(p.startswith(".") or p in SKIP_NAMES for p in parts):
        return True
    return any(rel_dir == s or rel_dir.startswith(s + "/") for s in SKIP_DIRS)


def holds_typed_docs(rel_dir: str) -> bool:
    """A folder the vault's typed documents live in or under (PATH_TYPES): docs/, docs/adr/, memory/…"""
    return any(pattern.startswith(rel_dir + "/") for pattern, _ in PATH_TYPES)


def code_folders(root: Path) -> tuple[str, ...]:
    """Folders below the root that hold their own code project (CODE_MARKERS) — the product's, foreign here. A marker
    in a folder that holds typed documents makes no product of it: one docs/package.json would otherwise hide every
    ADR and spec from the approval check (review 2026-10-22 H5)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not _is_skipped_dir(f"{rel_dir}/{d}".lstrip("/"))]
        if rel_dir and not holds_typed_docs(rel_dir) and any(m in filenames for m in CODE_MARKERS):
            out.append(rel_dir + "/")
            dirnames[:] = []  # everything below belongs to that project
    return tuple(out)


def iter_vault_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not _is_skipped_dir(f"{rel_dir}/{d}".lstrip("/"))]
        for fn in filenames:
            if fn.startswith("."):
                continue
            suffix = Path(fn).suffix.lower()
            if suffix in LINKABLE_SUFFIXES:
                yield f"{rel_dir}/{fn}".lstrip("/")


def _in_dot_code(rel_dir: str) -> bool:
    return any(rel_dir == d or rel_dir.startswith(d + "/") for d in CODE_DOT_DIRS)


def iter_code_files(root: Path, is_code):
    """Every code file of the project (`is_code`: graph_layers.is_code) — those of the vault's folders and the engine's own
    in CODE_DOT_DIRS —, never another session's research or a dependency or build folder."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in dirnames:
            sub = f"{rel_dir}/{d}".lstrip("/")
            if (sub + "/").startswith(FOREIGN_PREFIXES) or d in SKIP_NAMES:
                continue
            if _in_dot_code(sub) or any(c.startswith(sub + "/") for c in CODE_DOT_DIRS) or not _is_skipped_dir(sub):
                kept.append(d)
        dirnames[:] = kept
        if _is_skipped_dir(rel_dir) and not _in_dot_code(rel_dir):
            continue  # a folder on the way to one of CODE_DOT_DIRS (.claude): nothing of its own is read
        for fn in filenames:
            rel = f"{rel_dir}/{fn}".lstrip("/")
            if not fn.startswith(".") and is_code(rel):
                yield rel


def _extract_body_links(text: str, body_line: int) -> list[Link]:
    lines = text.split("\n")
    out: list[Link] = []
    in_fence = False
    fence = ""
    for idx in range(body_line - 1, len(lines)):
        line = lines[idx]
        stripped = line.lstrip()
        if _is_fence(stripped):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence = True, marker
            elif marker == fence:
                in_fence = False
            continue
        if in_fence:
            continue
        out += _line_links(line, idx + 1)
    return out


def _is_fence(stripped: str) -> bool:
    return stripped.startswith("```") or stripped.startswith("~~~")


def _line_links(line: str, line_no: int = 0) -> list[Link]:
    """The links one line outside a fence holds, as the check reads them: code spans removed first."""
    clean = INLINE_CODE_RE.sub("", line)
    out = [Link(m.group(1).strip(), line_no, "link") for m in WIKILINK_RE.finditer(clean)]
    for m in MDLINK_RE.finditer(clean):
        tgt = m.group(1)
        if _not_a_file(tgt):
            continue  # URLs, mailto:, in-page anchors
        out.append(Link("md:" + tgt, line_no, "link"))
    return out


def _not_a_file(target: str) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I)) or target.startswith("#")


def unlink_unresolved(text: str, rel: str, g: Graph | None, *, value: bool = False) -> str:
    """Text the engine writes into a knowledge file by itself — a compact summary, a model's summary — may name a link
    that does not open in this project: a note that does not exist, a file outside it. In a file no session may edit
    afterwards (another session's episode, guard G3) such a link would stay a graph error for good, so it is written as
    code instead: the words stay, the check no longer reads them as a link. A link that opens stays a link;
    fences and code spans stay as they are. `rel` is the file the text goes into, from the project root (a relative
    link opens from its folder). With no graph — the notes could not be read — no link counts as opening.
    `value=True`: a frontmatter value (an episode's title), where the check reads a wikilink even inside code — such a
    link keeps only its words, as code."""
    node = Node(path=rel)

    def opens(target: str) -> bool:
        if g is None:
            return False
        ln = Link(target, 0, "link")
        _resolve(g, node, ln)
        return ln.problem is None

    def as_code(s: str) -> str:
        return "`" + s.replace("`", "") + "`"

    def closed(line: str) -> bool:
        return all(opens(ln.target) for ln in _line_links(line))

    if value:
        words = WIKILINK_RE.sub(lambda m: m.group(0) if opens(m.group(1).strip()) else as_code(m.group(0).lstrip("!")[2:-2]),
                                text)
        shut = all(opens(m.group(1).strip()) for m in WIKILINK_RE.finditer(words))
        return words if shut else as_code(re.sub(r"[\[\]]", "", text))  # brackets that meet again: none are left

    def fix(line: str) -> str:
        if closed(line):
            return line
        # Code spans masked, not removed, so each link keeps its place in the line — [`a.py`](a.py) is still found
        mask = INLINE_CODE_RE.sub(lambda m: "x" * len(m.group(0)), line)

        def target(m: re.Match) -> str:
            return INLINE_CODE_RE.sub("", line[m.start(1):m.end(1)])

        cuts = [m.span() for m in WIKILINK_RE.finditer(mask) if not opens(target(m).strip())]
        cuts += [m.span() for m in MDLINK_RE.finditer(mask) if not _not_a_file(target(m)) and not opens("md:" + target(m))]
        spans: list[list[int]] = []
        for a, b in sorted(cuts):
            if spans and a < spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], b)
            else:
                spans.append([a, b])
        fixed = line
        for a, b in reversed(spans):
            fixed = fixed[:a] + as_code(fixed[a:b]) + fixed[b:]
        # A link the check reads only once a code span is gone (`]` and `(` apart), or code spans that run together
        # after the cut: the whole line becomes code — never a link that does not open
        return fixed if closed(fixed) else as_code(line)

    out, fence = [], ""
    for line in text.split("\n"):
        stripped = line.lstrip()
        if _is_fence(stripped):
            fence = stripped[:3] if not fence else "" if stripped[:3] == fence else fence
            out.append(line)
        else:
            out.append(line if fence else fix(line))
    return "\n".join(out)


def _frontmatter_links(fm: dict, text: str) -> list[Link]:
    out: list[Link] = []
    lines = text.split("\n")
    for key, val in fm.items():
        vals = val if isinstance(val, list) else [val]
        for v in vals:
            if not isinstance(v, str):
                continue
            for m in WIKILINK_RE.finditer(v):
                line_no = next((i + 1 for i, ln in enumerate(lines[:60]) if ln.startswith(f"{key}:") or m.group(0) in ln), 1)
                out.append(Link(m.group(1).strip(), line_no, key if key in RELATION_TYPES else "link"))
    return out


def load(root: Path | None = None, layers: bool = False, repo: Path | None = None, at_commit: bool = False) -> Graph:
    """The knowledge graph of the files under root; layers=True adds the bridges (add_layers — git history, task lines,
    the ids code comments cite). `repo`, `at_commit`: see add_layers."""
    g = _load_files((root or default_root()).resolve())
    if layers:
        add_layers(g, repo, at_commit)
    return g


def _load_files(root: Path) -> Graph:
    nodes: dict[str, Node] = {}
    products = code_folders(root)
    foreign = FOREIGN_PREFIXES + products
    for rel in iter_vault_files(root):
        node = Node(path=rel, foreign=rel.startswith(foreign))
        if rel.endswith(".md"):
            try:
                text = (root / rel).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
            except OSError as e:
                node.fm_error = f"unreadable: {e}"
                nodes[rel] = node
                continue
            fm, body_line, err = parse_frontmatter(text)
            node.fm, node.body_line, node.fm_error = fm, body_line, err
            if not node.foreign:
                node.links = _extract_body_links(text, body_line)
                if fm:
                    node.links = _frontmatter_links(fm, text) + node.links
        nodes[rel] = node
    by_stem: dict[str, list[str]] = {}
    for key, n in nodes.items():
        # Markdown is linked by stem ([[intent]]); other files by full name ([[x.html]]).
        by_stem.setdefault(n.stem.lower(), []).append(key)
    rows = _read_ledger(root)
    ledger = {n.id: _ledger_statuses(rows[n.id], n) for n in nodes.values() if n.fm and not n.foreign and n.id in rows}
    g = Graph(root=root, nodes=nodes, by_stem=by_stem, ledger=ledger, code_dirs=products)
    for n in nodes.values():
        for ln in n.links:
            _resolve(g, n, ln)
    return g


def _resolve(g: Graph, node: Node, ln: Link) -> None:
    raw = ln.target
    if raw.startswith("md:"):
        tgt = unquote(raw[3:]).split("#", 1)[0]
        if not tgt:
            ln.resolved = node.path
            return
        # A link names a file inside the project (review M2). An absolute or network target (`/Windows/System32`,
        # `//host/share`) is never looked up — on Windows the first is the system folder, the second asks the network
        # on every check — and `..` climbs out of the project, as does a folder link (symlink, junction) inside it.
        if tgt.startswith(("/", "\\")):
            ln.problem = "outside"
            return
        base = Path(node.path).parent
        cand = (base / tgt).as_posix()
        norm = os.path.normpath(cand).replace("\\", "/")
        if norm.startswith("../"):
            ln.problem = "outside"
            return
        if norm in g.nodes:
            ln.resolved = norm
        elif (g.root / norm).exists():
            if (g.root / norm).resolve().is_relative_to(g.root):
                ln.resolved = norm  # an existing folder or non-indexed file: valid, not a node
            else:
                ln.problem = "outside"
        else:
            ln.problem = "broken"
        return
    if not raw:
        ln.problem = "broken"
        return
    if "/" in raw:
        cand = raw if Path(raw).suffix else raw + ".md"
        cand = cand.lstrip("/")
        if cand in g.nodes:
            ln.resolved = cand
        else:
            ln.problem = "broken"
        return
    hits = g.by_stem.get(raw.lower().removesuffix(".md"), [])
    if len(hits) > 1:
        # Same order Obsidian uses, plus one rule of ours: a file in a foreign folder
        # (another session's research) never steals a link from one of our own files.
        owned = [h for h in hits if not g.nodes[h].foreign]
        hits = owned or hits
        here = [h for h in hits if Path(h).parent == Path(node.path).parent]
        if len(here) == 1:
            hits = here
        elif not owned:
            hits = sorted(hits, key=len)[:1]
    if len(hits) == 1:
        ln.resolved = hits[0]
    elif len(hits) > 1:
        ln.problem = "ambiguous"
    else:
        ln.problem = "broken"


def _read_ledger(root: Path) -> dict[str, list[tuple[str, str, str]]]:
    """id -> (the status it moved TO, the row's day YYYY-MM-DD or "", the file it names) for each row, in order."""
    out: dict[str, list[tuple[str, str, str]]] = {}
    p = root / LEDGER_PATH
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or "→" not in cells[2]:
            continue
        ident = cells[1].strip("` ")
        to = cells[2].split("→", 1)[1].strip().split()[0] if cells[2].split("→", 1)[1].strip() else ""
        day = cells[0][:10] if re.match(r"\d{4}-\d{2}-\d{2}", cells[0]) else ""
        out.setdefault(ident, []).append((to, day, cells[3].strip("` ") if len(cells) > 3 else ""))
    return out


def _ledger_statuses(rows: list[tuple[str, str, str]], n: Node) -> list[str]:
    """The statuses the ledger records for document n as it is now (review M4). A row counts only for the file it
    names. Where an approved document cannot change without being reopened (intent, spec, ADR), a row must also be as
    new as the document's `updated` day, so an approval does not outlive a reopen and a rewrite; a plan's `updated`
    moves with its ticks after approval, so for a plan only the file counts. Known gap: a reopen and a rewrite on the
    approval day itself, or one that leaves `updated` as it was."""
    updated = "" if n.type == "plan" else str((n.fm or {}).get("updated") or "")[:10]
    updated = updated if re.fullmatch(r"\d{4}-\d{2}-\d{2}", updated) else ""
    return [to for to, day, path in rows if path == n.path and not (updated and day and day < updated)]


# ── Bridges between the layers (ADR-0018 §2) ─────────────────────────────────────────────────────────────────
def add_layers(g: Graph, repo: Path | None = None, at_commit: bool = False) -> None:
    """Add the bridges to the knowledge graph: every code file with the files it imports (the code layer, §4), commits,
    tasks, proposals, the intent's goals, the specs' requirements and criteria, the plans' tasks, the ids code comments
    cite and the sessions' actions (§3) — each a node or a link that keeps its source line. `repo`:
    the repository whose history and changes count (at commit the checked tree is a copy of the index, without git);
    `at_commit`: the commit being made is what the index holds."""
    import graph_layers as gl  # here, not at the top: the guard imports this module on every tool call
    repo = (repo or g.root).resolve()
    g.layers = True
    seen = _add_code(g, gl)  # first: the commits and the sessions link to the code files it adds
    shas, history_code = _add_commits(g, gl, repo)
    # what the commit being made changes; when git could not read the history, nothing is known, and every broken bridge
    # counts as one in a changed file
    g.changed = gl.changed_paths(repo, at_commit) if shas is not None else None
    _add_tasks(g, gl)
    _add_entries(g, gl)
    _add_actions(g, gl)
    missed: dict[str, int] = {}  # code git knows that is outside the code layer — said, never left out in silence
    for f in history_code - seen:
        if (g.root / f).is_file():
            where = f.split("/", 1)[0] + "/" if "/" in f else f
            missed[where] = missed.get(where, 0) + 1
    g.coverage.update(code_missed=sum(missed.values()), code_missed_kinds=dict(sorted(missed.items())))
    docs = {n.id: n.path for n in g.nodes.values() if n.layer == "file" and not n.foreign and n.type in ("adr", "spec", "plan")}
    top = {p.name for p in g.root.iterdir()}
    for n in list(g.nodes.values()):
        for ln in n.links:
            if ln.kind == "receipt":
                _resolve_receipt(g, gl, repo, at_commit, shas, top, ln)
            elif ln.kind == "made":
                key, problem = _commit_key(g, gl, repo, shas, ln.target)
                ln.resolved, ln.problem = key, problem
            elif ln.kind in ("task", "names", "cites", "req", "ac", "goal") and not ln.resolved and not ln.problem:
                ln.resolved = _bridge_target(g, n, ln, docs)
                # a commit's message is history: a task or plan it names may be gone without anything being wrong
                ln.problem = None if ln.resolved or ln.kind == "task" else "no-id"


def _bridge_node(g: Graph, key: str, layer: str, fm: dict, origin: str) -> Node:
    if key not in g.nodes:
        g.nodes[key] = Node(path=key, fm=fm, layer=layer, origin=origin)
    return g.nodes[key]


def _add_commits(g: Graph, gl, repo: Path) -> tuple[dict[str, str] | None, set[str]]:
    """A node for each commit HEAD reaches, linked to the files it changed and the tasks its first line names. Returns
    full hash → node key for the receipts (None when git could not read the history) and the code files the history
    names."""
    commits, why = gl.read_commits(repo)
    if commits is None:
        g.coverage["commits"] = why
        return None, set()
    shas: dict[str, str] = {}
    files: set[str] = set()
    code = named = 0
    for order, c in enumerate(commits):  # newest first: `order` sorts a node's commits the way git log shows them
        n = _bridge_node(g, f"commit:{c.short}", "commit", {"id": c.short, "type": "commit", "title": c.subject,
                                                            "status": "", "date": c.date, "sha": c.sha, "order": order},
                         "git")
        shas[c.sha] = n.path
        n.links += [Link(f, 0, "changed", resolved=f) for f in c.files if f in g.nodes]
        n.links += [Link(t, 0, "task") for t in c.tasks]
        changed_code = [f for f in c.files if gl.is_code(f)]
        if changed_code:
            code, named = code + 1, named + bool(c.tasks)
            files.update(changed_code)
        for t in c.tasks:  # a task its todo line no longer holds (deleted 14 days after it was done) lives on in git
            if t.startswith("D-"):
                _bridge_node(g, f"task:{t}", "task", {"id": t, "type": "task", "title": c.subject, "status": "history"},
                             f"git {c.short}")
    g.coverage.update(commits=len(commits), since=commits[-1].date if commits else "", code_commits=code, code_named=named)
    return shas, files


def _add_tasks(g: Graph, gl) -> None:
    """tasks/*.md: a node for each D-NNN line, linked to its receipt and to what the line names."""
    lines = 0
    for key in sorted(k for k, n in g.nodes.items() if n.layer == "file" and not n.foreign and re.fullmatch(r"tasks/[^/]+\.md", k)
                      and Path(k).name.lower() != "readme.md"):
        for e in gl.read_task_lines(key, _text(g, key)):
            lines += 1
            fm = {"id": e.id, "type": "task", "title": e.title, "status": "done" if e.done else "open"}
            n = g.nodes.get(f"task:{e.id}")
            if n is not None and n.origin.startswith("git"):  # named by a commit first: its line is the better source
                n.fm, n.origin = fm, f"{key}:{e.line}"
            n = _bridge_node(g, f"task:{e.id}", "task", fm, f"{key}:{e.line}")
            if n.origin != f"{key}:{e.line}":
                continue  # the same id on a second line: the tasks gate names it, the graph keeps the first
            n.links.append(Link(key, e.line, "in", resolved=key, src=key))
            n.links += [Link(i, line, "names", src=key) for i, line in e.named]
            if e.receipt:
                n.links.append(Link(e.receipt, e.line, "receipt", src=key))
    history = sum(1 for n in g.nodes.values() if n.layer == "task" and n.status == "history")
    g.coverage.update(task_lines=lines, task_history=history)


def _add_entries(g: Graph, gl) -> None:
    """Ids inside the project's documents, each a node of its own: proposals, the intent's goals, the specs'
    requirements and criteria (a requirement names its goals), the plans' tasks (each names its requirements and
    criteria)."""
    readers = [(k, gl.read_proposals, "proposal") for k in (PROPOSALS_PATH,) if k in g.nodes]
    for n in list(g.nodes.values()):
        if n.layer != "file" or n.foreign:
            continue
        if n.type in ("intent", "spec"):
            readers.append((n.path, gl.read_rows, "row"))
        elif n.type == "plan":
            readers.append((n.path, gl.read_plan_tasks, "plan-task"))
    for key, read, kind in readers:
        doc = g.nodes[key]
        for e in read(key, _text(g, key)):
            typ = {"REQ": "requirement", "AC": "criterion", "G": "goal"}.get(re.sub(r"[-\d]+$", "", e.id), kind)
            ident = e.id if doc.type in ("intent", "memory") else f"{doc.id} {e.id}"
            status = ("done" if e.done else "open") if kind in ("proposal", "plan-task") else ""
            a = _bridge_node(g, f"{key}#{e.id}", "anchor", {"id": ident, "type": typ, "title": e.title, "status": status},
                             f"{key}:{e.line}")
            a.links.append(Link(key, e.line, "in", resolved=key, src=key))
            for target, line in e.named:
                a.links.append(Link(target, line, "goal" if target.startswith("G") else target.split("-")[0].lower(), src=key))


def _add_actions(g: Graph, gl) -> None:
    """The sessions (ADR-0018 §3): each episode's actions block links it to the files its session changed and read —
    those the graph holds; a file gone since is history, not a broken bridge — and to the commits it made, checked the
    way a receipt's are. An episode with no block, and one whose block says the transcript was not read, are counted."""
    shown = unread = without = 0
    since = ""
    for n in list(g.nodes.values()):
        if n.layer != "file" or n.foreign or n.type != "episode":
            continue
        acts = gl.read_actions(_text(g, n.path))
        if acts is None or not acts.readable:
            without += acts is None
            unread += acts is not None
            continue
        shown += 1
        day = str((n.fm or {}).get("date") or "")
        if day and (not since or day < since):
            since = day
        n.links += [Link(p, line, "edited", resolved=p) for p, line in acts.changed if p in g.nodes and p != n.path]
        n.links += [Link(p, line, "read", resolved=p) for p, line in acts.read if p in g.nodes and p != n.path]
        n.links += [Link(sha, line, "made") for sha, line in acts.commits]
    g.coverage.update(sessions=shown, sessions_since=since, sessions_unread=unread, sessions_without=without)


def _add_code(g: Graph, gl) -> set[str]:
    """The code layer (ADR-0018 §4): every code file is a node — other languages', and the engine's own in CODE_DOT_DIRS,
    included — linked to the project files it imports, and to the ids its comments cite (§2; a TOML file's comments
    too). A product's code folder is read (foreign for link checks, its code still in the graph); another session's
    research is not. Returns the code files the layer holds — read, unreadable or without a reader."""
    for rel in iter_code_files(g.root, gl.is_code):
        if rel not in g.nodes:
            g.nodes[rel] = Node(path=rel, foreign=rel.startswith(g.code_dirs))
    known = gl.Known.of(k for k, n in g.nodes.items() if n.layer == "file")
    seen, unread = set(), []
    styles: dict[str, int] = {}
    readers: dict[str, int] = {}
    none: dict[str, int] = {}
    dynamic = alias = unresolved = 0
    for n in list(g.nodes.values()):
        if n.layer != "file" or n.path.startswith(FOREIGN_PREFIXES):
            continue
        code, reader, style = gl.is_code(n.path), gl.import_reader(n.path), gl.comment_style(n.path)
        if code:
            seen.add(n.path)
        if code and not reader:
            kind = Path(n.path).suffix.lower() or Path(n.path).name
            none[kind] = none.get(kind, 0) + 1
        if not (reader or style):
            continue
        base = next((d.rstrip("/") for d in g.code_dirs if n.path.startswith(d)), "")
        r = gl.read_code(n.path, _text(g, n.path), known, base)
        if not r.readable:
            unread.append(n.path)
            continue
        if style:
            styles[style] = styles.get(style, 0) + 1
        if reader:
            readers[reader] = readers.get(reader, 0) + 1
        n.links += [Link(t, line, "imports", resolved=t) for t, line in r.imports]
        n.links += [Link(i, line, "cites") for i, line in gl.cited_ids(n.path, r.comments)]
        dynamic, alias, unresolved = dynamic + r.dynamic, alias + r.alias, unresolved + r.unresolved
    g.coverage.update(code_files=len(seen), code_styles=styles, code_unread=unread, import_readers=readers,
                      import_none=none, import_dynamic=dynamic, import_alias=alias, import_unresolved=unresolved)
    return seen


def _text(g: Graph, key: str) -> str:
    try:
        return (g.root / key).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    except OSError:
        return ""


def _bridge_target(g: Graph, n: Node, ln: Link, docs: dict[str, str]) -> str | None:
    """The node an id names: a decision, spec or plan by its id; a plan's task; a task; a proposal; inside a spec, its
    requirement or criterion (by the plan's `spec:`); a goal of the intent (by the spec's `intent:`)."""
    ident = ln.target
    if ident.startswith(("ADR-", "SPEC-")):
        return docs.get(ident)
    if ident.startswith("PLAN-"):
        plan, _, task = ident.partition(" ")
        key = docs.get(plan)
        return key if key and not task else (f"{key}#{task}" if key and f"{key}#{task}" in g.nodes else None)
    if ident.startswith("D-"):
        return f"task:{ident}" if f"task:{ident}" in g.nodes else None
    if ident.startswith("P-"):
        return f"{PROPOSALS_PATH}#{ident}" if f"{PROPOSALS_PATH}#{ident}" in g.nodes else None
    doc = g.nodes.get((ln.src or n.path).split("#")[0])
    via = "spec" if ident.startswith(("REQ-", "AC-")) else "intent"
    home = next((x.path for x in _rel_targets(g, doc, via)), None) if doc else None
    return f"{home}#{ident}" if home and f"{home}#{ident}" in g.nodes else None


def _commit_key(g: Graph, gl, repo: Path, shas: dict[str, str] | None, sha: str) -> tuple[str | None, str | None]:
    """The node of a commit a receipt or a session names: (key, None); (None, "no-commit") when this repository does not
    hold it; (None, "unchecked") when git could not tell — no history was read, or the clone is shallow."""
    key = next((k for full, k in (shas or {}).items() if full.startswith(sha)), None)
    if key is None and shas is not None:  # not in the history HEAD reaches: another branch, or past MAX_COMMITS
        ok = gl.commit_exists(repo, sha)
        if ok:
            key = _bridge_node(g, f"commit:{sha}", "commit", {"id": sha, "type": "commit", "title": "", "status": "",
                                                              "sha": sha}, "git").path
        elif ok is False and gl.git_answers(repo, "rev-parse", "--is-shallow-repository")[1] != "true":
            return None, "no-commit"
    return (key, None) if key else (None, "unchecked")


def _resolve_receipt(g: Graph, gl, repo: Path, at_commit: bool, shas: dict[str, str] | None, top: set[str],
                     ln: Link) -> None:
    """A receipt names a commit or a file: the first one it names is the link; every one is checked."""
    commits, paths = gl.receipt_parts(ln.target, top)
    found: list[str] = []
    for sha in commits:
        key, problem = _commit_key(g, gl, repo, shas, sha)
        if problem or key is None:
            ln.problem, ln.target = problem or "unchecked", sha
            return
        found.append(key)
    for token in paths:
        ok = gl.path_status(g.root, repo, token, at_commit)
        if ok is None:
            ln.problem, ln.target = "unchecked", token
            return
        if not ok:
            ln.problem, ln.target = "no-file", token
            return
        found += [k for k in (token, token + ".md") if k in g.nodes][:1]
    ln.resolved = found[0] if found else None


# ── Checks ───────────────────────────────────────────────────────────────────
def check(g: Graph) -> list[Issue]:
    issues: list[Issue] = []
    ids: dict[str, list[str]] = {}
    for n in g.nodes.values():
        if not n.path.endswith(".md") or n.foreign:
            continue
        expected = type_for_path(n.path)
        if n.fm_error:
            issues.append(Issue("error", "FM-PARSE", n.path, 1, n.fm_error))
        fm = n.fm or {}
        if expected and not n.fm:
            issues.append(Issue("error", "FM-MISSING", n.path, 1, f"this location requires frontmatter with type: {expected}"))
            continue
        if not n.fm:
            continue
        typ = n.type
        if expected and typ != expected:
            issues.append(Issue("error", "FM-TYPE", n.path, 1, f"type is {typ!r}, this location requires {expected!r}"))
        schema = SCHEMA.get(typ)
        if schema is None:
            if typ:
                issues.append(Issue("error", "FM-TYPE", n.path, 1, f"unknown type {typ!r} (known: {', '.join(SCHEMA)})"))
            continue
        for req in schema["required"]:
            if fm.get(req) in (None, "", []):
                issues.append(Issue("error", "FM-REQUIRED", n.path, 1, f"missing required field `{req}` for type {typ}"))
        if schema["status"] and fm.get("status") not in (None, "") and fm.get("status") not in schema["status"]:
            issues.append(Issue("error", "FM-STATUS", n.path, 1,
                                f"status {fm.get('status')!r} is not valid for {typ} (allowed: {', '.join(schema['status'])})"))
        pat = ID_PATTERNS.get(typ)
        if pat and fm.get("id"):
            if not re.fullmatch(pat, str(fm["id"])):
                issues.append(Issue("error", "FM-ID", n.path, 1, f"id {fm['id']!r} does not match {pat}"))
            elif not n.stem.startswith(str(fm["id"])):
                issues.append(Issue("error", "FM-ID", n.path, 1, f"file name must start with its id {fm['id']!r}"))
        if typ == "adr" and n.scope and n.scope not in SCOPES:
            issues.append(Issue("error", "SCOPE", n.path, 1,
                                f"scope {n.scope!r} is not valid for an adr (allowed: {', '.join(SCOPES)}; "
                                "none = project) — an engine ADR stays out of the project's stages (ADR-0011)"))
        if typ == "intent" and n.kind and n.kind not in KINDS:
            issues.append(Issue("error", "KIND", n.path, 1, f"kind {n.kind!r} is not a project type (allowed: "
                                f"{', '.join(KINDS)}) — the stage could not name its guide in docs/guides/"))
        if fm.get("id"):
            ids.setdefault(str(fm["id"]), []).append(n.path)

    for ident, paths in ids.items():
        if len(paths) > 1:
            for p in paths:
                issues.append(Issue("error", "ID-DUP", p, 1, f"id {ident!r} is used by {len(paths)} files: {', '.join(paths)}", tuple(paths)))

    known_ids = {n.id.lower(): n.stem for n in g.nodes.values() if n.fm and n.fm.get("id") and n.layer == "file"}
    for n in g.nodes.values():
        for ln in n.links:
            if ln.problem == "broken":
                shown = ln.target[3:] if ln.target.startswith("md:") else f"[[{ln.target}]]"
                hint = ""
                stem = known_ids.get(ln.target.lower())
                if stem and stem != ln.target:
                    hint = f" — use [[{stem}]] (links name the file, not the id)"
                issues.append(Issue("error", "LINK-BROKEN", n.path, ln.line, f"{shown} does not resolve{hint}"))
            elif ln.problem == "ambiguous":
                issues.append(Issue("error", "LINK-AMBIGUOUS", n.path, ln.line,
                                    f"[[{ln.target}]] matches several files — use a path link such as [[folder/{ln.target}]]"))
            elif ln.problem == "outside":
                issues.append(Issue("error", "LINK-OUTSIDE", n.path, ln.line,
                                    f"{ln.target[3:]} points outside the project — link a file inside it, by a relative path"))

    issues += _check_relations(g)
    issues += _check_chain_and_ledger(g)
    issues += _check_orphans(g)
    issues += _check_specs(g)
    if g.layers:
        issues += _check_bridges(g)
    return issues


def _check_bridges(g: Graph) -> list[Issue]:
    """A bridge whose target is not there, at its source line (ADR-0018 §2): an error in a file the commit being made
    changes — as a broken link is —, a warning in an older file (a squash may legally take a commit away, and history is
    not rewritten for a check); a bridge git could not check is a warning, never a pass."""
    out = []
    for n in g.nodes.values():
        for ln in n.links:
            code = BRIDGE_PROBLEMS.get(ln.problem or "")
            if not code:
                continue
            src = ln.src or n.path
            old = g.changed is not None and src not in g.changed
            level = "warning" if code == "BRIDGE-GIT" or old else "error"
            who = n.id if n.layer != "file" or ln.kind == "made" else "a comment"  # made: an episode's actions block
            what = {"BRIDGE-COMMIT": f"{who} cites commit {ln.target}, which does not exist in this repository",
                    "BRIDGE-FILE": f"{who}'s receipt names {ln.target}, which does not exist",
                    "BRIDGE-ID": f"{who} names {ln.target}, which is nowhere in the project — correct it, or write it "
                                 f"as code (`{ln.target}`) if it is only a name",
                    "BRIDGE-GIT": f"{who} cites {ln.target}, which git could not check here (no repository, or a "
                                  "shallow clone) — the bridge is unchecked"}[code]
            out.append(Issue(level, code, src, ln.line, what + (" (a file this commit does not change)" if old and
                                                                code != "BRIDGE-GIT" else "")))
    return out


def _rel_targets(g: Graph, n: Node, key: str) -> list[Node]:
    return [g.nodes[ln.resolved] for ln in n.links if ln.kind == key and ln.resolved in g.nodes]


def _check_relations(g: Graph) -> list[Issue]:
    out: list[Issue] = []
    for n in g.nodes.values():
        if n.foreign or not n.fm:
            continue
        for ln in n.links:
            if ln.kind not in RELATION_TYPES or not ln.resolved or ln.resolved not in g.nodes:
                continue
            want = RELATION_TYPES[ln.kind]
            if ln.kind in ("supersedes", "superseded_by"):
                want = n.type
            tgt = g.nodes[ln.resolved]
            if want and tgt.type != want:
                out.append(Issue("error", "REL-TYPE", n.path, ln.line,
                                 f"`{ln.kind}` must point to a {want}, but {tgt.path} is {tgt.type or 'untyped'}", (tgt.path,)))
    return out


def _check_chain_and_ledger(g: Graph) -> list[Issue]:
    out: list[Issue] = []
    for n in g.nodes.values():
        if n.foreign or not n.fm:
            continue
        typ, st = n.type, n.status
        if typ == "spec" and st in ("approved", "superseded"):
            intents = _rel_targets(g, n, "intent")
            if not intents or intents[0].status != "accepted":
                shown = intents[0].status if intents else "missing"
                out.append(Issue("error", "CHAIN-SPEC", n.path, 1,
                                 f"spec is {st} but its intent is {shown} — the owner must accept intent.md first",
                                 tuple(i.path for i in intents)))
        if typ == "plan" and st in ("approved", "in-progress", "done", "live"):
            specs = _rel_targets(g, n, "spec")
            if not specs or specs[0].status != "approved":
                shown = specs[0].status if specs else "missing"
                out.append(Issue("error", "CHAIN-PLAN", n.path, 1,
                                 f"plan is {st} but its spec is {shown} — a plan runs only on an approved spec",
                                 tuple(s.path for s in specs)))
        if typ in ("adr", "spec") and st in ("accepted", "approved"):
            for old in _rel_targets(g, n, "supersedes"):
                back = [x.path for x in _rel_targets(g, old, "superseded_by")]
                if old.status != "superseded" or n.path not in back:
                    out.append(Issue("error", "SUPERSEDE", n.path, 1,
                                     f"supersedes {old.stem}, which must be status superseded with superseded_by pointing back",
                                     (old.path,)))
        if st == "superseded":
            newer = [x for x in _rel_targets(g, n, "superseded_by") if x.status in ("accepted", "approved")]
            if not newer:
                out.append(Issue("error", "SUPERSEDE", n.path, 1, "status superseded, but no accepted/approved document supersedes it"))
        need = _ledger_requirement(typ, st)
        if need and need not in g.ledger.get(n.id, []):
            out.append(Issue("error", "LEDGER", n.path, 1,
                             f"status {st!r} has no owner record in {LEDGER_PATH} (expected a row for {n.id} → {need}); "
                             f"only /approve may set it", (LEDGER_PATH,)))
    return out


def _ledger_requirement(typ: str, st: str) -> str | None:
    if typ == "intent" and st == "accepted":
        return "accepted"
    if typ == "spec" and st == "approved":
        return "approved"
    if typ == "plan" and st == "live":
        return "live"
    if typ == "plan" and st in ("approved", "in-progress", "done"):
        return "approved"
    if typ == "adr" and st in ("accepted", "rejected", "superseded"):
        return st
    if typ == "spec" and st == "superseded":
        return "superseded"
    return None


def _check_orphans(g: Graph) -> list[Issue]:
    inbound: dict[str, int] = {}
    for src, dst, _ in g.knowledge_edges():
        if src != dst:
            inbound[dst] = inbound.get(dst, 0) + 1
    out = []
    for n in g.nodes.values():
        if not n.foreign and n.type in ("spec", "plan", "adr", "domain") and not inbound.get(n.path):
            out.append(Issue("warning", "ORPHAN", n.path, 1, "nothing links here — link it from its index or a related document"))
    return out


# ── A spec the owner is asked to approve ─────────────────────────────
# From `review` on, the spec is what the owner judges: a line left from the template, an empty cell in the requirements
# or criteria table, or more than three open questions fails here (and approve.py refuses a document with errors).
# A draft is still being written; a superseded spec is history and is not reopened for this.
SPEC_TEMPLATE = ".claude/skills/spec/template.md"
SPEC_CHECKED = ("review", "approved")
SPEC_MAX_QUESTIONS = 3
SPEC_TOKEN_RE = re.compile(r"\bN{3,4}\b|YYYY-MM-DD|<[" + chr(0x10D0) + "-" + chr(0x10FF) + r"][^<>\n]*[^\s<>]>")  # <ქართული>
SPEC_DOTS_RE = re.compile(r"(?:^|\|)\s*(?:…|\.\.\.)\s*(?=\||$)"                                    # a cell that is only …
                          r"|^(?:[-*+]|\d+[.)])\s+(?:\*\*[^*\n]+\*\*\s*)?(?:…|\.\.\.)(?=\s|$)"     # a bullet that opens with …
                          r"|\b(?:Given|When|Then)\s+…")
SPEC_ROW_RE = re.compile(r"^\|\s*\**((?:REQ|AC)-\d+)\**\s*\|")
SPEC_EMPTY_RE = re.compile(r"^(?:[\s\-–—.?]*|todo|tbd|tktk)$", re.I)
SPEC_QUESTIONS_RE = re.compile(r"^#{1,2}\s+(?:\d+\.\s*)?ღია კითხვები")
SPEC_ITEM_RE = re.compile(r"^ {0,3}(?:[-*+]|\d+[.)])\s+(.*)$")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_table_sep(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") and "---" in s and not s.strip("|-: \t")


def _norm(line: str) -> str:
    s = line.strip()
    return "|".join(_cells(s)) if s.startswith("|") else " ".join(s.split())


def _prose_lines(text: str, start: int):
    """(1-based number, line) for every line from `start` on that is outside a fenced code block."""
    lines, fence = text.split("\n"), ""
    for idx in range(start - 1, len(lines)):
        mark = lines[idx].lstrip()[:3]
        if mark in ("```", "~~~"):
            fence = "" if fence == mark else (fence or mark)
            continue
        if not fence:
            yield idx + 1, lines[idx]


def _template_lines(root: Path) -> set[str] | None:
    """The spec template's own text lines — not its headings, table heads or rules; a spec still holding one is unfinished."""
    try:
        text = (root / SPEC_TEMPLATE).read_text(encoding="utf-8").replace("\r\n", "\n")
    except OSError:
        return None
    rows = list(_prose_lines(text, split_frontmatter(text)[1]))
    return {_norm(line) for i, (_, line) in enumerate(rows) if line.strip() and not line.strip().startswith("#")
            and not _is_table_sep(line) and not (i + 1 < len(rows) and _is_table_sep(rows[i + 1][1]))}


def _check_specs(g: Graph) -> list[Issue]:
    specs = [n for n in g.nodes.values() if not n.foreign and n.type == "spec" and n.status in SPEC_CHECKED]
    template = _template_lines(g.root) if specs else set()
    out: list[Issue] = []
    for n in specs:
        if template is None:  # half of the check cannot run, and that is not a pass (review Q6) — filed under the spec,
            # so /approve and the Stop-gate, which keep the issues of the files they touch, see it too (review round 2)
            out.append(Issue("error", "SPEC-NO-TEMPLATE", n.path, 1, f"the spec template ({SPEC_TEMPLATE}) is missing, "
                             "so a line left from it cannot be recognised here — restore it (`git checkout -- "
                             f"{SPEC_TEMPLATE}`); only the placeholder marks (NNNN, YYYY-MM-DD, <…>, …) were checked",
                             (SPEC_TEMPLATE,)))
        try:
            text = (g.root / n.path).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        except OSError as e:
            out.append(Issue("error", "SPEC-UNREAD", n.path, 1, f"could not be read for the spec check: {e}"))
            continue
        fix = (" — it is approved: reopen it (an edit that only sets status: draft), fix it, and the owner approves it "
               "again" if n.status == "approved" else "")
        start = split_frontmatter(text)[1]
        header: list[str] = []
        prev, questions, q_line, in_q = "", 0, 0, False
        for no, line in _prose_lines(text, 1):
            s, body = line.strip(), no >= start
            bare = INLINE_CODE_RE.sub("", s)
            if body and re.match(r"^#{1,2}\s", s):
                in_q = bool(SPEC_QUESTIONS_RE.match(s))
                q_line = no if in_q else q_line
            elif in_q and (m := SPEC_ITEM_RE.match(line)) and not m.group(1).startswith("~~") \
                    and m.group(1).strip() not in ("…", "..."):
                questions += 1
            why = ("placeholder" if SPEC_TOKEN_RE.search(bare) or (body and SPEC_DOTS_RE.search(bare))
                   else "text" if body and s and _norm(s) in (template or set()) else "")
            row = SPEC_ROW_RE.match(s) if body and not why else None
            cells = _cells(s) if row else []
            if row and header:  # Markdown shows a short row's missing cells empty and drops cells past the header
                cells = (cells + [""] * len(header))[:len(header)]
            empty = [i for i, c in enumerate(cells) if SPEC_EMPTY_RE.match(c)]
            if why:
                out.append(Issue("error", "SPEC-TEMPLATE", n.path, no, f"still the template's {why}: {printable(s[:60])!r} "
                                 f"— at `{n.status}` every line is the spec's own{fix}"))
            elif empty:
                col = header[empty[0]] if empty[0] < len(header) else f"column {empty[0] + 1}"
                out.append(Issue("error", "SPEC-EMPTY", n.path, no, f"{row.group(1)}: the `{col}` cell is empty — at "
                                 f"`{n.status}` every cell of the requirements and criteria tables is filled{fix}"))
            if _is_table_sep(s):
                header = _cells(prev)
            prev = s
        if questions > SPEC_MAX_QUESTIONS:
            out.append(Issue("error", "SPEC-QUESTIONS", n.path, q_line, f"{questions} open questions — at `{n.status}` "
                             f"a spec keeps at most {SPEC_MAX_QUESTIONS}: ask the rest in the chat, one per message, and "
                             f"write the answers into the spec{fix}"))
    return out


def filter_issues(issues: list[Issue], files: list[str], root: Path) -> list[Issue]:
    want = set()
    for f in files:
        p = Path(f)
        try:
            rel = (p if p.is_absolute() else (Path.cwd() / p)).resolve().relative_to(root).as_posix()
        except ValueError:
            rel = f.replace("\\", "/")
        want.add(rel)
    return [i for i in issues if i.path in want or any(x in want for x in i.involves)]


# ── Views ────────────────────────────────────────────────────────────────────
PLACEHOLDER_RE = re.compile(r"^(?:_.*_|<!--.*-->)$")  # the template's own lines in an empty intent section


def is_engine(n: Node) -> bool:
    """An engine ADR (`scope: engine`) is the engine's own rule — the engine author decides it, not the project."""
    return n.type == "adr" and n.scope == "engine"


def idea_written(path: Path) -> bool:
    """True when intent.md's §1 holds more than the template's `_…_` placeholder lines."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    m = re.search(r"^## 1\b[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        return True  # no §1 heading: a hand-made intent — its draft status still sends it through the interview
    return any(ln.strip() and not PLACEHOLDER_RE.match(ln.strip()) for ln in m.group(1).splitlines())


QUESTION_RE = re.compile(r"^\s*(?:\d+[.)]|[-*+])\s+\S")  # a list item in §7: an interview question still open
BUILDER_CHECKED = "მშენებლის შემოწმება"  # what /intent writes into the history once the builder check has run


def interview_state(path: Path) -> str:
    """Where intent.md's interview stands (D-083): "open" while §7 holds a question — or the file has no §7, a hand-made
    intent —, "check" once §7 is empty and the history has no builder-check line, "done" once it has one."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "open"
    q = re.search(r"^## 7\b[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not q or any(QUESTION_RE.match(ln) for ln in q.group(1).splitlines()):
        return "open"
    h = re.search(r"^## ცვლილებების ისტორია[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return "done" if h and BUILDER_CHECKED in h.group(1) else "check"


def pending(g: Graph, engine: bool = False) -> list[Node]:
    """Documents waiting for the owner's /approve: the project's own, or (engine=True) the engine's ADRs. An intent
    whose §1 is still the template is not offered — there is nothing in it to approve yet —, nor one whose interview
    is over while its builder check has not run (D-083). A finished plan (`done`) waits for the owner's `/approve live N`
    (ADR-0013)."""
    out = [n for n in g.nodes.values() if not n.foreign and n.type in PENDING_STATUSES
           and (n.status in PENDING_STATUSES[n.type] or (n.type == "plan" and n.status == "done"))
           and is_engine(n) == engine
           and not (n.type == "intent" and (not idea_written(g.root / n.path)
                                            or interview_state(g.root / n.path) == "check"))]
    order = {"intent": 0, "spec": 1, "plan": 2, "adr": 3}
    return sorted(out, key=lambda n: (order.get(n.type, 9), n.id))


def approve_hint(n: Node) -> str:
    if n.type == "intent":
        return "/approve intent"
    m = re.fullmatch(r"[A-Z]+-(\d{4})", n.id)
    if not m:  # e.g. SPEC-0002-0001 would otherwise read as `/approve spec 0001` — a different document (review S5)
        return "(id არასწორია — ჯერ frontmatter-ის id უნდა გასწორდეს)"
    if n.type == "plan" and n.status == "done":  # the owner's word after the show and the pilot (ADR-0013)
        return f"/approve live {m.group(1)}"
    return f"/approve {n.type} {m.group(1)}"


# ── Stage conductor (ADR-0011) ───────────────────────────────────────────────
# The stages are not new: they are ADR-0001's loop (intent → spec → plan → code → gates → review → show → run and
# observe, ADR-0013) and plan.md's phases F1–F6. The conductor stores nothing — each call reads the same statuses the
# graph reads and says where the project stands and what comes next, for the person and for the agent. Stage 6 begins
# with the owner's own word: a finished plan (`done`) becomes `live` only through `/approve live N`.
STAGES = {1: "განზრახვა", 2: "სპეციფიკაცია", 3: "არქიტექტურა", 4: "გეგმა და აშენება", 5: "ჩვენება და პილოტი",
          6: "გაშვება და დაკვირვება"}


@dataclass
class Stage:
    number: int
    short: str         # the status line's text — a few words
    step: str          # where the project stands, one sentence
    person: str        # what the person does next
    agent: str         # what the agent does next
    command: str = ""  # the person's exact command, when the next move is theirs
    doc: str = ""      # the document in focus (vault path)

    @property
    def name(self) -> str:
        return STAGES[self.number]

    @property
    def label(self) -> str:
        return f"ეტაპი {self.number}/{len(STAGES)} · {self.name}"

    def status_line(self) -> str:
        return printable(f"{self.label} — {self.short}" + (f" → {self.command}" if self.command else ""))

    def block(self) -> str:
        where = f" (`{self.doc}`)" if self.doc else ""
        path = " → ".join(f"{k} {v}" for k, v in STAGES.items())
        return printable("\n".join([
            "## ეტაპი — სად დგას პროექტი (`bash .claude/hooks/py.sh tools/context_graph.py stage`, ADR-0011)",
            f"- **{self.label}** — {self.step}{where}",
            f"- ადამიანს: {self.person}",
            f"- აგენტს: {self.agent}",
            f"- გზა (ADR-0001-ის ციკლი, plan.md-ის F1–F6): {path}. ადამიანს ეტაპი ჩვეულებრივი სიტყვებით უთხარი, "
            "ბრძანება — ზუსტად.",
            "- ეს ბლოკი ყოველ ჯერზე დოკუმენტების სტატუსებიდან ითვლება: თუ progress.md-ის, plan.md-ის ან tasks/todo.md-ის "
            "ჩანაწერი მას ეწინააღმდეგება, ის ჩანაწერი ძველია — ამ ბლოკს მიჰყევი, ჩანაწერი კი `/session-close`-ით გაასწორე.",
        ]))


def guide_note(g: Graph, section: str) -> str:
    """Where the project type's guide covers this step — empty while the type or its guide is unknown (D-044)."""
    intent = g.nodes.get("intent.md")
    kind = intent.kind if intent is not None and intent.kind in KINDS else ""
    path = f"docs/guides/{kind}.md"
    return f"; სახელმძღვანელო — `{path}` {section}" if kind and (g.root / path).is_file() else ""


def code_checks_off(root: Path) -> bool:
    """True when gates.toml has both level-1 code checks (`lint`, `unit`) and both are switched off. A missing or
    unreadable file is not "off": the stage then says nothing rather than guess."""
    try:
        data = tomllib.loads((root / "tools/gates/gates.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    gates = {g.get("id"): g for g in data.get("gate", []) if isinstance(g, dict)}
    return all(i in gates and not gates[i].get("enabled", False) for i in ("lint", "unit"))


NEEDS_KIND = ("ჯერ ჩაწერე intent.md-ის frontmatter-ში პროექტის ტიპი — `kind:` website / game / agent / automation / "
              "other (ცხრილი: `docs/guides/other.md`) — და კითხვები მისი სახელმძღვანელოს §1-დან აიღე; ")
CHECKS_FIRST = ("ჯერ ჩართე კოდის შემოწმებები (გეგმის პირველი ამოცანა): `tools/gates/gates.toml`-ში `lint` — ახლავე, "
                "`unit` — პირველ ტესტთან ერთად (ცარიელი ტესტების გაშვება არაფერს ამტკიცებს), სტეკის ADR-ის ბრძანებებით "
                "და მხოლოდ პროექტის საკუთარ კოდზე (არა ძრავის `tools/`-ზე); ფაილი დაცულია — ადამიანს „კი“ ჰკითხე, ხელით "
                "რედაქტირებას ნუ სთხოვ; მერე ")


def _review(number: int, doc: Node, step: str, fix: str) -> Stage:
    """A document waits for the person: they read it and approve it, or say what to change."""
    cmd = approve_hint(doc)
    return Stage(number, short=f"{doc.id} გელოდება", step=step,
                 person=f"აგენტი ჩატში მოკლედ გაჩვენებს, რა წერია (ფაილი — `{doc.path}`); თუ ეთანხმები — `{cmd}`, "
                        "თუ არა — თქვი, რა შეიცვალოს",
                 agent=f"{doc.id}: ჩატში აჩვენე მოკლე შეჯამება — რას გააკეთებს, რას არა, რა უნდა გადაწყვიტოს ადამიანმა "
                       f"(ფაილის წაკითხვას ნუ სთხოვ); შეასწორე მისი შენიშვნებით ({fix}); დამტკიცება მხოლოდ მისი `{cmd}`-ია, "
                       "მის შემდეგ კი ეგრევე შეინახე (CHECKPOINT commit) და შემდეგ ნაბიჯზე გადადი — „გავაგრძელო?“-ს ნუ იკითხავ",
                 command=cmd, doc=doc.path)


def project_stage(g: Graph) -> Stage:
    """Where the project stands, read from intent.md, the newest spec, the project's ADRs and that spec's plan."""
    intent = g.nodes.get("intent.md")
    if intent is None or intent.status != "accepted":
        if intent is None or not idea_written(g.root / intent.path):
            return Stage(1, short="დაწერე შენი იდეა", step="იდეა ჯერ არ არის ჩაწერილი",
                         person="დაწერე შენი იდეა ჩვეულებრივი სიტყვებით: რა გინდა შექმნა და ვისთვის",
                         agent="როცა ადამიანი იდეას დაწერს — `/intent`: ჩაწერე ის intent.md-ის §1-ში მისივე სიტყვებით "
                               "და frontmatter-ში ტიპი (`kind:` website / game / agent / automation / other), მერე ინტერვიუ, "
                               "ერთი კითხვა ერთ ჯერზე, `docs/guides/<kind>.md` §1-ით. setup-ს ნუ სთხოვ — ძრავა უკვე აწყობილია",
                         doc="intent.md")
        interview = interview_state(g.root / intent.path)
        if interview == "check":  # §7 is empty: one step only — the approval is not named until the check has run (D-083)
            return Stage(1, short="მშენებლის შემოწმება", step="ინტერვიუ დასრულდა — ტექსტის შემოწმება ჯერ არ გაკეთებულა",
                         person="დაელოდე — აგენტი `intent.md`-ს ცალკე აგენტს წააკითხებს, რომელსაც თქვენი საუბარი არ "
                                "უნახავს, და გკითხავს მხოლოდ იმას, რაც მას ამ ტექსტით აშენებისას დააკლდებოდა",
                         agent="ახლა მხოლოდ მშენებლის შემოწმება (`/intent`, ნაბიჯი 4; ტექსტი — "
                               "`.claude/skills/intent/builder-check.md`): ერთი ახალი subagent `intent.md`-ს მარტო ტექსტით "
                               "კითხულობს. მისი კითხვებიდან ის, რასაც ტექსტი ან საუბარი უკვე პასუხობს, ჩაწერე; წვრილმანი "
                               "თავად გადაწყვიტე და **ჰიპოთეზად** მონიშნე; რასაც მხოლოდ ადამიანი უპასუხებს (მაქსიმუმ სამი), "
                               "§7-ში ჩაწერე და ერთ შეტყობინებაში ჰკითხე; მერე `intent.md`-ის ცვლილებების ისტორიაში "
                               f"ჩაწერე ხაზი „{BUILDER_CHECKED}: …“ — დამტკიცებას მანამდე ნუ შესთავაზებ",
                         doc="intent.md")
        if interview == "done":
            return _review(1, intent, "ინტერვიუ და მისი შემოწმება დასრულდა — განზრახვა შენს დამტკიცებას ელოდება",
                           "`/intent`")
        return Stage(1, short="ინტერვიუ", step="ინტერვიუ — განზრახვა იწერება",
                     person="უპასუხე კითხვებს; როცა intent.md შენს აზრს სწორად ასახავს — `/approve intent`",
                     agent=("" if intent.kind in KINDS else NEEDS_KIND)
                     + "გააგრძელე `/intent`-ის ინტერვიუ — ერთი კითხვა ერთ შეტყობინებაში, 2–3 ვარიანტითა და "
                       "რეკომენდაციით; როცა ღია კითხვა აღარ დარჩება, ჯერ მშენებლის შემოწმება (`/intent`, ნაბიჯი 4; "
                       "ტექსტი — `.claude/skills/intent/builder-check.md`) და მისი ხაზი `intent.md`-ის ისტორიაში, მერე "
                       "მოკლედ აჩვენე, რა ჩაიწერა, და შესთავაზე `/approve intent`"
                     + guide_note(g, "§1 — კითხვები (ისინი §7-ის შაბლონურ სიას ცვლის: §7-ში მხოლოდ ჯერ უპასუხო "
                                     "კითხვები დატოვე)"),
                     command="/approve intent", doc="intent.md")
    specs = sorted((n for n in g.nodes.values() if n.type == "spec" and not n.foreign and n.status != "superseded"),
                   key=lambda n: n.id)
    if not specs:
        return Stage(2, short="აგენტი წერს სპეციფიკაციას", step="განზრახვა დამტკიცებულია — სპეციფიკაცია ჯერ არ არის",
                     person="დაელოდე — აგენტი წერს სპეციფიკაციას: რა უნდა შეეძლოს შედეგს, შემოწმებადი კრიტერიუმებით",
                     agent="დაწერე პირველი სპეციფიკაცია: `/spec`" + guide_note(g, "§3 — პირველი ვერსიის ფარგლები"))
    spec = specs[-1]
    if spec.status != "approved":
        return _review(2, spec, f"{spec.id} შენს გადახედვას ელოდება",
                       "`/spec`; წარდგენამდე — spec-reviewer და მშენებლის შემოწმება")
    adrs = [n for n in g.nodes.values() if n.type == "adr" and not n.foreign and not is_engine(n)]
    if not any(n.status == "accepted" for n in adrs):
        proposed = sorted((n for n in adrs if n.status == "proposed"), key=lambda n: n.id)
        if proposed:
            return _review(3, proposed[0], f"{proposed[0].id} (რით აშენდეს) შენს გადაწყვეტილებას ელოდება", "`/adr`")
        return Stage(3, short="აგენტი სტეკს გთავაზობს",
                     step=f"{spec.id} დამტკიცებულია — ჯერ არ არის გადაწყვეტილი, რით აშენდეს",
                     person="აგენტი შემოგთავაზებს, რით აშენდეს (ტექნოლოგია, ჰოსტინგი) — აირჩიე",
                     agent="შესთავაზე 2–3 ვარიანტი რეკომენდაციით; არჩეული ჩაწერე `/adr`-ით (`scope`-ის გარეშე — ეს "
                           "პროექტის გადაწყვეტილებაა); ADR-ში ჩაწერე ხუთი ბრძანება — install · run · lint · test · show"
                           + guide_note(g, "§2 — ვარიანტები და მათი ბრძანებები"))
    plans = sorted((n for n in g.nodes.values() if n.type == "plan" and not n.foreign
                    and any(t.path == spec.path for t in _rel_targets(g, n, "spec"))), key=lambda n: n.id)
    if not plans:
        return Stage(4, short="აგენტი გეგმას ადგენს", step=f"{spec.id}-ს გეგმა ჯერ არ აქვს",
                     person="დაელოდე — აგენტი გეგმას ადგენს: რა ამოცანებად აშენდება და როგორ შემოწმდება",
                     agent=f"`/feature-plan` — გეგმა {spec.id}-ზე")
    plan = plans[-1]
    if plan.status == "draft":
        return _review(4, plan, f"{plan.id} შენს გადახედვას ელოდება", "`/feature-plan`")
    if plan.status == "live":  # the owner's `/approve live N` after the show and the pilot (ADR-0013)
        return Stage(6, short="ცოცხალია — დააკვირდი", step=f"{plan.id} ცოცხალშია — გაშვება და დაკვირვება",
                     person="დააკვირდი ცოცხალ შედეგს: რას ამბობენ მომხმარებლები, სად ცდება, რა ჯდება; რაც არ მუშაობს ან "
                            "აკლია — უბრალოდ დაწერე, ის ახალი სპეციფიკაცია გახდება",
                     agent="დაკვირვების რიტმი და საზომები — სპეციფიკაციის §6 (წარმატების საზომი) და გაიდის §6; ხარჯი და "
                           "აგენტების საქმე — `/observatory`; AI-პროდუქტზე eval-ნაკრები მოდელის ან ინსტრუქციის ყოველ "
                           "ცვლილებაზე თავიდან ეშვება (drift); ცოცხალი შეცდომა ჯერ ტესტი ან eval-შემთხვევა ხდება, მერე "
                           "ამოცანა ან ახალი `/spec` — უკუკავშირის მარყუჟი (ADR-0013)"
                           + guide_note(g, "§6 — გაშვება და დაკვირვება"), doc=plan.path)
    if plan.status != "done":
        return Stage(4, short=f"{plan.id} მიმდინარეობს", step=f"{plan.id} მიმდინარეობს — აგენტი ამოცანა-ამოცანა აშენებს",
                     person="აგენტი ამოცანა-ამოცანა აშენებს; როცა რამეს გკითხავს — შენს მონაცემებს, „კი“-ს დაყენებაზე "
                            "ან დაცული ფაილის შეცვლაზე — უპასუხე; ბოლოს შედეგს გაჩვენებს",
                     agent=(CHECKS_FIRST if code_checks_off(g.root) else "")
                     + f"შეასრულე {plan.id} ამოცანა-ამოცანა (`/feature-plan`, ნაწილი B): ტესტი, კოდი, gate-ები, commit; "
                       "ბოლოს აჩვენე შედეგი", doc=plan.path)
    cmd = approve_hint(plan)
    return Stage(5, short="ნახე შედეგი", step=f"{plan.id} დასრულებულია — ჩვენება და პილოტი",
                 person="ნახე შედეგი და სცადე; გამოქვეყნება და პილოტი — შენი „კი“-თ; როცა ცოცხლად მუშაობს და კმაყოფილი "
                        f"ხარ — `{cmd}`; რაც არ მოგწონს — უბრალოდ დაწერე",
                 agent="აჩვენე შედეგი ცოცხლად (სად გახსნას, რა ნახოს, რა სცადოს); გამოქვეყნება და პილოტი — ადამიანის „კი“-თ; "
                       f"მე-6 ეტაპზე მხოლოდ მისი `{cmd}` გადაიყვანს — `live`-ს თავად არასდროს წერ; ახალი ფუნქცია ან "
                       "ცვლილება — ახალი `/spec`" + guide_note(g, "§4 — როგორ აჩვენო, გამოაქვეყნო და პილოტი ჩაატარო"),
                 command=cmd, doc=plan.path)


def to_json(g: Graph) -> dict:
    out = {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "root": str(g.root),
        "nodes": [{"key": n.path, "id": n.id, "type": n.type or ("file" if not n.path.endswith(".md") else "note"),
                   "status": n.status, "title": n.title, "foreign": n.foreign, "layer": n.layer}
                  | ({"origin": n.origin} if n.origin else {}) for n in g.nodes.values()],
        "edges": [{"from": a, "to": b, "kind": k} for a, b, k in g.edges()],
    }
    if g.layers:
        out["coverage"] = g.coverage
    return out


def counts(g: Graph) -> tuple[int, int, int, int]:
    """(knowledge nodes, knowledge links, bridge nodes, bridge links) — the files and the links they write, apart from
    what add_layers read out of git, the task lines and the code comments."""
    files = sum(1 for n in g.nodes.values() if n.layer == "file")
    edges = g.edges()
    known = len(g.knowledge_edges())
    return files, known, len(g.nodes) - files, len(edges) - known


def coverage_line(g: Graph) -> str:
    """What the bridge readers read and what they could not (ADR-0018 §5) — the line every answer ends with, so a short
    answer is never taken for a complete one."""
    if not g.layers:
        return "დაფარვა — მხოლოდ ცოდნის ფაილები; commit-ები, დავალებები, სესიები და კოდის ფენა არ წაკითხულა"
    c, parts = g.coverage, []
    if isinstance(c.get("commits"), str):
        parts.append(f"commit-ები ვერ წავიკითხე ({c['commits']})")
    else:
        since = f", {c['since']}-დან" if c.get("since") else ""
        parts.append(f"commit-ები: {c.get('commits', 0)}{since}; კოდის შემცვლელი {c.get('code_commits', 0)} commit-იდან "
                     f"დავალებას {c.get('code_named', 0)} ასახელებს")
    history = f", კიდევ {c['task_history']} — მხოლოდ git-ის ისტორიაში" if c.get("task_history") else ""
    parts.append(f"დავალებები: {c.get('task_lines', 0)} ხაზი tasks/-ში{history}")
    parts.append(_code_coverage(c))
    shown = c.get("sessions", 0)
    sessions = f"სესიები: {shown} ეპიზოდი მოქმედებებით" + (f", {c.get('sessions_since') or '?'}-დან" if shown else "")
    if c.get("sessions_unread"):
        sessions += (f", {c['sessions_unread']} ეპიზოდის ბლოკი მოქმედებებს არ ასახელებს (ჩანაწერი ვერ წაიკითხა ან ბლოკი "
                     "გაწყვეტილია)")
    if c.get("sessions_without"):
        sessions += f", {c['sessions_without']} ეპიზოდს ბლოკი არ აქვს (ADR-0018 §3-მდე ან ჯერ ღიაა)"
    parts.append(sessions)
    return "დაფარვა — " + "; ".join(parts)


def _counted(counts: dict, limit: int = 8) -> str:
    items = sorted(counts.items())
    return ", ".join(f"{k} {v}" for k, v in items[:limit]) + (" …" if len(items) > limit else "")


def _code_coverage(c: dict) -> str:
    """The code layer's part of the coverage line (ADR-0018 §4, §5): which reader read how many files, which stayed
    without one, what an import reader cannot follow, and the code git knows outside the layer."""
    files = c.get("code_files", 0)
    text = f"კოდი: {files} ფაილი"
    if files:
        text += f" — იმპორტები: {_counted(c.get('import_readers') or {}) or '—'}"
        if c.get("import_none"):
            text += f", იმპორტის წამკითხველი არ აქვს: {_counted(c['import_none'])}"
    if c.get("code_styles"):
        text += f"; კომენტარები: {_counted(c['code_styles'])}"
    if c.get("code_unread"):
        text += f"; ვერ წაიკითხა {len(c['code_unread'])} ფაილი"
    if files:
        found = [f"{word} {c[key]}" for key, word in (("import_dynamic", "დინამიკური"), ("import_alias", "ფსევდონიმი"))
                 if c.get(key)]
        text += "; დინამიკურ იმპორტსა და ფსევდონიმიან გზას (`@/…`) არ მიჰყვება" + (f" ({', '.join(found)})" if found else "")
    if c.get("import_unresolved"):
        text += f"; {c['import_unresolved']} იმპორტის გზას გრაფში ფაილი არ შეესაბამება"
    if c.get("code_missed"):
        text += f"; git-ის ისტორიის კიდევ {c['code_missed']} კოდის ფაილი ამ ფენის გარეთაა ({_counted(c['code_missed_kinds'])})"
    return text


def context_map(g: Graph, issues: list[Issue]) -> str:
    errors = [i for i in issues if i.level == "error"]
    inbound: dict[str, int] = {}
    outbound: dict[str, int] = {}
    for a, b, _ in g.knowledge_edges():
        outbound[a] = outbound.get(a, 0) + 1
        inbound[b] = inbound.get(b, 0) + 1
    files, known, bridge_nodes, bridges = counts(g)
    lines = [
        "# კონტექსტის რუკა (context map)",
        "",
        f"_გენერირებულია {dt.datetime.now().astimezone().isoformat(timespec='seconds')} — `tools/context_graph.py build`; "
        "ხელით არ იცვლება, git-ში არ ინახება._",
        "",
        f"კვანძები: {files} · კავშირები: {known} · შეცდომები: {len(errors)}"
        + (f" · ხიდები: {bridges} ({bridge_nodes} კვანძი — commit-ები, დავალებები, ჩანაწერები)" if g.layers else ""),
        "",
        "## მფლობელის დასამტკიცებელი",
        "",
    ]
    pend = pending(g)
    lines += [f"- {n.id} — {n.title} (`{n.status}`) → `{approve_hint(n)}`" for n in pend] or ["- არაფერი"]
    eng = pending(g, engine=True)
    if eng:
        lines += ["", "## ძრავის გადაწყვეტილებები (`scope: engine` — პროექტის ეტაპებს არ აჩერებს)", ""]
        lines += [f"- {n.id} — {n.title} (`{n.status}`) → `{approve_hint(n)}`" for n in eng]
    for typ in ("intent", "roadmap", "progress", "spec", "plan", "adr", "domain", "memory", "lesson", "episode"):
        group = sorted((n for n in g.nodes.values() if n.type == typ and not n.foreign), key=lambda n: n.path)
        if typ == "episode":
            group = group[-10:]
        if not group:
            continue
        lines += ["", f"## {typ}", "", "| id | სათაური | სტატუსი | ფაილი | ← | → |", "|---|---|---|---|---|---|"]
        for n in group:
            lines.append(f"| {n.id} | {n.title} | {n.status} | `{n.path}` | {inbound.get(n.path, 0)} | {outbound.get(n.path, 0)} |")
    rel = [(a, b, k) for a, b, k in g.knowledge_edges() if k in RELATION_TYPES]
    if rel:
        lines += ["", "## ტიპიზებული კავშირები", ""]
        lines += [f"- {g.nodes[a].id} —{k}→ {g.nodes[b].id if b in g.nodes else b}" for a, b, k in rel]
    if g.layers:
        kinds: dict[str, int] = {}
        for _, _, k in g.edges():
            if k in BRIDGE_KINDS:
                kinds[k] = kinds.get(k, 0) + 1
        lines += ["", "## ხიდები ([[ADR-0018-agentic-graph-layers-and-bridges]])", "",
                  "ერთი კვანძის გზა: `bash .claude/hooks/py.sh tools/context_graph.py why <ფაილი ან id>` (რატომ არის ასე) · "
                  "`… impact <ფაილი ან id>` (რას ეხება ცვლილება)", "",
                  " · ".join(f"{k}: {kinds[k]}" for k in sorted(kinds)) or "ხიდი არ არის", "", coverage_line(g)]
    if errors:
        lines += ["", "## შეცდომები", ""] + [f"- {i.fmt()}" for i in errors[:40]]
    return "\n".join(lines) + "\n"


def build(g: Graph, issues: list[Issue]) -> Path:
    out = g.root / "memory" / "graph"
    out.mkdir(parents=True, exist_ok=True)
    (out / "graph.json").write_text(json.dumps(to_json(g), ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "CONTEXT-MAP.md").write_text(printable(context_map(g, issues)), encoding="utf-8")
    return out


# A node's neighbours are shown kind by kind, at most PER_KIND of each (the rest: „… და კიდევ N"), and an answer stops at
# MAX_LINES — a short answer the agent can read in one go (ADR-0018 §5). Knowledge links first, then the bridges.
PER_KIND = {"query": 12, "why": 6, "impact": 6}
MAX_LINES = 80
KIND_ORDER = [*RELATION_TYPES, "link", "imports", "names", "req", "ac", "goal", "cites", "task", "receipt", "in", "changed",
              "made", "edited", "read"]
WHY_KINDS = {"task", "names", "req", "ac", "goal", "cites", "intent", "spec", "adrs", "depends_on", "supersedes"}
IMPACT_KINDS = {"link", *RELATION_TYPES, "names", "req", "ac", "goal", "cites"}


def _label(g: Graph, key: str) -> str:
    n = g.nodes.get(key)
    if not n or not n.type:
        return key  # untyped note or plain file: its path says the most
    date = str((n.fm or {}).get("date") or "") if n.layer == "commit" else ""
    meta = ", ".join(x for x in (n.type, n.status, date) if x)
    where = f" — {n.origin}" if n.layer in ("task", "anchor") and n.origin else ""
    return f"{n.stem} ({meta}) {n.title}".rstrip() + where


def _started(n: Node) -> float:
    """When an episode's session began — its `started`, else its `date`; 0 when neither reads as a time."""
    for raw in ((n.fm or {}).get("started"), (n.fm or {}).get("date")):
        try:
            return dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError, OverflowError, OSError):
            continue
    return 0.0


def _rank(g: Graph, key: str) -> tuple[int, float, str]:
    """Commits newest first, the way git log shows them; sessions newest first too; everything else by its key."""
    n = g.nodes.get(key)
    if n is not None and n.layer == "commit":
        return 0, int((n.fm or {}).get("order", 10 ** 9)), key
    if n is not None and n.type == "episode":
        return 1, -_started(n), key
    return 2, 0, key


def trace(g: Graph, start: Node, follow, depth: int, per_kind: int, once: bool = False) -> str:
    """The tree of what `follow(key)` allows from start — [(direction "fwd"/"back", {kinds})] for each node —, each node
    opened once, `depth` levels deep, ending with the coverage line. `once`: a neighbour reached two ways from one node
    (a commit names its task, and the task's receipt names the commit) is shown the first way only."""
    fwd: dict[str, set[tuple[str, str]]] = {}
    back: dict[str, set[tuple[str, str]]] = {}
    for a, b, k in g.edges():
        if a != b:
            fwd.setdefault(a, set()).add((b, k))
            back.setdefault(b, set()).add((a, k))
    lines = [f"{_label(g, start.path)}  [{start.path}]"]
    seen = {start.path}

    def order(kind: str) -> tuple[int, str]:
        return (KIND_ORDER.index(kind) if kind in KIND_ORDER else len(KIND_ORDER)), kind

    def walk(key: str, level: int) -> None:
        shown: set[str] = set()
        for direction, kinds in follow(key):
            by_kind: dict[str, list[str]] = {}
            pairs = sorted(((o, k) for o, k in (fwd if direction == "fwd" else back).get(key, set()) if k in kinds),
                           key=lambda p: order(p[1]))
            for other, k in pairs:
                if once and other in shown:
                    continue
                by_kind.setdefault(k, []).append(other)
                shown.add(other)
            for k in sorted(by_kind, key=order):
                others = sorted(by_kind[k], key=lambda x: _rank(g, x))
                for other in others[:per_kind]:
                    lines.append(f"{'  ' * level}{'→' if direction == 'fwd' else '←'} {_label(g, other)} [{k}]")
                    if other not in seen and level < depth and len(lines) <= MAX_LINES:
                        seen.add(other)
                        walk(other, level + 1)
                if len(others) > per_kind:
                    lines.append(f"{'  ' * level}  … და კიდევ {len(others) - per_kind} [{k}]")

    walk(start.path, 1)
    if len(lines) > MAX_LINES + 1:
        lines[MAX_LINES + 1:] = [f"… და კიდევ {len(lines) - MAX_LINES - 1} ხაზი (ზღვარი — {MAX_LINES}; ვიწრო კითხვისთვის "
                                 "ნაკლები --depth)"]
    return "\n".join(lines + [coverage_line(g)])


def _not_found(g: Graph, ident: str) -> str:
    return (f"not found: {ident!r} (try a file stem such as intent, plan, ADR-0001-..., an id such as D-001 or REQ-001, "
            f"or a commit's hash)\n{coverage_line(g)}")


def query(g: Graph, ident: str, depth: int) -> str:
    """One node's neighbourhood, both ways, every kind of link."""
    start = g.find(ident)
    if not start:
        return _not_found(g, ident)
    every = set(KIND_ORDER) | BRIDGE_KINDS
    return trace(g, start, lambda _key: [("fwd", every), ("back", every)], depth, PER_KIND["query"])


def why(g: Graph, ident: str, depth: int) -> str:
    """„Why is this so?" (ADR-0018 §2): a file → the commits that changed it → the task each names → what the task names
    (decision, spec, plan) → a plan task's requirement and criterion → the requirement's goal — and what the file's own
    comments and frontmatter cite."""
    start = g.find(ident)
    if not start:
        return _not_found(g, ident)

    def follow(key: str) -> list[tuple[str, set[str]]]:
        n = g.nodes.get(key)
        layer = n.layer if n else "file"
        if layer == "commit":  # the task its message names, the task its receipt names, the session that made it
            return [("fwd", {"task"}), ("back", {"receipt", "made"})]
        steps = [("back", {"changed"})] if key == start.path and layer == "file" else []
        return steps + [("fwd", WHY_KINDS | ({"in"} if layer == "anchor" else set()))]

    return trace(g, start, follow, depth, PER_KIND["why"], once=True)


def impact(g: Graph, ident: str, depth: int) -> str:
    """„What does a change touch?" (ADR-0018 §2): what links to it, names it or cites it — the documents, tasks, plan tasks
    and code comments that rely on it —, for a code file the files that import it and, a level further, the files that
    import those (§4), the commits that changed it, with the task each was made for, and the sessions that changed it,
    newest first (§3)."""
    import graph_layers as gl  # here, not at the top (see add_layers)
    start = g.find(ident)
    if not start:
        return _not_found(g, ident)
    code = start.layer == "file" and gl.is_code(start.path)

    def follow(key: str) -> list[tuple[str, set[str]]]:
        n = g.nodes.get(key)
        layer = n.layer if n else "file"
        if layer == "commit":
            return [("fwd", {"task"})]  # the task the commit was made for
        if key != start.path:  # one step on: a requirement's plan tasks, a goal's requirements, an importer's importers
            if layer == "anchor":
                return [("back", {"req", "ac", "goal", "names", "cites"})]
            return [("back", {"imports"})] if layer == "file" and code else []
        extra = ({"in"} | ({"changed", "edited", "imports"} if layer == "file" else set())
                 | ({"task"} if layer in ("task", "anchor") else set()))
        return [("back", IMPACT_KINDS | extra)]

    return trace(g, start, follow, depth, PER_KIND["impact"], once=True)


def brief(g: Graph, issues: list[Issue]) -> str:
    errors = [i for i in issues if i.level == "error"]
    pend, eng = pending(g), pending(g, engine=True)
    files, known, _, bridges = counts(g)
    lines = [
        project_stage(g).block(),
        "",
        "## კონტექსტის გრაფი (tools/context_graph.py)",
        f"- {files} კვანძი, {known} კავშირი" + (f", {bridges} ხიდი (ADR-0018)" if g.layers else "")
        + f", შეცდომა: {len(errors)}" + (" — გაასწორე, სანამ სხვა სამუშაოს დაიწყებ:" if errors else ""),
    ]
    lines += [f"  - {i.fmt()}" for i in errors[:5]]
    if len(errors) > 5:
        lines.append(f"  - … კიდევ {len(errors) - 5} (`bash .claude/hooks/py.sh tools/context_graph.py check`)")
    if pend:
        lines.append("- მფლობელის დასამტკიცებელი (შეახსენე; თავად ვერ დაამტკიცებ):")
        lines += [f"  - {n.id} — {n.title} (`{n.status}`) → `{approve_hint(n)}`" for n in pend[:10]]
    if eng:
        lines.append(f"- ძრავის საკუთარი ADR-ები (`scope: engine`): {len(eng)} `proposed` — პროექტის ეტაპებს არ აჩერებს; "
                     "ისინი ძრავის ავტორის გადასაწყვეტია და ახალი პროექტის მფლობელს დასამტკიცებლად არ ეძლევა "
                     "(`bash .claude/hooks/py.sh tools/context_graph.py pending`)")
    lines.append("- ორიენტაცია: `memory/graph/CONTEXT-MAP.md`; ერთი კვანძის სამეზობლო: "
                 "`bash .claude/hooks/py.sh tools/context_graph.py query <id>`")
    return printable("\n".join(lines))


# ── CLI ──────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", help="project root (default: CONTEXT_ROOT env or this file's parent)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    c = sub.add_parser("check")
    c.add_argument("files", nargs="*")
    c.add_argument("--json", action="store_true")
    for name, depth in (("query", 1), ("why", 4), ("impact", 2)):
        q = sub.add_parser(name)
        q.add_argument("ident")
        q.add_argument("--depth", type=int, default=depth)
    sub.add_parser("pending")
    sub.add_parser("stage")
    sub.add_parser("brief")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else default_root().resolve()
    if not (root / "intent.md").exists() and not (root / "docs").is_dir():
        print(f"INCONCLUSIVE: {root} does not look like the project root (no intent.md, no docs/)", file=sys.stderr)
        return 2
    if a.cmd == "brief" and os.environ.get("EPISODIC_NESTED") == "1":
        return 0  # a nested session (claude -p from a script) gets no brief: nothing to load
    # the bridges (ADR-0018) for every view and the check; `pending` and `stage` read the documents' statuses alone
    g = load(root, layers=a.cmd not in ("pending", "stage"))
    md_count = sum(1 for n in g.nodes.values() if n.path.endswith(".md") and not n.foreign)
    issues = check(g)

    if a.cmd == "build":
        out = build(g, issues)
        files, known, _, bridges = counts(g)
        print(f"built {out.relative_to(root).as_posix()}/ — {files} nodes, {known} edges, {bridges} bridges, "
              f"{sum(i.level == 'error' for i in issues)} errors")
        return 0
    if a.cmd == "check":
        if md_count == 0:
            print("INCONCLUSIVE: 0 knowledge files scanned — nothing was proved", file=sys.stderr)
            return 2
        shown = filter_issues(issues, a.files, root) if a.files else issues
        if a.json:
            print(json.dumps([i.__dict__ for i in shown], ensure_ascii=False, indent=1))
        else:
            for i in shown:
                print(i.fmt())
            n_err = sum(i.level == "error" for i in shown)
            n_warn = sum(i.level == "warning" for i in shown)
            scope = f"{len(a.files)} file(s)" if a.files else "whole vault"
            print(f"GRAPH-CHECK {'FAIL' if n_err else 'OK'}: {md_count} files scanned, scope={scope}, "
                  f"errors={n_err}, warnings={n_warn}")
            print(coverage_line(g))
        return 1 if any(i.level == "error" for i in shown) else 0
    if a.cmd in ("query", "why", "impact"):
        view = {"query": query, "why": why, "impact": impact}[a.cmd]
        print(printable(view(g, a.ident, max(1, a.depth))))
        return 0
    if a.cmd == "pending":
        pend, eng = pending(g), pending(g, engine=True)
        for n in pend:
            print(printable(f"{n.id:10} {n.status:9} {approve_hint(n):22} {n.title}"))
        if not pend:
            print("nothing in the project is waiting for the owner")
        if eng:
            print("\nengine decisions (scope: engine) — the engine author's, they do not hold up the project's stages:")
            for n in eng:
                print(printable(f"{n.id:10} {n.status:9} {approve_hint(n):22} {n.title}"))
        return 0
    if a.cmd == "stage":
        print(project_stage(g).block())
        return 0
    if a.cmd == "brief":
        try:
            build(g, issues)
        except OSError as e:
            print(f"graph build failed: {e}", file=sys.stderr)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                 "additionalContext": brief(g, issues)}}, ensure_ascii=False))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
