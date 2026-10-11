#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Context graph of the project's knowledge files: one source, two views, one check.

The source is the Markdown itself: YAML frontmatter (id, type, status, relations)
plus links ([[wikilinks]] and relative [text](path.md) links). Obsidian draws these
same links as its graph view for the owner; this script builds the same graph for
the agent, and checks it mechanically.

  py -3.12 tools/context_graph.py build                write memory/graph/graph.json + CONTEXT-MAP.md
  py -3.12 tools/context_graph.py check [FILE ...]     integrity check; with FILEs, report only
                                                       issues that involve those files
  py -3.12 tools/context_graph.py query ID [--depth N] one node's neighbourhood (ID or file stem)
  py -3.12 tools/context_graph.py pending              documents waiting for the owner's /approve
  py -3.12 tools/context_graph.py stage                where the project stands (F1–F5) and what comes next
  py -3.12 tools/context_graph.py brief                SessionStart hook: rebuild + stage + short brief

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
]

SCHEMA: dict[str, dict] = {
    "intent":   {"required": ("id", "type", "title", "status", "updated"), "status": ("draft", "accepted")},
    "roadmap":  {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "progress": {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "spec":     {"required": ("id", "type", "title", "status", "created", "updated", "intent"),
                 "status": ("draft", "review", "approved", "superseded")},
    "plan":     {"required": ("id", "type", "title", "status", "created", "updated", "spec"),
                 "status": ("draft", "approved", "in-progress", "done")},
    "adr":      {"required": ("id", "type", "title", "status", "date"),
                 "status": ("proposed", "accepted", "rejected", "superseded")},
    "domain":   {"required": ("id", "type", "title", "status", "updated"), "status": ("living",)},
    "episode":  {"required": ("id", "type", "session", "date", "status"), "status": ("open", "closed")},
    "memory":   {"required": ("id", "type", "title", "status"), "status": ("living", "generated")},
    "guide":    {"required": ("id", "type", "title"), "status": None},
}

ID_PATTERNS = {
    "spec": r"SPEC-\d{4}",
    "plan": r"PLAN-\d{4}",
    "adr": r"ADR-\d{4}",
    "episode": r"EP-\d{4}-\d{2}-\d{2}-[0-9a-z]{8}",
}

# Statuses only the owner may set (through tools/approve.py, never an agent).
OWNER_STATUSES = {
    "intent": {"accepted"},
    "spec": {"approved", "superseded"},
    "plan": {"approved"},
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

LEDGER_PATH = "memory/approvals.md"

WIKILINK_RE = re.compile(r"!?\[\[([^\]\|#\n]*)(#[^\]\|\n]*)?(\|[^\]\n]*)?\]\]")
MDLINK_RE = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


# ── Data model ───────────────────────────────────────────────────────────────
@dataclass
class Link:
    target: str          # raw target text
    line: int            # 1-based line in the file
    kind: str            # "link" or a frontmatter relation name
    resolved: str | None = None   # node key (vault-relative posix path) or None
    problem: str | None = None    # "broken" | "ambiguous" | "unquoted"


@dataclass
class Node:
    path: str                     # vault-relative posix path — the node key
    fm: dict | None = None
    fm_error: str | None = None
    body_line: int = 1
    links: list[Link] = field(default_factory=list)
    foreign: bool = False

    @property
    def stem(self) -> str:
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
    ledger: dict[str, list[str]]

    def edges(self) -> list[tuple[str, str, str]]:
        out = []
        for n in self.nodes.values():
            for ln in n.links:
                if ln.resolved:
                    out.append((n.path, ln.resolved, ln.kind))
        return out

    def find(self, ident: str) -> Node | None:
        """Look a node up by vault path, file stem, or frontmatter id (case-insensitive)."""
        ident = ident.strip().removesuffix(".md")
        for key in (ident, ident + ".md"):
            if key in self.nodes:
                return self.nodes[key]
        lo = ident.lower()
        for n in self.nodes.values():
            if n.stem.lower() == lo or n.id.lower() == lo:
                return n
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
    s = str(value)
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


def status_of(text: str | None) -> str | None:
    """The frontmatter status of a document's text, or None (no text, no frontmatter, empty status)."""
    if text is None:
        return None
    fm, _, _ = parse_frontmatter(text)
    v = (fm or {}).get("status")
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


def code_folders(root: Path) -> tuple[str, ...]:
    """Folders below the root that hold their own code project (CODE_MARKERS) — the product's, foreign here."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not _is_skipped_dir(f"{rel_dir}/{d}".lstrip("/"))]
        if rel_dir and any(m in filenames for m in CODE_MARKERS):
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


def _extract_body_links(text: str, body_line: int) -> list[Link]:
    lines = text.split("\n")
    out: list[Link] = []
    in_fence = False
    fence = ""
    for idx in range(body_line - 1, len(lines)):
        line = lines[idx]
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence = True, marker
            elif marker == fence:
                in_fence = False
            continue
        if in_fence:
            continue
        clean = INLINE_CODE_RE.sub("", line)
        for m in WIKILINK_RE.finditer(clean):
            out.append(Link(m.group(1).strip(), idx + 1, "link"))
        for m in MDLINK_RE.finditer(clean):
            tgt = m.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", tgt, re.I) or tgt.startswith("#"):
                continue  # URLs, mailto:, in-page anchors
            out.append(Link("md:" + tgt, idx + 1, "link"))
    return out


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


def load(root: Path | None = None) -> Graph:
    root = (root or default_root()).resolve()
    nodes: dict[str, Node] = {}
    foreign = FOREIGN_PREFIXES + code_folders(root)
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
    g = Graph(root=root, nodes=nodes, by_stem=by_stem, ledger=_read_ledger(root))
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
        base = Path(node.path).parent
        cand = (base / tgt).as_posix()
        norm = os.path.normpath(cand).replace("\\", "/")
        if norm.startswith("../"):
            ln.problem = "broken"
            return
        if norm in g.nodes:
            ln.resolved = norm
        elif (g.root / norm).exists():
            ln.resolved = norm  # an existing folder or non-indexed file: valid, not a node
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


def _read_ledger(root: Path) -> dict[str, list[str]]:
    """id -> list of statuses the ledger records it moving TO, in order."""
    out: dict[str, list[str]] = {}
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
        out.setdefault(ident, []).append(to)
    return out


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

    known_ids = {n.id.lower(): n.stem for n in g.nodes.values() if n.fm and n.fm.get("id")}
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

    issues += _check_relations(g)
    issues += _check_chain_and_ledger(g)
    issues += _check_orphans(g)
    return issues


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
        if typ == "plan" and st in ("approved", "in-progress", "done"):
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
    if typ == "plan" and st in ("approved", "in-progress", "done"):
        return "approved"
    if typ == "adr" and st in ("accepted", "rejected", "superseded"):
        return st
    if typ == "spec" and st == "superseded":
        return "superseded"
    return None


def _check_orphans(g: Graph) -> list[Issue]:
    inbound: dict[str, int] = {}
    for src, dst, _ in g.edges():
        if src != dst:
            inbound[dst] = inbound.get(dst, 0) + 1
    out = []
    for n in g.nodes.values():
        if not n.foreign and n.type in ("spec", "plan", "adr", "domain") and not inbound.get(n.path):
            out.append(Issue("warning", "ORPHAN", n.path, 1, "nothing links here — link it from its index or a related document"))
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


def pending(g: Graph, engine: bool = False) -> list[Node]:
    """Documents waiting for the owner's /approve: the project's own, or (engine=True) the engine's ADRs. An intent
    whose §1 is still the template is not offered — there is nothing in it to approve yet."""
    out = [n for n in g.nodes.values() if not n.foreign and n.type in PENDING_STATUSES
           and n.status in PENDING_STATUSES[n.type] and is_engine(n) == engine
           and not (n.type == "intent" and not idea_written(g.root / n.path))]
    order = {"intent": 0, "spec": 1, "plan": 2, "adr": 3}
    return sorted(out, key=lambda n: (order.get(n.type, 9), n.id))


def approve_hint(n: Node) -> str:
    if n.type == "intent":
        return "/approve intent"
    m = re.fullmatch(r"[A-Z]+-(\d{4})", n.id)
    if not m:  # e.g. SPEC-0002-0001 would otherwise read as `/approve spec 0001` — a different document (review S5)
        return "(id არასწორია — ჯერ frontmatter-ის id უნდა გასწორდეს)"
    return f"/approve {n.type} {m.group(1)}"


# ── Stage conductor (ADR-0011) ───────────────────────────────────────────────
# The stages are not new: they are ADR-0001's loop (intent → spec → plan → code → gates → review) and plan.md's
# phases F1–F5. The conductor stores nothing — each call reads the same statuses the graph reads and says where the
# project stands and what comes next, for the person and for the agent.
STAGES = {1: "განზრახვა", 2: "სპეციფიკაცია", 3: "არქიტექტურა", 4: "გეგმა და აშენება", 5: "ჩვენება და პილოტი"}


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
        return f"{self.label} — {self.short}" + (f" → {self.command}" if self.command else "")

    def block(self) -> str:
        where = f" (`{self.doc}`)" if self.doc else ""
        path = " → ".join(f"{k} {v}" for k, v in STAGES.items())
        return "\n".join([
            "## ეტაპი — სად დგას პროექტი (`py -3.12 tools/context_graph.py stage`, ADR-0011)",
            f"- **{self.label}** — {self.step}{where}",
            f"- ადამიანს: {self.person}",
            f"- აგენტს: {self.agent}",
            f"- გზა (ADR-0001-ის ციკლი, plan.md-ის F1–F5): {path}. ადამიანს ეტაპი ჩვეულებრივი სიტყვებით უთხარი, "
            "ბრძანება — ზუსტად.",
        ])


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
CHECKS_FIRST = ("ჯერ ჩართე კოდის შემოწმებები: `tools/gates/gates.toml`-ში `lint` და `unit` სტეკის ADR-ის ბრძანებებით, "
                "მხოლოდ პროექტის საკუთარ კოდზე (არა ძრავის `tools/`-ზე) — ფაილი დაცულია, ამიტომ ადამიანის „კი“ სჭირდება; "
                "მერე ")


def _review(number: int, doc: Node, step: str, fix: str) -> Stage:
    """A document waits for the person: they read it and approve it, or say what to change."""
    cmd = approve_hint(doc)
    return Stage(number, short=f"{doc.id} გელოდება", step=step,
                 person=f"წაიკითხე `{doc.path}`; თუ ეთანხმები — `{cmd}`, თუ არა — თქვი, რა შეიცვალოს",
                 agent=f"{doc.id}: შეასწორე ადამიანის შენიშვნების მიხედვით ({fix}); დამტკიცება მხოლოდ მისი `{cmd}`-ია",
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
        return Stage(1, short="ინტერვიუ", step="ინტერვიუ — განზრახვა იწერება",
                     person="უპასუხე კითხვებს; როცა intent.md შენს აზრს სწორად ასახავს — `/approve intent`",
                     agent=("" if intent.kind in KINDS else NEEDS_KIND)
                     + "გააგრძელე `/intent`-ის ინტერვიუ (§7-ის ღია კითხვები); როცა ღია კითხვა აღარ დარჩება, მოკლედ "
                       "აჩვენე, რა ჩაიწერა, და შესთავაზე `/approve intent`" + guide_note(g, "§1 — კითხვები"),
                     command="/approve intent", doc="intent.md")
    specs = sorted((n for n in g.nodes.values() if n.type == "spec" and not n.foreign and n.status != "superseded"),
                   key=lambda n: n.id)
    if not specs:
        return Stage(2, short="აგენტი წერს სპეციფიკაციას", step="განზრახვა დამტკიცებულია — სპეციფიკაცია ჯერ არ არის",
                     person="დაელოდე — აგენტი წერს სპეციფიკაციას: რა უნდა შეეძლოს შედეგს, შემოწმებადი კრიტერიუმებით",
                     agent="დაწერე პირველი სპეციფიკაცია: `/spec`" + guide_note(g, "§3 — პირველი ვერსიის ფარგლები"))
    spec = specs[-1]
    if spec.status != "approved":
        return _review(2, spec, f"{spec.id} შენს გადახედვას ელოდება", "`/spec`; წარდგენამდე — spec-reviewer")
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
    if plan.status != "done":
        return Stage(4, short=f"{plan.id} მიმდინარეობს", step=f"{plan.id} მიმდინარეობს — აგენტი ამოცანა-ამოცანა აშენებს",
                     person="დაელოდე — აგენტი აშენებს და შედეგს გაჩვენებს",
                     agent=(CHECKS_FIRST if code_checks_off(g.root) else "")
                     + f"შეასრულე {plan.id} ამოცანა-ამოცანა (`/feature-plan`, ნაწილი B): ტესტი, კოდი, gate-ები, commit; "
                       "ბოლოს აჩვენე შედეგი", doc=plan.path)
    return Stage(5, short="ნახე შედეგი", step=f"{plan.id} დასრულებულია",
                 person="ნახე შედეგი; ახალი იდეა ან ცვლილება — უბრალოდ დაწერე",
                 agent="აჩვენე შედეგი ცოცხლად (სად გახსნას, რა ნახოს, რა სცადოს); ახალი ფუნქცია ან ცვლილება — ახალი "
                       "`/spec`" + guide_note(g, "§4 — როგორ აჩვენო"), doc=plan.path)


def to_json(g: Graph) -> dict:
    return {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "root": str(g.root),
        "nodes": [{"key": n.path, "id": n.id, "type": n.type or ("file" if not n.path.endswith(".md") else "note"),
                   "status": n.status, "title": n.title, "foreign": n.foreign} for n in g.nodes.values()],
        "edges": [{"from": a, "to": b, "kind": k} for a, b, k in g.edges()],
    }


def context_map(g: Graph, issues: list[Issue]) -> str:
    errors = [i for i in issues if i.level == "error"]
    inbound: dict[str, int] = {}
    outbound: dict[str, int] = {}
    for a, b, _ in g.edges():
        outbound[a] = outbound.get(a, 0) + 1
        inbound[b] = inbound.get(b, 0) + 1
    lines = [
        "# კონტექსტის რუკა (context map)",
        "",
        f"_გენერირებულია {dt.datetime.now().astimezone().isoformat(timespec='seconds')} — `tools/context_graph.py build`; "
        "ხელით არ იცვლება, git-ში არ ინახება._",
        "",
        f"კვანძები: {len(g.nodes)} · კავშირები: {len(g.edges())} · შეცდომები: {len(errors)}",
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
    for typ in ("intent", "roadmap", "progress", "spec", "plan", "adr", "domain", "memory", "episode"):
        group = sorted((n for n in g.nodes.values() if n.type == typ and not n.foreign), key=lambda n: n.path)
        if typ == "episode":
            group = group[-10:]
        if not group:
            continue
        lines += ["", f"## {typ}", "", "| id | სათაური | სტატუსი | ფაილი | ← | → |", "|---|---|---|---|---|---|"]
        for n in group:
            lines.append(f"| {n.id} | {n.title} | {n.status} | `{n.path}` | {inbound.get(n.path, 0)} | {outbound.get(n.path, 0)} |")
    rel = [(a, b, k) for a, b, k in g.edges() if k != "link"]
    if rel:
        lines += ["", "## ტიპიზებული კავშირები", ""]
        lines += [f"- {g.nodes[a].id} —{k}→ {g.nodes[b].id if b in g.nodes else b}" for a, b, k in rel]
    if errors:
        lines += ["", "## შეცდომები", ""] + [f"- {i.fmt()}" for i in errors[:40]]
    return "\n".join(lines) + "\n"


def build(g: Graph, issues: list[Issue]) -> Path:
    out = g.root / "memory" / "graph"
    out.mkdir(parents=True, exist_ok=True)
    (out / "graph.json").write_text(json.dumps(to_json(g), ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "CONTEXT-MAP.md").write_text(context_map(g, issues), encoding="utf-8")
    return out


def query(g: Graph, ident: str, depth: int) -> str:
    start = g.find(ident)
    if not start:
        return f"not found: {ident!r} (try a file stem such as intent, plan, ADR-0001-..., or an id)"
    fwd: dict[str, list[tuple[str, str]]] = {}
    back: dict[str, list[tuple[str, str]]] = {}
    for a, b, k in g.edges():
        if a == b:
            continue
        fwd.setdefault(a, []).append((b, k))
        back.setdefault(b, []).append((a, k))

    def label(key: str) -> str:
        n = g.nodes.get(key)
        if not n or not n.type:
            return key  # untyped note or plain file: its path says the most
        meta = ", ".join(x for x in (n.type, n.status) if x)
        return f"{n.stem} ({meta}) {n.title}".rstrip()

    lines = [f"{label(start.path)}  [{start.path}]"]
    seen = {start.path}

    def walk(key: str, level: int) -> None:
        if level > depth:
            return
        for tgt, k in sorted(set(fwd.get(key, []))):
            lines.append(f"{'  ' * level}→ {label(tgt)} [{k}]")
            if tgt not in seen:
                seen.add(tgt)
                walk(tgt, level + 1)
        for src, k in sorted(set(back.get(key, []))):
            lines.append(f"{'  ' * level}← {label(src)} [{k}]")
            if src not in seen:
                seen.add(src)
                walk(src, level + 1)

    walk(start.path, 1)
    return "\n".join(lines)


def brief(g: Graph, issues: list[Issue]) -> str:
    errors = [i for i in issues if i.level == "error"]
    pend, eng = pending(g), pending(g, engine=True)
    lines = [
        project_stage(g).block(),
        "",
        "## კონტექსტის გრაფი (tools/context_graph.py)",
        f"- {len(g.nodes)} კვანძი, {len(g.edges())} კავშირი, შეცდომა: {len(errors)}"
        + (" — გაასწორე, სანამ სხვა სამუშაოს დაიწყებ:" if errors else ""),
    ]
    lines += [f"  - {i.fmt()}" for i in errors[:5]]
    if len(errors) > 5:
        lines.append(f"  - … კიდევ {len(errors) - 5} (`py -3.12 tools/context_graph.py check`)")
    if pend:
        lines.append("- მფლობელის დასამტკიცებელი (შეახსენე; თავად ვერ დაამტკიცებ):")
        lines += [f"  - {n.id} — {n.title} (`{n.status}`) → `{approve_hint(n)}`" for n in pend[:10]]
    if eng:
        lines.append(f"- ძრავის საკუთარი ADR-ები (`scope: engine`): {len(eng)} `proposed` — პროექტის ეტაპებს არ აჩერებს; "
                     "ისინი ძრავის ავტორის გადასაწყვეტია და ახალი პროექტის მფლობელს დასამტკიცებლად არ ეძლევა "
                     "(`py -3.12 tools/context_graph.py pending`)")
    lines.append("- ორიენტაცია: `memory/graph/CONTEXT-MAP.md`; ერთი კვანძის სამეზობლო: "
                 "`py -3.12 tools/context_graph.py query <id>`")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", help="project root (default: CONTEXT_ROOT env or this file's parent)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    c = sub.add_parser("check")
    c.add_argument("files", nargs="*")
    c.add_argument("--json", action="store_true")
    q = sub.add_parser("query")
    q.add_argument("ident")
    q.add_argument("--depth", type=int, default=1)
    sub.add_parser("pending")
    sub.add_parser("stage")
    sub.add_parser("brief")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve() if a.root else default_root().resolve()
    if not (root / "intent.md").exists() and not (root / "docs").is_dir():
        print(f"INCONCLUSIVE: {root} does not look like the project root (no intent.md, no docs/)", file=sys.stderr)
        return 2
    g = load(root)
    md_count = sum(1 for n in g.nodes.values() if n.path.endswith(".md") and not n.foreign)
    issues = check(g)

    if a.cmd == "build":
        out = build(g, issues)
        print(f"built {out.relative_to(root).as_posix()}/ — {len(g.nodes)} nodes, {len(g.edges())} edges, "
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
        return 1 if any(i.level == "error" for i in shown) else 0
    if a.cmd == "query":
        print(query(g, a.ident, max(1, a.depth)))
        return 0
    if a.cmd == "pending":
        pend, eng = pending(g), pending(g, engine=True)
        for n in pend:
            print(f"{n.id:10} {n.status:9} {approve_hint(n):22} {n.title}")
        if not pend:
            print("nothing in the project is waiting for the owner")
        if eng:
            print("\nengine decisions (scope: engine) — the engine author's, they do not hold up the project's stages:")
            for n in eng:
                print(f"{n.id:10} {n.status:9} {approve_hint(n):22} {n.title}")
        return 0
    if a.cmd == "stage":
        print(project_stage(g).block())
        return 0
    if a.cmd == "brief":
        if os.environ.get("EPISODIC_NESTED") == "1":
            return 0
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
