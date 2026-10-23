#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A finding counts only when a machine can find what it points at.

REVIEW.md says a finding counts only when it is located and evidenced; until now only the closing line was read
(orchestration/run.py). This reads a review and checks what a machine can:

  - a `file:line` (also `file:a-b`, `file#La-Lb`) names a file inside the project — relative, no `..`, no drive or
    `/` start, no hidden character — and lines that exist in it; a bare path names an existing file; a secret file
    (`.env`, `*.key`… — tools/redact.py's SECRET_KINDS) is refused without being opened;
  - a finding that cites a file opens its evidence with a code quote of 12+ characters (between backticks), and the
    quote is really written within 3 lines of the cited lines (whitespace ignored; `...` or `…` may stand for skipped
    text) — commands and payloads go after it;
  - a location without a file names a document that exists: SPEC-/PLAN-/ADR-NNNN, and any AC-/REQ- in that
    document, or D-/P-/L-NNN in the task list, the proposals or the lessons;
  - an UNRESOLVED item carries no severity: it names a missing fact, it is not a finding;
  - the closing line agrees with the rows: no `VERDICT: approve` over a critical or high finding; a critic's
    `<LENS>: n critical, n high, n medium, n low — VERDICT OK|FAIL|INCONCLUSIVE` counts its own rows, says FAIL
    exactly when one is critical or high, INCONCLUSIVE when none is but an UNRESOLVED row is, and has a CHECKS line.

Two formats are read: REVIEW.md's blocks (FINDING n / severity: / where: / evidence: …, UNRESOLVED n / where: /
missing: / who:) and the critic agents' rows (`id | severity or UNRESOLVED | file:line | evidence | fix`).

  bash .claude/hooks/py.sh tools/check_findings.py REVIEW-FILE [--root DIR]      (`-` reads stdin)

Exit 0 = every finding located and evidenced, closing line consistent · 1 = a finding does not count or the closing
line contradicts the rows (each problem names its code in brackets) · 2 = INCONCLUSIVE: nothing readable.
"""
from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import is_secret_path  # noqa: E402

for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SEVERITIES = ("critical", "high", "medium", "low")
NEAR = 3          # lines around the cited ones a quote may sit in
MIN_QUOTE = 12    # a shorter code span is a name, not a quote
HEADER_RE = re.compile(r"^\s*(?:#+\s*)?\**(FINDING|UNRESOLVED)\s+([\w.-]+)\**\s*:?\s*$")
FIELD_RE = re.compile(r"^\s*(?:[-*]\s+)?\**(severity|where|claim|evidence|fix|missing|who)\**\s*:\**\s*(.*)$", re.I)
ROW_ID_RE = re.compile(r"^[A-Z]{1,3}\d+$")
REVIEW_END_RE = re.compile(r"^(VERDICT|POSITION):\s*([A-Za-z-]+)$")
CRITIC_END_RE = re.compile(r"^([A-Z][A-Z-]*):\s*(?:(\d+) critical,\s*)?(\d+) high,\s*(\d+) medium,\s*(\d+) low\s*[—–-]+\s*"
                           r"VERDICT\s+(OK|FAIL|INCONCLUSIVE)$")  # CODE-QUALITY has no critical count
LOC_RE = re.compile(r"(?P<path>[^\s`'\"()\[\],;:#]+)(?::(?P<a>\d+)(?:\s*[-–]\s*(?P<b>\d+))?|#L(?P<c>\d+)(?:-L?(?P<d>\d+))?)")
ABS_RE = re.compile(r"(?:^|[\s(`'\"])(?:[A-Za-z]:[\\/]|[\\/](?=[\w.~-])|~(?=[\\/]))")  # C:/…, /…, \\server, ~/…
QUOTE_RE = re.compile(r"(`+)(.+?)\1", re.S)
DOC_RE = re.compile(r"\b(SPEC|PLAN|ADR)-(\d{4})\b")
DOC_GLOB = {"SPEC": "docs/specs/SPEC-{}*.md", "PLAN": "docs/plans/PLAN-{}*.md", "ADR": "docs/adr/ADR-{}*.md"}
PART_RE = re.compile(r"\b(?:AC|REQ)-\d{3}\b")
ITEM_RE = re.compile(r"\b([DPL])-\d{3}\b")
ITEM_FILES = {"D": "tasks/todo.md", "P": "memory/PROPOSALS.md", "L": "memory/LESSONS.md"}
UNREAD = ("[no-file]", "[past-end]", "[outside]", "[secret]")  # a place never read: its quote is not looked for
NO_QUOTE = (f"[no-quote] the evidence quotes no code — open it with the cited lines between backticks ({MIN_QUOTE}+ "
            "characters), so a machine can find them there")


@dataclass
class Item:
    kind: str                       # finding | unresolved
    ident: str
    fields: dict = field(default_factory=dict)


def hidden(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cf" for ch in text)


def cells(line: str) -> list[str]:
    """A table row split on `|` — not on one inside a code quote."""
    out, cur, code = [], [], False
    for ch in line.strip().strip("|"):
        if ch == "`":
            code = not code
        if ch == "|" and not code:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    return out + ["".join(cur).strip()]


def parse(text: str) -> tuple[list[Item], str, bool]:
    """(items, closing line, has a CHECKS line)."""
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    filled = [ln for ln in lines if ln.strip()]
    closing = filled[-1].replace("*", "").replace("`", "").strip().rstrip(".") if filled else ""
    items: list[Item] = []
    cur: Item | None = None
    key = ""
    for ln in lines:
        h = HEADER_RE.match(ln)
        if h:
            cur, key = Item("finding" if h.group(1) == "FINDING" else "unresolved", f"{h.group(1)} {h.group(2)}"), ""
            items.append(cur)
            continue
        if ln.count("|") >= 3:
            row = cells(ln)
            if len(row) >= 4 and ROW_ID_RE.match(row[0]):
                kind = "unresolved" if "UNRESOLVED" in row[1].upper() else "finding"
                sev = row[1].lower().replace("unresolved", "").strip()
                rest = cells("|".join(row[3:]))
                evidence = "|".join(rest[:-1]) if len(rest) > 1 else rest[0]
                # an UNRESOLVED line's fourth column names the missing fact — it quotes nothing (live drill, 2026-10-20)
                text_key = "missing" if kind == "unresolved" else "evidence"
                items.append(Item(kind, row[0], {"severity": sev, "where": row[2], text_key: evidence}))
                cur = None
                continue
        f = FIELD_RE.match(ln)
        if cur is not None and f:
            key = f.group(1).lower()
            cur.fields[key] = f.group(2)
        elif cur is not None and key and not REVIEW_END_RE.match(ln.strip()):
            cur.fields[key] += "\n" + ln
    return items, closing, any(ln.lstrip().startswith("CHECKS:") for ln in lines)


def first_quote(evidence: str) -> str | None:
    for m in QUOTE_RE.finditer(evidence):
        body = re.sub(r"^[A-Za-z0-9_+-]*\n", "", m.group(2)) if m.group(1) == "```" else m.group(2)
        if len(body.strip()) >= MIN_QUOTE:
            return body
    return None


def quote_near(quote: str, lines: list[str], a: int, b: int) -> bool:
    window = " ".join(" ".join(lines[max(0, a - 1 - NEAR):b + NEAR]).split())
    pos = 0
    for piece in re.split(r"\.\.\.|…", quote):
        piece = " ".join(piece.split())
        if not piece:
            continue
        pos = window.find(piece, pos)
        if pos < 0:
            return False
        pos += len(piece)
    return True


def path_problem(root: Path, raw: str) -> str | None:
    """A citation names its file the one way every machine reads alike: from the project root, without climbing. A
    secret file is never opened, whoever names it — the review may be a model's (review S2)."""
    if ".." in raw.split("/"):
        return f"[outside] {raw}: a `..` in the path — cite it from the project root, without climbing"
    real = (root / raw).resolve()
    if not real.is_relative_to(root):
        return f"[outside] {raw} resolves outside the project (through a link)"
    if is_secret_path(raw) or is_secret_path(real.relative_to(root).as_posix()):  # by its name, or a link's target
        return f"[secret] {raw} is a secret file — it is never opened; cite the code that reads it"
    return None


def check_file_loc(root: Path, m: re.Match, quote: str | None) -> tuple[str | None, bool]:
    """(problem or None, quote found here)."""
    raw = m.group("path").replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    a = int(m.group("a") or m.group("c") or 0)
    b = int(m.group("b") or m.group("d") or a)
    problem = path_problem(root, raw)
    if problem:
        return problem, False
    p = (root / raw).resolve()
    if not p.is_file():
        return f"[no-file] {raw} does not exist", False
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    if a < 1 or b < a or b > len(lines):
        return f"[past-end] {raw}:{a}{'-' + str(b) if b != a else ''} — the file has {len(lines)} line(s)", False
    return None, quote is not None and quote_near(quote, lines, a, b)


def check_doc_loc(root: Path, where: str) -> str | None:
    d = DOC_RE.search(where)
    if d:
        docs = sorted(root.glob(DOC_GLOB[d.group(1)].format(d.group(2))))
        if not docs:
            return f"[no-doc] {d.group(0)} has no document in this project"
        text = docs[0].read_text(encoding="utf-8", errors="replace")
        gone = [x for x in PART_RE.findall(where) if x not in text]
        return f"[no-doc] {', '.join(gone)} is not in {docs[0].name}" if gone else None
    i = ITEM_RE.search(where)
    if i:
        f = root / ITEM_FILES[i.group(1)]
        return None if f.is_file() and i.group(0) in f.read_text(encoding="utf-8", errors="replace") else \
            f"[no-doc] {i.group(0)} is not in {ITEM_FILES[i.group(1)]}"
    return "[unlocated] give a file:line inside the project or a document id (SPEC-0001 AC-003, ADR-0003, D-070)"


def check_item(root: Path, it: Item) -> list[str]:
    sev, where = it.fields.get("severity", "").strip().lower(), it.fields.get("where", "").strip().strip("`")
    out = []
    if it.kind == "unresolved" and sev:
        out.append(f"[unresolved-severity] an UNRESOLVED item names a missing fact and carries no severity (got {sev!r})")
    if it.kind == "finding" and sev not in SEVERITIES:
        out.append(f"[severity] {sev or '(none)'} — use one of {', '.join(SEVERITIES)}")
    if not where:
        return out + ["[unlocated] no location"]
    quote = first_quote(it.fields.get("evidence", ""))
    if hidden(where) or (quote and hidden(quote)):
        return out + ["[hidden-char] an invisible character in the location or the quote"]
    if ABS_RE.search(where):
        return out + [f"[outside] {where[:80]}: an absolute path — cite it relative to the project root"]
    # A finding in code is tied to that code by its quote; without one nothing a machine can check says the finding is
    # about what is written there (review 2026-10-22 H6). A document id needs none: its id is what is checked.
    unquoted = it.kind == "finding" and not quote
    locs = list(LOC_RE.finditer(where))
    if not locs:
        bare = where.split()[0].replace("\\", "/")
        if "/" in bare or re.search(r"\.[A-Za-z]\w*$", bare):  # a path without a line: the quote may sit anywhere in it
            problem = path_problem(root, bare) or (None if (root / bare).is_file() else f"[no-file] {bare} does not exist")
            if not problem and quote and not quote_near(quote, (root / bare).read_text(
                    encoding="utf-8", errors="replace").splitlines(), 1, 10 ** 9):
                problem = f"[quote-absent] the quote is not in {bare}"
            return out + ([problem] if problem else [NO_QUOTE] if unquoted else [])
        problem = check_doc_loc(root, where)
        return out + ([problem] if problem else [])
    found = False
    for m in locs:
        problem, here = check_file_loc(root, m, quote)
        if problem:
            out.append(problem)
        found = found or here
    if not any(p.startswith(UNREAD) for p in out):
        if quote and not found:
            out.append(f"[quote-absent] `{' '.join(quote.split())[:60]}` is not within {NEAR} lines of {where}")
        elif unquoted:
            out.append(NO_QUOTE)
    return out


def check_closing(items: list[Item], closing: str, has_checks: bool) -> list[str]:
    blocking = sum(it.kind == "finding" and it.fields.get("severity", "").strip().lower() in ("critical", "high")
                   for it in items)
    r, c = REVIEW_END_RE.match(closing), CRITIC_END_RE.match(closing)
    if r:
        bad = r.group(1) == "VERDICT" and r.group(2).lower() == "approve" and blocking
        return [f"[closing] VERDICT: approve over {blocking} critical/high finding(s)"] if bad else []
    if c:
        out = [] if has_checks else ["[closing] no CHECKS line — the critic's work is not shown"]
        for sev, said in zip(SEVERITIES, c.groups()[1:5]):
            rows = sum(it.kind == "finding" and it.fields.get("severity", "").strip().lower() == sev for it in items)
            if rows != int(said or 0):  # a closing line without a critical count holds no critical row
                out.append(f"[closing] the closing line says {said or 0} {sev}, the rows hold {rows}")
        unresolved = any(it.kind == "unresolved" for it in items)
        want = "FAIL" if blocking else ("INCONCLUSIVE" if unresolved else "OK")
        if c.group(6) != want:
            out.append(f"[closing] VERDICT {c.group(6)} — the rows call for {want}")
        return out
    return [f"[closing] the last line is not a closing line: {closing[:80]!r}"]


def check_text(text: str, root: Path) -> tuple[int, list[str], str]:
    """(exit code, problem lines, summary line)."""
    root = root.resolve()
    items, closing, has_checks = parse(text)
    has_closing = bool(REVIEW_END_RE.match(closing) or CRITIC_END_RE.match(closing))
    if not items and not has_closing:
        return 2, [], "FINDINGS INCONCLUSIVE: nothing readable — no finding and no closing line"
    problems = [f"{it.ident} ({it.fields.get('where', '').strip()[:60] or 'no location'}): {p}"
                for it in items for p in check_item(root, it)]
    problems += [f"closing line: {p}" for p in check_closing(items, closing, has_checks)]
    found = sum(it.kind == "finding" for it in items)
    shown = f"{found} finding(s), {len(items) - found} unresolved, closing: {closing[:70] or '(none)'}"
    return (1, problems, f"FINDINGS FAIL: {len(problems)} problem(s) — {shown}") if problems else \
        (0, [], f"FINDINGS PASS: {shown}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="check that a review's findings are located and evidenced")
    ap.add_argument("review", help="the review text file, or - for stdin")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]), help="the project root")
    a = ap.parse_args(argv)
    try:
        text = sys.stdin.read() if a.review == "-" else Path(a.review).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"FINDINGS INCONCLUSIVE: cannot read {a.review}: {e}")
        return 2
    rc, problems, summary = check_text(text, Path(a.root))
    for p in problems:
        print(f"  {p}")
    print(summary)
    return rc


if __name__ == "__main__":
    sys.exit(main())
