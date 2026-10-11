#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The owner's approval: the only way a document becomes accepted or approved.

Run by the owner-only skill /approve (it hands over everything the owner typed as
ONE argument) or by hand from a terminal:

    py -3.12 tools/approve.py "adr 0003"

What it does, in order: find the document, check its preconditions (a spec needs an
accepted intent, a plan needs an approved spec, a superseding ADR needs the old one
accepted), change the status, write one row per change into memory/approvals.md,
re-run the graph check on the touched files, and roll everything back if the check
finds a new error. It always exits 0 and prints a Georgian result, because a non-zero
exit would abort the /approve skill and hide the message from the owner.

The guard (.claude/hooks/guard.py) stops the agent from running this file or writing
the ledger; the LEDGER check in tools/context_graph.py catches an approval status that
has no row here, however it got there.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
import context_graph as cg  # noqa: E402

USAGE = """გამოყენება:
  /approve                        რა ელოდება შენს დამტკიცებას
  /approve intent                 intent.md → accepted
  /approve spec 0001              SPEC-0001 → approved   (საჭიროა: intent accepted)
  /approve plan 0001              PLAN-0001 → approved   (საჭიროა: მისი spec approved)
  /approve adr 0001               ADR-0001 → accepted    (თუ supersedes აქვს, ძველი → superseded)
  /approve reject adr 0001 მიზეზი  ADR-0001 → rejected
ბოლოს შეგიძლია შენიშვნა დაურთო: /approve adr 0001 ვეთანხმები, ოღონდ …"""

TARGET = {"intent": "accepted", "spec": "approved", "plan": "approved", "adr": "accepted"}
FROM = cg.PENDING_STATUSES  # the owner approves only what is waiting for them


def root_dir() -> Path:
    env = os.environ.get("APPROVE_ROOT") or os.environ.get("CONTEXT_ROOT")
    return Path(env).resolve() if env else Path(__file__).resolve().parents[1]


def stamp() -> str:
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")


def ledger_row(ident: str, frm: str, to: str, rel: str, note: str) -> str:
    note = (note or "—").replace("|", "¦").replace("\n", " ").strip()
    return f"| {stamp()} | {ident} | {frm} → {to} | {rel} | {note} |"


LEDGER_HEADER = (
    "---\nid: approvals\ntype: memory\ntitle: დამტკიცებების ჟურნალი\nstatus: living\n---\n\n"
    "# დამტკიცებების ჟურნალი (owner ledger)\n\n"
    "მხოლოდ `tools/approve.py` წერს (მფლობელის `/approve`). აგენტს ამ ფაილის შეცვლა ეკრძალება, "
    "gate-ის LEDGER შემოწმება კი ითხოვს, რომ ყოველ დამტკიცებულ სტატუსს აქ ჰქონდეს ჩანაწერი.\n\n"
    "| როდის | id | ცვლილება | ფაილი | შენიშვნა |\n|---|---|---|---|---|\n"
)


def ledger_text(root: Path) -> str | None:
    """The owner ledger as it is now (None if it does not exist yet)."""
    ledger = root / cg.LEDGER_PATH
    return ledger.read_text(encoding="utf-8") if ledger.exists() else None


def write_ledger(root: Path, before: str | None, rows: list[str]) -> None:
    """Append rows to the ledger text read earlier (the one place the ledger is written)."""
    ledger = root / cg.LEDGER_PATH
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text((before or LEDGER_HEADER).rstrip("\n") + "\n" + "\n".join(rows) + "\n",
                      encoding="utf-8", newline="\n")


def parse_args(raw: str) -> tuple[str, str, str, str]:
    """-> (action, kind, number, note). action: list | approve | reject | help."""
    toks = raw.split()
    if not toks or toks[0].lower() in ("list", "სია", "ls"):
        return "list", "", "", ""
    if toks[0].lower() in ("help", "-h", "--help", "დახმარება"):
        return "help", "", "", ""
    action = "approve"
    if toks[0].lower() in ("reject", "უარი"):
        action, toks = "reject", toks[1:]
    if not toks:
        return "help", "", "", ""
    head = toks[0].lower()
    m = re.fullmatch(r"(adr|spec|plan)-(\d+)", head)
    if m:
        return action, m.group(1), f"{int(m.group(2)):04d}", " ".join(toks[1:])
    if head == "intent":
        return action, "intent", "", " ".join(toks[1:])
    if head in ("adr", "spec", "plan") and len(toks) > 1 and toks[1].isdigit():
        return action, head, f"{int(toks[1]):04d}", " ".join(toks[2:])
    return "help", "", "", ""


def find_doc(g: cg.Graph, kind: str, num: str) -> cg.Node | None:
    if kind == "intent":
        return g.nodes.get("intent.md")
    want = f"{kind.upper()}-{num}"
    hits = [n for n in g.nodes.values() if not n.foreign and n.type == kind and n.id == want]
    return hits[0] if len(hits) == 1 else None


def related(g: cg.Graph, n: cg.Node, key: str) -> list[cg.Node]:
    return [g.nodes[ln.resolved] for ln in n.links if ln.kind == key and ln.resolved in g.nodes]


def plan_changes(g: cg.Graph, action: str, doc: cg.Node) -> tuple[list[tuple[cg.Node, str]], str | None]:
    """[(node, new_status)] or an error message."""
    kind, st = doc.type, doc.status
    errs = [i for i in cg.filter_issues(cg.check(g), [str(g.root / doc.path)], g.root)
            if i.level == "error" and i.path == doc.path]
    if errs:
        return [], "ჯერ ეს შეცდომები უნდა გასწორდეს:\n" + "\n".join("  " + i.fmt() for i in errs[:8])
    if action == "reject":
        if kind != "adr":
            return [], "უარყოფა (reject) მხოლოდ ADR-ზე მუშაობს; სპეციფიკაცია ან გეგმა უბრალოდ draft-ად რჩება."
        if st != "proposed":
            return [], f"{doc.id} უკვე `{st}`-ია — უარყოფა მხოლოდ proposed ADR-ზე შეიძლება."
        return [(doc, "rejected")], None
    if st not in FROM[kind]:
        return [], f"{doc.id} არის `{st}` — დამტკიცება შეიძლება მხოლოდ სტატუსიდან: {', '.join(sorted(FROM[kind]))}."
    if kind == "intent" and not cg.idea_written(g.root / doc.path):
        return [], "intent.md-ის §1 ჯერ ცარიელია — ჯერ იდეა უნდა ჩაიწეროს (`/intent`), მერე დამტკიცდება."
    changes = [(doc, TARGET[kind])]
    if kind == "spec":
        intents = related(g, doc, "intent")
        if not intents or intents[0].status != "accepted":
            return [], "ჯერ intent.md უნდა დაამტკიცო (`/approve intent`) — სპეციფიკაცია მასზე დგას."
    if kind == "plan":
        specs = related(g, doc, "spec")
        if not specs or specs[0].status != "approved":
            shown = specs[0].id if specs else "(ბმული აკლია)"
            return [], f"ჯერ ამ გეგმის სპეციფიკაცია უნდა დამტკიცდეს: {shown}."
    if kind in ("adr", "spec"):
        for old in related(g, doc, "supersedes"):
            if old.type != kind or old.status != TARGET[kind]:
                return [], f"{doc.id} ანაცვლებს {old.id}-ს, მაგრამ ის `{old.status}`-ია და არა `{TARGET[kind]}`."
            changes.append((old, "superseded"))
    return changes, None


def apply(g: cg.Graph, changes: list[tuple[cg.Node, str]], note: str, new_doc: cg.Node) -> str | None:
    root = g.root
    ledger = root / cg.LEDGER_PATH
    originals: dict[Path, str | None] = {}
    today = dt.date.today().isoformat()
    try:
        for node, new_status in changes:
            p = root / node.path
            text = p.read_text(encoding="utf-8").replace("\r\n", "\n")
            originals[p] = text
            text = cg.set_field(text, "status", new_status)
            if "updated" in (node.fm or {}) or node.type != "adr":
                text = cg.set_field(text, "updated", today)
            if new_status == "superseded":
                text = cg.set_field(text, "superseded_by", f"[[{new_doc.stem}]]")
            p.write_text(text, encoding="utf-8", newline="\n")
        originals[ledger] = ledger_text(root)
        rows = []
        for node, new_status in changes:
            why = note if node is new_doc else f"ჩაანაცვლა {new_doc.id}"
            rows.append(ledger_row(node.id, node.status, new_status, node.path, why))
        write_ledger(root, originals[ledger], rows)
        g2 = cg.load(root)
        touched = [str(root / n.path) for n, _ in changes]
        errs = [i for i in cg.filter_issues(cg.check(g2), touched, root) if i.level == "error"]
        if errs:
            raise RuntimeError("შემოწმებამ ახალი შეცდომა იპოვა:\n" + "\n".join("  " + i.fmt() for i in errs[:8]))
        return None
    except Exception as e:  # restore every file exactly as it was
        for p, text in originals.items():
            if text is None:
                p.unlink(missing_ok=True)
            else:
                p.write_text(text, encoding="utf-8", newline="\n")
        return f"ცვლილება გაუქმდა (rollback): {e}"


def list_pending(g: cg.Graph) -> str:
    pend, eng = cg.pending(g), cg.pending(g, engine=True)
    lines = ["შენს დამტკიცებას ელოდება:"] if pend else ["პროექტში ამჟამად არაფერი ელოდება შენს დამტკიცებას."]
    lines += [f"  {cg.approve_hint(n):22} {n.id} — {n.title} (`{n.status}`)" for n in pend]
    if eng:
        lines.append(f"ძრავის საკუთარი ADR-ები ({len(eng)}, `scope: engine`) პროექტის ეტაპებს არ აჩერებს — ისინი ძრავის "
                     f"ავტორის გადასაწყვეტია: {', '.join(n.id for n in eng)}.")
    return "\n".join(lines)


def next_step(root: Path, doc: cg.Node) -> str:
    """What comes after this decision — read from the documents, as the SessionStart brief reads it (ADR-0011)."""
    if cg.is_engine(doc):
        return "ℹ ეს ძრავის წესია (`scope: engine`) — პროექტის ეტაპს არ ცვლის."
    try:
        st = cg.project_stage(cg.load(root))
    except Exception as e:  # the decision itself is already recorded; only this hint failed
        return f"(შემდეგი ეტაპი ვერ განისაზღვრა: {type(e).__name__})"
    return f"➡ ახლა: {st.label} — {st.step}.\n   {st.person}."


def main(argv: list[str]) -> int:
    raw = " ".join(argv[1:]).strip().strip("'\"")
    root = root_dir()
    try:
        g = cg.load(root)
    except Exception as e:
        print(f"❌ პროექტის წაკითხვა ვერ მოხერხდა ({root}): {e}")
        return 0
    action, kind, num, note = parse_args(raw)
    if action == "help":
        print(f"❌ ვერ გავიგე: „{raw}“\n\n{USAGE}")
        return 0
    if action == "list":
        print(list_pending(g))
        return 0
    doc = find_doc(g, kind, num)
    if doc is None:
        label = "intent.md" if kind == "intent" else f"{kind.upper()}-{num}"
        print(f"❌ {label} ვერ მოიძებნა (ან ერთზე მეტი ფაილი აქვს ერთი id).\n\n{list_pending(g)}")
        return 0
    target = "rejected" if action == "reject" else TARGET[kind]
    if doc.status == target and target not in g.ledger.get(doc.id, []):
        # the owner changed the status by hand (e.g. in Obsidian): record it, change nothing else
        write_ledger(root, ledger_text(root), [ledger_row(doc.id, "(ხელით)", target, doc.path,
                                                          note or "ხელით შეცვლილი სტატუსი დადასტურდა")])
        print(f"✅ {doc.id} უკვე `{target}` იყო ხელით შეცვლილი — ახლა ჟურნალშიც ჩაიწერა.")
        return 0
    changes, err = plan_changes(g, action, doc)
    if err:
        print(f"❌ {doc.id} „{doc.title}“ — არ დამტკიცდა.\n{err}")
        return 0
    err = apply(g, changes, note, doc)
    if err:
        print(f"❌ {doc.id} — {err}")
        return 0
    verb = "უარყოფილია" if action == "reject" else "დამტკიცდა"
    lines = [f"✅ {doc.id} „{doc.title}“ — {doc.status} → {target} ({verb}). ჩაიწერა memory/approvals.md-ში."]
    for node, st in changes[1:]:
        lines.append(f"   {node.id} → {st} (ჩაანაცვლა {doc.id}).")
    lines.append(next_step(root, doc))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
