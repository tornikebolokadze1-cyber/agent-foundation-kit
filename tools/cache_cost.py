#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cache and cost of Claude Code requests (ADR-0010) — numbers only, never message content.

tools/observe.py collects one Request per model call from the session transcripts. This module prices them at
Anthropic's API list prices, splits the cost into cache reads, cache writes, output and uncached input, and
names the most likely cause of every rebuild — a call that had to write again, into the cache, a large part of
the context that was already there one call earlier. The owner pays by subscription, so the dollars are a
yardstick for how fast the limits are spent, not a bill.

Prices come from tools/model_prices.toml (the CACHE_PRICES environment variable overrides the path — the drill
uses it). A model with no price there is listed as unpriced and left out of the total: never counted as free.
"""
from __future__ import annotations

import os
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

PRICES_FILE = Path(__file__).resolve().parent / "model_prices.toml"
REBUILD_TOKENS = 50_000  # a call that re-wrote at least this much of the context it already had
# Measured 2026-10-10 in this project's transcripts: the main session writes 1-hour entries, subagents 5-minute.
TTL_1H_S, TTL_5M_S = 3600, 300
CAUSE_KA = {
    "start": "სესიის დაწყება",
    "fallback": "მოდელი თავისით შეიცვალა უარის შემდეგ",
    "model": "მოდელის გადართვა",
    "compaction": "compact",
    "restart": "Claude Code გადაიტვირთა, განახლდა ან სესია თავიდან გაიხსნა",
    "ttl": "პაუზა ქეშის ვადაზე გრძელი",
    "other": "მიზეზი უცნობია",
}
PART_KA = {"read": "ქეშიდან კითხვა", "write": "ქეშში ჩაწერა", "output": "პასუხი", "uncached": "ქეშის გარეშე"}


@dataclass
class Request:
    """One model call: the usage of one assistant message, de-duplicated by message id. The three flags say what
    the transcript recorded between the previous call and this one."""

    source: str  # the transcript file it came from — rebuilds are judged within one file
    sub: bool
    model: str
    t: float = 0.0
    version: str = ""
    inp: int = 0
    read: int = 0
    write: int = 0
    w5: int = 0
    w1h: int = 0
    out: int = 0
    compacted: bool = False  # a compaction
    fallback: bool = False  # Claude Code switched the model by itself after a refusal
    restarted: bool = False  # a session_context record: Claude Code (re)opened the session

    def update(self, usage: dict) -> None:
        raw = usage.get("cache_creation")
        cc: dict = raw if isinstance(raw, dict) else {}
        self.inp = int(usage.get("input_tokens") or 0)
        self.read = int(usage.get("cache_read_input_tokens") or 0)
        self.write = int(usage.get("cache_creation_input_tokens") or 0)
        self.w5 = int(cc.get("ephemeral_5m_input_tokens") or 0)
        self.w1h = int(cc.get("ephemeral_1h_input_tokens") or 0)
        self.out = max(self.out, int(usage.get("output_tokens") or 0))

    @property
    def context(self) -> int:
        return self.inp + self.read + self.write


@dataclass(frozen=True)
class Price:
    input: float
    output: float
    cache_read: float
    long_threshold: int = 0
    long_input: float = 0.0
    long_output: float = 0.0
    long_cache_read: float = 0.0


@dataclass(frozen=True)
class PriceBook:
    models: dict[str, Price]
    write_5m: float
    write_1h: float
    source: str

    def find(self, model: str) -> Price | None:
        """The listed model this id names exactly — a date suffix (-20251001) and a context tag ([1m]) are allowed, a
        different version is not: claude-opus-5-6 is unpriced, never priced as claude-opus-5."""
        for name, price in self.models.items():
            if re.fullmatch(re.escape(name) + r"(-\d{8})?(\[[^\]]*\])?", model):
                return price
        return None


def load_prices(path: Path | None = None) -> PriceBook:
    p = path or Path(os.environ.get("CACHE_PRICES") or PRICES_FILE)
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    models = {name: Price(**vals) for name, vals in (data.get("models") or {}).items()}
    return PriceBook(models, float(data["write_5m"]), float(data["write_1h"]), str(data.get("source") or ""))


def input_price(p: Price, tokens: int) -> float:
    return p.long_input if p.long_threshold and tokens > p.long_threshold else p.input


def cost_parts(r: Request, p: Price, book: PriceBook) -> dict[str, float]:
    long = bool(p.long_threshold) and r.context > p.long_threshold
    i = input_price(p, r.context)
    rd = p.long_cache_read if long else p.cache_read
    o = p.long_output if long else p.output
    unlabelled = max(r.write - r.w5 - r.w1h, 0)  # a write with no TTL breakdown is priced as a 5-minute write
    return {"read": r.read * rd / 1e6,
            "write": ((r.w5 + unlabelled) * book.write_5m + r.w1h * book.write_1h) * i / 1e6,
            "output": r.out * o / 1e6,
            "uncached": r.inp * i / 1e6}


def ttl_s(r: Request, prev: Request) -> int:
    if r.w1h or prev.w1h:
        return TTL_1H_S
    if r.w5 or prev.w5:
        return TTL_5M_S
    return TTL_5M_S if r.sub else TTL_1H_S


def cause_of(r: Request, prev: Request | None, big_model: str, pending: set[str]) -> str:
    if prev is None:
        return "start"
    if "fallback" in pending:
        return "fallback"
    if big_model and r.model != big_model:
        return "model"
    if "compaction" in pending:
        return "compaction"
    if "restart" in pending or (prev.version and r.version and r.version != prev.version):
        return "restart"
    if prev.t and r.t and r.t - prev.t > ttl_s(r, prev):
        return "ttl"
    return "other"


def rebuilds(reqs: list[Request]) -> list[tuple[str, Request, int]]:
    """(cause, request, re-written tokens) for every call that wrote again at least REBUILD_TOKENS of the context
    it already had — judged within its own transcript file. New content (a big file just read) is not a rebuild:
    what grew since the previous call is subtracted from the write. A compaction, a restart or a refusal fallback
    stays pending until the next rebuild, because the call right after one is often small."""
    by_source: dict[str, list[Request]] = defaultdict(list)
    for r in reqs:
        by_source[r.source].append(r)
    found: list[tuple[str, Request, int]] = []
    for calls in by_source.values():
        prev: Request | None = None
        big_model = ""  # the model that held the last large context
        pending: set[str] = set()
        for r in calls:
            pending |= {name for name, on in (("compaction", r.compacted), ("fallback", r.fallback),
                                              ("restart", r.restarted)) if on}
            rewritten = r.write - max(r.context - prev.context, 0) if prev else r.write
            if rewritten >= REBUILD_TOKENS:
                found.append((cause_of(r, prev, big_model, pending), r, rewritten))
                pending.clear()
            elif r.context >= REBUILD_TOKENS:
                pending.clear()  # a large context read from the cache: whatever the marker caused is over
            if r.context >= REBUILD_TOKENS:
                big_model = r.model
            prev = r
    return found


def summarize(reqs: list[Request], book: PriceBook | None = None) -> dict:
    """Everything the report shows, as plain data (also the `cache` field of `observe.py report --json`)."""
    s: dict = {"requests": len(reqs), "usd": None, "parts": {}, "cache_share": None, "by_model": {},
               "rebuilds": {}, "rebuild_share_main": None, "largest": None, "unpriced": [], "prices": "", "error": ""}
    if not reqs:
        return s
    total_in = sum(r.context for r in reqs)
    s["cache_share"] = round(100 * sum(r.read for r in reqs) / total_in, 1) if total_in else None
    found = rebuilds(reqs)
    for cause in CAUSE_KA:
        hits = [n for c, _, n in found if c == cause]
        if hits:
            s["rebuilds"][cause] = {"count": len(hits), "tokens": sum(hits)}
    main_writes = sum(r.write for r in reqs if not r.sub)
    avoidable = sum(n for c, r, n in found if not r.sub and c != "start")
    s["rebuild_share_main"] = round(100 * avoidable / main_writes, 1) if main_writes else None
    if found:
        c, r, n = max(found, key=lambda x: x[2])
        s["largest"] = {"cause": c, "tokens": n, "model": r.model, "subagent": r.sub}
    try:
        book = book or load_prices()
    except (OSError, ValueError, KeyError, TypeError) as e:
        s["error"] = f"prices unreadable — {type(e).__name__}: {e}"
        return s
    s["prices"] = book.source
    parts: dict[str, float] = defaultdict(float)
    unpriced: set[str] = set()
    for r in reqs:
        m = s["by_model"].setdefault(r.model + (" (subagent)" if r.sub else ""), {"requests": 0, "usd": 0.0})
        m["requests"] += 1
        p = book.find(r.model)
        if p is None:
            unpriced.add(r.model)
            m["usd"] = None
            continue
        cp = cost_parts(r, p, book)
        for k, v in cp.items():
            parts[k] += v
        if m["usd"] is not None:
            m["usd"] += sum(cp.values())
    for m in s["by_model"].values():
        m["usd"] = None if m["usd"] is None else round(m["usd"], 2)
    s["usd"] = round(sum(parts.values()), 2) if parts else None  # nothing priced → unknown, never $0
    s["parts"] = {k: round(v, 2) for k, v in parts.items()}
    s["unpriced"] = sorted(unpriced)
    return s


def kilo(n: int) -> str:
    return f"{n / 1e6:.2f}M" if n >= 1e6 else f"{n / 1e3:.0f}K"


def render(s: dict) -> list[str]:
    """The Georgian report section for tools/observe.py."""
    lines = ["## ქეში და ხარჯი"]
    if not s["requests"]:
        return lines + ["მოდელის გამოძახება (usage-ით) ვერ ვიპოვე — ხარჯს ვერ ვითვლი."]
    share = f"{s['cache_share']}%" if s["cache_share"] is not None else "?"
    if s["error"] or s["usd"] is None:
        why = s["error"] or "არცერთ მოდელს ფასი არ აქვს"
        lines.append(f"ფასი უცნობია ({why}) · ქეშიდან წაკითხული შემავალი ტექსტი: {share}")
    else:
        lines.append(f"API-ის ფასით ≈ ${s['usd']:.2f} — გამოწერის ლიმიტის საზომი, არა ანგარიში · "
                     f"ქეშიდან წაკითხული შემავალი ტექსტი: {share}")
        total = sum(s["parts"].values()) or 1.0
        lines.append("სად მიდის: " + " · ".join(f"{PART_KA[k]} {100 * v / total:.0f}%"
                                               for k, v in sorted(s["parts"].items(), key=lambda kv: -kv[1])))
        models = sorted(s["by_model"].items(), key=lambda kv: -(kv[1]["usd"] or 0))
        lines.append("მოდელები: " + " · ".join(
            f"{k} ${v['usd']:.2f} ({v['requests']} გამოძახება)" if v["usd"] is not None
            else f"{k} — ფასი არ აქვს ({v['requests']} გამოძახება)" for k, v in models))
    if s["rebuilds"]:
        lines.append("„თავიდან აწყობა\" (ერთ ნაბიჯზე 50K+ უკვე არსებული ტოკენის ხელახლა ჩაწერა): " + " · ".join(
            f"{CAUSE_KA[c]} ×{v['count']} ({kilo(v['tokens'])})" for c, v in s["rebuilds"].items()))
        if s["rebuild_share_main"] is not None:
            lines.append(f"მთავარ სესიაში ქეშში ჩაწერის {s['rebuild_share_main']}% აცილებად თავიდან აწყობაზე მოვიდა "
                         "(სესიის დაწყება არ ითვლება)")
    else:
        lines.append("„თავიდან აწყობა\" არ ყოფილა")
    if s["unpriced"]:
        lines.append(f"ფასი არ აქვს, ამიტომ ჯამში არ შედის: {', '.join(s['unpriced'])} — დაამატე tools/model_prices.toml-ში")
    if s["prices"]:
        lines.append(f"ფასები: tools/model_prices.toml — {s['prices']}")
    return lines
