#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The engine's status line (ADR-0010): the owner's own status line, the project's stage (ADR-0011) and one line about
the prompt cache.

The stage line names where the project stands in the F1–F5 loop and the person's next command, read from the documents'
statuses by tools/context_graph.py (`🧭 ეტაპი 2/5 · სპეციფიკაცია — SPEC-0001 გელოდება → /approve spec 0001`).

Claude Code runs the project's `statusLine` command on every update and every `refreshInterval` seconds, with a
JSON payload on stdin (session_id, transcript_path, model, context_window …), and shows what it prints. A project
setting replaces the user's, so this script first runs the BASE status line — `statusLine.command` from
~/.claude/settings.json, or ENGINE_STATUSLINE_BASE when that is set (empty = none) — with the same payload and
prints its output unchanged. Without a base, or when the base fails, it prints a short line itself: model ·
context % · the ↻N compaction badge (red from 3 — time for a new session, CLAUDE.md).

Then the cache line. Claude Code's own `prompt_cache` payload field (seen in 2.1.295: warm, ttl, expires_at,
recache_tokens_if_cold) is used when present; otherwise the state is read from the tail of this session's transcript
— when the newest model request went out and how long the cache lives (1 hour or 5 minutes, read from the newest
write; each request renews the life):
  ♻ ქეში თბილია ~14:05-მდე                         the next message reads the context from the cache
  ♻ ქეში იწურება 14:05-ზე (8 წთ)                    less than 10 minutes left
  ❄ ქეში ცივია: შემდეგი შეტყობინება 377K-ს თავიდან ჩაწერს (≈$3.02) — ახალი თემისთვის ახალი სესია იაფია
  ❄ ქეში ცივია, კონტექსტი პატარაა (45K) — თავიდან ჩაწერა იაფია
  ♻ ქეში: უცნობია (…)                              nothing readable — never shown as warm
The request time is taken from the record written just before the answer began (looked for in the last 4 MB), so
the estimate errs early.
A status line must never break the screen: this script always exits 0 and prints a short marker, never a traceback.
The owner's line runs through bash found on PATH — never from the current folder or from inside this project, where a
file could be planted — and it gets 4 seconds, after which it is stopped together with everything it started.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
# Windows looks for a program in the current folder before PATH unless this is set. Here the current folder is the
# project, where a planted bash.bat would otherwise run every 15 seconds with the owner's environment (critic S1).
os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import cache_cost  # noqa: E402

INNER = "ENGINE_STATUSLINE_INNER"  # set for the base command: a base that is this script prints nothing
TAILS = (256 * 1024, 4 * 1024 * 1024)  # bytes read from the end of the transcript; the larger only when needed
SOON_S = 600  # warn when less than 10 minutes of cache life are left
LARGE_TOKENS = 150_000  # a cold rewrite above this costs clearly more than a new session's start (~80K, ADR-0010)
BASE_TIMEOUT_S = 4
TOKEN_KEYS = ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
EMPTY = "empty"  # the session has made no model call yet
SID_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")  # a session id is a UUID: nothing that could walk out of a folder
RED, YELLOW, GREEN, DIM, RESET = "\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[2m", "\x1b[0m"
CYAN = "\x1b[36m"


def part(d: dict, key: str) -> dict:
    v = d.get(key)
    return v if isinstance(v, dict) else {}


def base_command() -> str:
    env = os.environ.get("ENGINE_STATUSLINE_BASE")
    if env is not None:
        return env.strip()
    try:
        cfg = json.loads((Path.home() / ".claude" / "settings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    sl = cfg.get("statusLine") if isinstance(cfg, dict) else None
    return str(sl.get("command") or "").strip() if isinstance(sl, dict) and sl.get("type") == "command" else ""


def trusted_bash() -> str | None:
    """bash from PATH — never one inside this project, where a file could have been planted."""
    found = shutil.which("bash")
    if not found:
        return None
    try:
        Path(found).resolve().relative_to(ROOT)
    except ValueError:
        return found
    return None


def kill_tree(proc: subprocess.Popen) -> None:
    """Stop the base command and everything it started — on Windows, killing bash alone leaves node or git running."""
    try:
        if os.name == "nt":
            taskkill = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "taskkill.exe"
            subprocess.run([str(taskkill), "/T", "/F", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run_base(cmd: str, payload: str) -> str:
    """The base status line's output, or "" when there is none, it fails or it is too slow. Input and output go
    through files, not pipes: a pipe still held by a grandchild would make even a timed-out wait block (critic S2)."""
    bash = trusted_bash() if cmd else None
    if not bash:
        return ""
    with tempfile.TemporaryFile() as fin, tempfile.TemporaryFile() as fout:
        fin.write(payload.encode("utf-8"))
        fin.seek(0)
        try:
            proc = subprocess.Popen([bash, "-c", cmd], stdin=fin, stdout=fout, stderr=subprocess.DEVNULL,
                                    env={**os.environ, INNER: "1"}, start_new_session=os.name != "nt")
        except OSError:
            return ""
        try:
            rc = proc.wait(timeout=BASE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            return ""
        fout.seek(0)
        out = fout.read().decode("utf-8", errors="replace")
    return out.rstrip() if rc == 0 else ""


def compactions(sid: str) -> int:
    if not SID_RE.fullmatch(sid):
        return 0
    state = Path(os.environ.get("CLAUDE_STATUSLINE_STATE_DIR") or Path.home() / ".claude" / "session-state")
    try:
        with (state / f"compacts-{sid}").open("rb") as f:
            return int(f.read(64).decode("ascii", errors="replace").strip() or 0)
    except (OSError, ValueError):
        return 0


def own_line(data: dict) -> str:
    model = part(data, "model")
    parts = [str(model.get("display_name") or model.get("id") or "?")]
    window = part(data, "context_window")
    if isinstance(window.get("used_percentage"), (int, float)):
        parts.append(f"კონტექსტი {round(window['used_percentage'])}%")
    n = compactions(str(data.get("session_id") or ""))
    if n >= 3:
        parts.append(f"{RED}↻{n} ახალი სესია → /session-close, მერე /clear{RESET}")
    elif n:
        parts.append(f"↻{n}")
    return " · ".join(parts)


def transcript_of(data: dict) -> Path | None:
    raw = str(data.get("transcript_path") or "")
    if raw:
        return Path(raw)
    sid = str(data.get("session_id") or "")
    cwd = part(data, "workspace").get("project_dir") or data.get("cwd")
    if SID_RE.fullmatch(sid) and cwd:
        folder = re.sub(r"[^A-Za-z0-9]", "-", str(cwd))
        return Path.home() / ".claude" / "projects" / folder / f"{sid}.jsonl"
    return None


def records(path: Path, tail: int) -> Iterator[dict]:
    """The main-thread records of the transcript's last `tail` bytes, newest first."""
    with path.open("rb") as f:
        end = f.seek(0, os.SEEK_END)
        start = max(0, end - tail)
        f.seek(start)
        lines = f.read(end - start).split(b"\n")
    for raw in reversed(lines[1:] if start else lines):  # the first line of a cut tail is a fragment
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        if isinstance(d, dict) and not d.get("isSidechain"):
            yield d


def stamp(d: dict) -> float:
    try:
        return datetime.fromisoformat(str(d.get("timestamp") or "").replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def write_ttl(usage: dict) -> int:
    cc = part(usage, "cache_creation")
    if cc.get("ephemeral_1h_input_tokens"):
        return cache_cost.TTL_1H_S
    return cache_cost.TTL_5M_S if cc.get("ephemeral_5m_input_tokens") else 0


def newest_call(recs: Iterator[dict]) -> dict | None:
    """The newest model call: its id, model, context size, when its request went out, and the cache life."""
    call: dict | None = None
    for d in recs:
        msg = part(d, "message")
        usage = msg.get("usage") if d.get("type") == "assistant" and msg.get("model") != "<synthetic>" else None
        if call is None:
            if isinstance(usage, dict):
                call = {"id": msg.get("id"), "model": str(msg.get("model") or ""), "sent": stamp(d), "before": 0.0,
                        "tokens": sum(int(usage.get(k) or 0) for k in TOKEN_KEYS), "ttl": write_ttl(usage)}
            continue
        if isinstance(usage, dict) and msg.get("id") == call["id"]:
            call["sent"] = stamp(d) or call["sent"]  # an earlier line of the same answer: the request is older still
            call["before"] = 0.0
            continue
        if not call["before"]:
            call["before"] = stamp(d)  # the last record before the answer: the request went out right after it
        if isinstance(usage, dict):  # an earlier model call — every line of the newest one is behind us
            call["ttl"] = call["ttl"] or write_ttl(usage)
            if call["ttl"]:
                break
    if call is not None:
        call["sent"] = call["before"] or call["sent"]
        call["ttl"] = call["ttl"] or cache_cost.TTL_1H_S  # the main session writes 1-hour entries (ADR-0010)
    return call


def rewrite_cost(model: str, tokens: int, ttl: int) -> float | None:
    try:
        book = cache_cost.load_prices()
    except (OSError, ValueError, KeyError, TypeError):
        return None
    price = book.find(model)
    if price is None:
        return None
    factor = book.write_1h if ttl >= cache_cost.TTL_1H_S else book.write_5m
    return tokens * cache_cost.input_price(price, tokens) * factor / 1e6


def cache_state(data: dict) -> dict | str:
    """{expires, warm, ttl, tokens, model} — from Claude Code's `prompt_cache` field when the payload has it, else from
    the transcript tail; a string says why the state is unknown (EMPTY: no model call yet)."""
    pc = part(data, "prompt_cache")
    expires = pc.get("expires_at")
    if isinstance(expires, (int, float)) and not isinstance(expires, bool):
        tokens = pc.get("recache_tokens_if_cold")
        if not isinstance(tokens, int):
            tokens = int(part(data, "context_window").get("total_input_tokens") or 0)
        return {"expires": float(expires), "warm": pc.get("warm") is not False, "tokens": tokens, "model": "",
                "ttl": cache_cost.TTL_5M_S if pc.get("ttl") == "5m" else cache_cost.TTL_1H_S}
    if str(data.get("transcript_path") or "").startswith(("\\\\", "//")):
        return "ქსელური გზა — არ იხსნება"  # never touch a network share from a status line (critic S4)
    path = transcript_of(data)
    if path is None or not path.is_file():
        return "სესიის ჩანაწერი არ ჩანს"
    try:
        call = newest_call(records(path, TAILS[0]))
        if (call is None or not call["before"]) and path.stat().st_size > TAILS[0]:
            call = newest_call(records(path, TAILS[1])) or call  # the request's start was not in the short tail
    except OSError:
        return "ჩანაწერი ვერ წავიკითხე"
    if call is None:
        return EMPTY
    if not call["sent"]:
        return "ჩანაწერს დრო არ აქვს"
    return {"expires": call["sent"] + call["ttl"], "warm": True, "ttl": call["ttl"], "tokens": call["tokens"],
            "model": call["model"]}


def cache_line(data: dict, now: float) -> str:
    state = cache_state(data)
    if state == EMPTY:
        return f"{DIM}♻ ქეში: ჯერ ცარიელია{RESET}"
    if isinstance(state, str):
        return f"{DIM}♻ ქეში: უცნობია ({state}){RESET}"
    left = state["expires"] - now
    clock = datetime.fromtimestamp(state["expires"]).strftime("%H:%M")
    if state["warm"] and left > SOON_S:
        return f"{GREEN}♻ ქეში თბილია ~{clock}-მდე{RESET}"
    if state["warm"] and left > 0:
        return f"{YELLOW}♻ ქეში იწურება {clock}-ზე ({math.ceil(left / 60)} წთ){RESET}"
    tokens = state["tokens"]
    if tokens < LARGE_TOKENS:
        return f"{DIM}❄ ქეში ცივია, კონტექსტი პატარაა ({cache_cost.kilo(tokens)}) — თავიდან ჩაწერა იაფია{RESET}"
    cost = rewrite_cost(str(part(data, "model").get("id") or state["model"]), tokens, state["ttl"])
    price = f" (≈${cost:.2f})" if cost is not None else ""
    return (f"{RED}❄ ქეში ცივია: შემდეგი შეტყობინება {cache_cost.kilo(tokens)}-ს თავიდან ჩაწერს{price}"
            f" — ახალი თემისთვის ახალი სესია იაფია{RESET}")


def stage_line() -> str:
    """Where the project stands and the person's next command (ADR-0011) — read from the documents' statuses, the
    same way the SessionStart brief reads them (~15 ms). Empty when this folder holds no intent.md."""
    import context_graph as cg
    root = cg.default_root()
    if not (root / "intent.md").is_file():
        return ""
    return f"{CYAN}🧭 {cg.project_stage(cg.load(root)).status_line()}{RESET}"


def main() -> int:
    payload = sys.stdin.read()
    if os.environ.get(INNER):
        return 0  # started as its own base: the outer run prints everything
    try:
        data = json.loads(payload) if payload.strip() else {}
    except ValueError:
        data = {}
    data = data if isinstance(data, dict) else {}
    # A status line must never break the screen: each half fails on its own, with a visible marker, never a traceback.
    try:
        first = run_base(base_command(), payload) or own_line(data)
    except Exception as e:
        first = f"statusline: {type(e).__name__}"
    try:
        stage = stage_line()
    except Exception as e:
        stage = f"{DIM}🧭 ეტაპი: უცნობია ({type(e).__name__}){RESET}"
    try:
        second = cache_line(data, time.time())
    except Exception as e:
        second = f"{DIM}♻ ქეში: უცნობია ({type(e).__name__}){RESET}"
    print("\n".join(line for line in (first, stage, second) if line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
