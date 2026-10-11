#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Maker–checker orchestration runner (ADR-0005). Dormant until config.toml has enabled = true.

  py -3.12 orchestration/run.py status
  py -3.12 orchestration/run.py arch --topic "<question>" [--context FILE ...] [--dry-run]
  py -3.12 orchestration/run.py code-check --plan PLAN-0001 --task T3 [--base main] [--dry-run]

Architecture loop (1 round per topic): Fable writes a proposal -> Astra audits it and
states its own position -> Fable writes the final synthesis with an ADR draft (proposed).
Code loop (max 2 rounds per task): the interactive session (Opus) writes the code; Sol
reviews the diff against the spec and REVIEW.md and returns a VERDICT.

Every run is recorded in orchestration/runs/<id>/ (prompts, answers, meta.json). The
round caps are counted from those records, so they hold across sessions.

Exit: 0 ok · 1 a step failed · 3 disabled · 4 round cap reached · 5 bad input.
Checkers run `codex exec -s read-only` (ChatGPT login, no API key); Claude calls run
with --restricted and read-only tools. A dry run calls no model and writes nothing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("ORCH_ROOT") or HERE.parent).resolve()
CONFIG = Path(os.environ.get("ORCH_CONFIG") or HERE / "config.toml")
RUNS = Path(os.environ.get("ORCH_RUNS") or HERE / "runs")
PROMPTS = HERE / "prompts"
sys.path.insert(0, str(HERE.parent / "tools"))

EXIT_FAIL, EXIT_DISABLED, EXIT_CAP, EXIT_INPUT = 1, 3, 4, 5


def load_config() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def slug(text: str) -> str:
    ascii_part = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40].strip("-")
    return ascii_part or "topic"


def topic_key(text: str) -> str:
    norm = " ".join(text.lower().split())
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:10]


def records() -> list[dict]:
    out = []
    for meta in sorted(RUNS.glob("*/meta.json")):
        try:
            out.append(json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return out


def completed(loop: str, key: str) -> int:
    return sum(1 for r in records() if r.get("loop") == loop and r.get("key") == key and r.get("status") == "complete")


def fill(template: str, **values: str) -> str:
    text = (PROMPTS / template).read_text(encoding="utf-8")
    for k, v in values.items():
        text = text.replace("{" + k + "}", v)
    return text


def nested_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    env["EPISODIC_NESTED"] = "1"
    return env


def claude_cmd(model: str, tools: str) -> list[str]:
    exe = shutil.which("claude") or "claude"
    return [exe, "-p", "Follow the task given on stdin exactly.", "--model", model, "--restricted",
            "--strict-mcp-config", "--tools", tools, "--no-session-persistence", "--output-format", "json"]


def codex_cmd(model: str, sandbox: str, out_file: Path) -> list[str]:
    exe = shutil.which("codex") or "codex"
    return [exe, "exec", "-m", model, "-s", sandbox, "-C", str(ROOT), "--ephemeral", "--skip-git-repo-check",
            "-o", str(out_file), "-"]


def run_step(cmd: list[str], stdin: str, timeout: int) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, cwd=str(ROOT), env=nested_env())
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as e:
        return 127, "", str(e)


def claude_text(stdout: str) -> str:
    try:
        return str(json.loads(stdout).get("result") or "")
    except ValueError:
        return stdout


def version(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return ((r.stdout or r.stderr).strip().splitlines() or ["?"])[0] if r.returncode == 0 else f"error rc={r.returncode}"
    except (OSError, subprocess.SubprocessError) as e:
        return f"missing ({type(e).__name__})"


def write_meta(run_dir: Path, meta: dict) -> None:
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")


def refuse_if_disabled(cfg: dict, dry: bool) -> int | None:
    if cfg.get("enabled") or dry:
        return None
    print("ORCHESTRATION DISABLED — ორკესტრაცია გამორთულია (orchestration/config.toml: enabled = false; ADR-0005). "
          "ჩართვა მფლობელის გადაწყვეტილებაა (P-001). --dry-run აჩვენებს, რა გაეშვებოდა.")
    return EXIT_DISABLED


# ── status ───────────────────────────────────────────────────────────────────
def cmd_status(_: argparse.Namespace) -> int:
    cfg = load_config()
    a, c = cfg["architecture"], cfg["code"]
    print(f"ORCHESTRATION: {'ENABLED' if cfg.get('enabled') else 'DISABLED'} (orchestration/config.toml; ADR-0005)")
    print(f"architecture: {a['maker_model']} → {a['checker_model']} → {a['synthesis_model']}, "
          f"max {a['max_rounds']} round per topic")
    print(f"code: {c['maker_model']} (this session) → {c['checker_model']}, max {c['max_rounds']} rounds per task")
    print(f"claude CLI: {version([shutil.which('claude') or 'claude', '--version'])}")
    print(f"codex CLI:  {version([shutil.which('codex') or 'codex', '--version'])}")
    print(f"codex login: {version([shutil.which('codex') or 'codex', 'login', 'status'])}")
    recs = records()
    arch = [r for r in recs if r.get("loop") == "arch"]
    code = [r for r in recs if r.get("loop") == "code"]
    print(f"runs: {len(recs)} (architecture {len(arch)}, code {len(code)}) in {RUNS.relative_to(ROOT).as_posix() if RUNS.is_relative_to(ROOT) else RUNS}")
    for r in recs[-5:]:
        print(f"  {r.get('id')}: {r.get('status')} {r.get('verdict') or r.get('position') or ''}".rstrip())
    return 0


# ── architecture loop ─────────────────────────────────────────────────────────
def context_files(extra: list[str]) -> list[Path]:
    files = [ROOT / "intent.md", ROOT / "REVIEW.md"]
    files += sorted((ROOT / "docs" / "domain").glob("*.md"))
    files += sorted((ROOT / "docs" / "adr").glob("ADR-*.md"))
    for e in extra:
        p = (ROOT / e).resolve()
        if not p.is_relative_to(ROOT) or not p.is_file():
            raise ValueError(f"context file not found inside the project: {e}")
        files.append(p)
    return [f for f in files if f.exists()]


def cmd_arch(a: argparse.Namespace) -> int:
    cfg = load_config()
    topic = " ".join((a.topic or "").split())
    if not topic:
        print("--topic is required")
        return EXIT_INPUT
    refused = refuse_if_disabled(cfg, a.dry_run)
    if refused:
        return refused
    arch, cx, cl = cfg["architecture"], cfg["codex"], cfg["claude"]
    key = topic_key(topic)
    done = completed("arch", key)
    if done >= arch["max_rounds"]:
        print(f"ROUND CAP — ამ თემაზე უკვე {done} ციკლი შესრულდა (ლიმიტი {arch['max_rounds']}). "
              "გადაწყვეტს მფლობელი; ახალი კითხვა = ახალი თემა.")
        return EXIT_CAP
    try:
        ctx = context_files(a.context or [])
    except ValueError as e:
        print(str(e))
        return EXIT_INPUT
    ctx_list = "\n".join(f"- {p.relative_to(ROOT).as_posix()}" for p in ctx)
    run_id = f"{dt.date.today().isoformat()}-arch-{slug(topic)}-{key}"
    run_dir = RUNS / run_id
    maker_prompt = fill("architect-maker.md", topic=topic, context_files=ctx_list)
    plan = [("maker", claude_cmd(arch["maker_model"], cl["maker_tools"])),
            ("checker", codex_cmd(arch["checker_model"], cx["sandbox"], run_dir / "checker.md")),
            ("synthesis", claude_cmd(arch["synthesis_model"], cl["maker_tools"]))]
    if a.dry_run:
        print(f"DRY-RUN arch — run id {run_id} (nothing is called, nothing is written)")
        for name, cmd in plan:
            print(f"  {name}: {' '.join(cmd)}")
        print(f"  maker prompt: {len(maker_prompt)} chars; context files:\n{ctx_list}")
        return 0
    run_dir.mkdir(parents=True, exist_ok=True)
    meta = {"id": run_id, "loop": "arch", "key": key, "topic": topic, "status": "running", "started": now(),
            "models": {"maker": arch["maker_model"], "checker": arch["checker_model"], "synthesis": arch["synthesis_model"]}}
    write_meta(run_dir, meta)
    (run_dir / "maker.prompt.md").write_text(maker_prompt, encoding="utf-8")
    rc, out, err = run_step(plan[0][1], maker_prompt, cl["timeout_s"])
    proposal = claude_text(out)
    (run_dir / "maker.md").write_text(proposal, encoding="utf-8")
    if rc != 0 or not proposal.strip():
        return fail(run_dir, meta, "maker", rc, err)
    checker_prompt = fill("architect-checker.md", topic=topic, context_files=ctx_list, proposal=proposal)
    (run_dir / "checker.prompt.md").write_text(checker_prompt, encoding="utf-8")
    rc, out, err = run_step(plan[1][1], checker_prompt, cx["timeout_s"])
    audit_file = run_dir / "checker.md"
    audit = audit_file.read_text(encoding="utf-8") if audit_file.exists() else out
    audit_file.write_text(audit, encoding="utf-8")
    if rc != 0 or not audit.strip():
        return fail(run_dir, meta, "checker", rc, err)
    synth_prompt = fill("architect-synthesis.md", topic=topic, proposal=proposal, audit=audit)
    (run_dir / "synthesis.prompt.md").write_text(synth_prompt, encoding="utf-8")
    rc, out, err = run_step(plan[2][1], synth_prompt, cl["timeout_s"])
    synthesis = claude_text(out)
    (run_dir / "synthesis.md").write_text(synthesis, encoding="utf-8")
    if rc != 0 or not synthesis.strip():
        return fail(run_dir, meta, "synthesis", rc, err)
    m = re.search(r"POSITION:\s*([a-z-]+)", audit)
    meta.update(status="complete", finished=now(), position=m.group(1) if m else "unstated")
    write_meta(run_dir, meta)
    print(f"✅ architecture loop complete: {run_dir.relative_to(ROOT).as_posix()}/ "
          f"(checker position: {meta['position']}). Next: turn synthesis.md into an ADR with /adr; "
          "the owner decides with /approve.")
    return 0


def fail(run_dir: Path, meta: dict, step: str, rc: int, err: str) -> int:
    meta.update(status="failed", failed_step=step, rc=rc, error=(err or "").strip()[-500:], finished=now())
    write_meta(run_dir, meta)
    print(f"❌ {step} failed (rc={rc}): {(err or '').strip()[-300:]}\n   record: {run_dir.relative_to(ROOT).as_posix()}/meta.json "
          "(failed runs do not use up a round)")
    return EXIT_FAIL


# ── code loop (checker step) ──────────────────────────────────────────────────
def git_out(*args: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.stdout if r.returncode == 0 else ""


def cmd_code_check(a: argparse.Namespace) -> int:
    import context_graph as cg
    cfg = load_config()
    refused = refuse_if_disabled(cfg, a.dry_run)
    if refused:
        return refused
    code, cx = cfg["code"], cfg["codex"]
    g = cg.load(ROOT)
    plan_id = a.plan.upper()
    plan = next((n for n in g.nodes.values() if n.type == "plan" and n.id == plan_id), None)
    if not plan:
        print(f"{plan_id} not found in docs/plans/")
        return EXIT_INPUT
    if plan.status not in ("approved", "in-progress"):
        print(f"{plan_id} is {plan.status} — the checker runs only on an approved / in-progress plan")
        return EXIT_INPUT
    plan_text = (ROOT / plan.path).read_text(encoding="utf-8")
    task_line = next((ln for ln in plan_text.splitlines() if re.search(rf"\b{re.escape(a.task)}\b", ln)), "")
    if not task_line:
        print(f"task {a.task} not found in {plan.path}")
        return EXIT_INPUT
    key = f"{plan_id}-{a.task}"
    done = completed("code", key)
    if done >= code["max_rounds"]:
        print(f"ROUND CAP — {key}: უკვე {done} შემოწმება (ლიმიტი {code['max_rounds']}). "
              "მესამე ბრუნი არ არის: ღია critical/high შენიშვნებზე გადაწყვეტს მფლობელი (UNVERIFIED).")
        return EXIT_CAP
    diff = git_out("diff", f"{a.base}...HEAD") + git_out("diff", "HEAD")
    if not diff.strip():
        print(f"nothing to review: no diff against {a.base} and no uncommitted change")
        return EXIT_INPUT
    truncated = len(diff) > code["max_diff_chars"]
    diff = diff[: code["max_diff_chars"]] + ("\n…(diff truncated)…\n" if truncated else "")
    specs = [g.nodes[ln.resolved] for ln in plan.links if ln.kind == "spec" and ln.resolved in g.nodes]
    spec_text = (ROOT / specs[0].path).read_text(encoding="utf-8") if specs else "(plan has no resolvable spec link)"
    review_path = ROOT / "REVIEW.md"
    if not review_path.exists():
        print("REVIEW.md is missing — the checker has no review contract; restore it first")
        return EXIT_INPUT
    rnd = done + 1
    prompt = fill("code-checker.md", round=str(rnd), max_rounds=str(code["max_rounds"]), plan_id=plan_id,
                  task=a.task, task_text=task_line.strip(), spec_text=spec_text,
                  review_md=review_path.read_text(encoding="utf-8"), diff=diff)
    run_id = f"{dt.date.today().isoformat()}-code-{plan_id.lower()}-{a.task.lower()}-r{rnd}"
    run_dir = RUNS / run_id
    cmd = codex_cmd(code["checker_model"], cx["sandbox"], run_dir / "review.md")
    if a.dry_run:
        print(f"DRY-RUN code-check — {key}, round {rnd}/{code['max_rounds']} (nothing is called, nothing is written)")
        print(f"  checker: {' '.join(cmd)}")
        print(f"  prompt: {len(prompt)} chars; diff {len(diff)} chars{' (truncated)' if truncated else ''}")
        return 0
    run_dir.mkdir(parents=True, exist_ok=True)
    meta = {"id": run_id, "loop": "code", "key": key, "round": rnd, "status": "running", "started": now(),
            "models": {"maker": code["maker_model"], "checker": code["checker_model"]}}
    write_meta(run_dir, meta)
    (run_dir / "review.prompt.md").write_text(prompt, encoding="utf-8")
    rc, out, err = run_step(cmd, prompt, cx["timeout_s"])
    review_file = run_dir / "review.md"
    review = review_file.read_text(encoding="utf-8") if review_file.exists() else out
    review_file.write_text(review, encoding="utf-8")
    if rc != 0 or not review.strip():
        return fail(run_dir, meta, "checker", rc, err)
    m = re.search(r"VERDICT:\s*([a-z-]+)", review)
    verdict = m.group(1) if m else "unstated"
    meta.update(status="complete", finished=now(), verdict=verdict)
    write_meta(run_dir, meta)
    print(f"checker verdict: {verdict} — {run_dir.relative_to(ROOT).as_posix()}/review.md (round {rnd}/{code['max_rounds']})")
    if verdict != "approve" and rnd >= code["max_rounds"]:
        print("round cap reached — do not start a third round; report open critical/high findings to the owner as UNVERIFIED")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="maker–checker orchestration (ADR-0005)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p = sub.add_parser("arch")
    p.add_argument("--topic", required=True)
    p.add_argument("--context", nargs="*")
    p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("code-check")
    p.add_argument("--plan", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--base", default="main")
    p.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    return {"status": cmd_status, "arch": cmd_arch, "code-check": cmd_code_check}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
