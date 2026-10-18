#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Maker–checker orchestration runner (ADR-0005). Dormant until config.toml has enabled = true.

  bash .claude/hooks/py.sh orchestration/run.py status
  bash .claude/hooks/py.sh orchestration/run.py arch --topic "<question>" [--context FILE ...] [--dry-run]
  bash .claude/hooks/py.sh orchestration/run.py code-check --plan PLAN-0001 --task T3 [--base main] [--dry-run]

Two stages (config.toml `stage`). Stage 1 runs Claude models only. Architecture loop (1 round
per topic): Opus writes a proposal -> Sonnet audits it and states its own position -> Opus writes
the final synthesis with an ADR draft (proposed). Code loop (max 2 rounds per task): the
interactive session (Sonnet) writes the code; Opus reviews the diff against the spec and
REVIEW.md and returns a VERDICT. Stage 2 is the owner's decision and may name other providers,
e.g. a ChatGPT checker through `codex exec -s read-only` (ChatGPT login, no API key).

Every model is written provider:model. Each Claude step runs `claude -p --restricted` with
read-only tools, a per-call budget, the project's Read deny rules passed in again through
--settings (restricted mode ignores the project's own settings) together with the same kinds of
secret file at every folder depth, and an environment without other services' keys
(tools/claude_cli.py); restricted mode itself keeps the file tools inside the working folder (measured
2026-10-18: a path outside it and a link out of it were both refused). A secret file never enters a
prompt: --context refuses one, and the reviewed diff leaves them out — the kinds come from one table,
SECRET_KINDS, the same one the nested calls' deny rules are made from. Text from outside run.py — the topic, the plan, the diff, a
model's answer — goes into the next prompt between two markers that carry a random word chosen
for that prompt, so it cannot pose as instructions. Prompts and answers pass through
tools/redact.py. Every run gets a folder of its own, orchestration/runs/<id>/ (prompts, answers,
meta.json with the stage, the models and each step's cost). The round caps are counted from
those records, so they hold across sessions; a failed run — a checker that did not end with its
VERDICT / POSITION line included — uses no round and keeps its record. A failed step is reported in
run.py's own words; the step's error output, which can carry text from the diff or from a file the
model read, goes to meta.json only (redacted).

Exit: 0 ok · 1 a step failed (or GIT ERROR, RUNS) · 3 disabled · 4 round cap reached · 5 bad input or
configuration, every message starting with its marker: CONFIG, STAGE GATE, MODEL SPEC, TOOLS,
BUDGET CONFIG, LIMITS, SANDBOX, DENY RULES, TEMPLATE, ORCH_CLAUDE_CMD, TOPIC, CONTEXT, PLAN,
BAD TASK, BAD BASE, NO DIFF, REVIEW CONTRACT. A dry run calls no model and writes nothing.

Environment, for tests and the drill: ORCH_ROOT the project · ORCH_CONFIG config.toml ·
ORCH_RUNS the run records · ORCH_SETTINGS the settings.json whose Read deny rules are passed on ·
ORCH_PROMPTS the prompt templates · ORCH_CLAUDE_CMD a JSON list that replaces the claude command.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"  # Windows: never a git / codex / claude from the current folder

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("ORCH_ROOT") or HERE.parent).resolve()
CONFIG = Path(os.environ.get("ORCH_CONFIG") or HERE / "config.toml")
RUNS = Path(os.environ.get("ORCH_RUNS") or HERE / "runs")
PROMPTS = Path(os.environ.get("ORCH_PROMPTS") or HERE / "prompts")
SETTINGS = Path(os.environ.get("ORCH_SETTINGS") or HERE.parent / ".claude" / "settings.json")  # the engine's own rules
sys.path.insert(0, str(HERE.parent / "tools"))
import context_graph as cg  # noqa: E402
from claude_cli import find_claude, nested_env  # noqa: E402
from redact import redact  # noqa: E402

EXIT_FAIL, EXIT_DISABLED, EXIT_CAP, EXIT_INPUT = 1, 3, 4, 5
PROVIDERS = ("claude", "codex")
ROLES = (("architecture", "maker_model"), ("architecture", "checker_model"), ("architecture", "synthesis_model"),
         ("code", "maker_model"), ("code", "checker_model"), ("routine", "model"))
READ_ONLY_TOOLS = {"Read", "Grep", "Glob"}
SPEC_RE = re.compile(r"([a-z]+):([A-Za-z0-9][A-Za-z0-9._~/-]*)")
TASK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
BASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/~^-]{0,99}")
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}")
VERDICTS = ("approve", "changes-requested", "blocked")
POSITIONS = ("agree", "agree-with-changes", "disagree")
STATUSES = ("running", "complete", "failed")
TEMPLATES = {  # every template and the values run.py fills into it — checked before a loop starts
    "architect-maker.md": {"nonce", "topic", "context_files"},
    "architect-checker.md": {"nonce", "topic", "context_files", "proposal"},
    "architect-synthesis.md": {"nonce", "topic", "proposal", "audit"},
    "code-checker.md": {"nonce", "round", "max_rounds", "plan_id", "task", "task_text", "spec_text", "review_md", "diff"},
}
SECRET_KINDS = (  # the kinds of secret file, at every folder depth: the one table both walls below are made from
    "**/.env", "**/.env.*", "**/.envrc", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/id_rsa*",
    "**/id_ed25519*", "**/id_ecdsa*", "**/credentials*.json", "**/serviceAccountKey*.json", "**/secrets/**",
    "**/.ssh/**", "**/.aws/**")
NESTED_DENY = [f"Read({p})" for p in SECRET_KINDS]  # for every nested Claude call; .env.example falls under .env.*
DENY_PROBLEM = ("DENY RULES — no Read deny rules in .claude/settings.json; a nested Claude call would see the secret "
                "files")
SUBTYPE_RE = re.compile(r"[a-z_]{1,40}")  # claude's own error kind, e.g. error_max_budget_usd — the only part shown


class Refused(Exception):
    """A stop before anything runs: the message starts with its marker and is printed; rc is the exit code."""

    def __init__(self, message: str, rc: int = EXIT_INPUT) -> None:
        super().__init__(message)
        self.rc = rc


class ConfigError(Refused):
    pass


class GitError(RuntimeError):
    pass


class StepFailed(Exception):
    """A step without a usable answer. The message is run.py's own words, never the step's output."""

    def __init__(self, step: str, rc: int, why: str) -> None:
        super().__init__(why)
        self.step, self.rc = step, rc


def load_config() -> dict:
    try:
        return tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"CONFIG — cannot read {shown(CONFIG)}: {e}") from None


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def shown(path: Path) -> str:
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


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
            rec = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def completed(loop: str, key: str) -> int:
    return sum(1 for r in records() if r.get("loop") == loop and r.get("key") == key and r.get("status") == "complete")


def is_secret_path(rel: str) -> bool:
    """A file that never goes into a prompt: one of SECRET_KINDS, read the way the deny rules read them (`**/` any
    folder, `/**` anything inside that folder), ignoring case. A nested call cannot read .env.example either (.env.*),
    so it is not offered as context or shown in a diff."""
    parts = PurePosixPath(rel.replace("\\", "/").lower()).parts
    for kind in (k.removeprefix("**/").lower() for k in SECRET_KINDS):
        if kind.endswith("/**") and kind[:-3] in parts[:-1]:
            return True
        if not kind.endswith("/**") and parts and fnmatch.fnmatchcase(parts[-1], kind):
            return True
    return False


def program(name: str) -> str:
    """A program's full path from PATH. A bare name would let Windows look in the current folder first."""
    found = shutil.which(name)
    if not found:
        raise FileNotFoundError(f"{name} not found on PATH")
    return found


# ── prompts ───────────────────────────────────────────────────────────────────
def template_text(name: str) -> str:
    try:
        return (PROMPTS / name).read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"TEMPLATE — cannot read {name}: {e.strerror or e}") from None


def check_templates(*names: str) -> None:
    """Every template a loop will fill, checked before anything runs: a broken one must not waste a model call."""
    for name in names:
        wanted = set(re.findall(r"\{([a-z_]+)\}", template_text(name)))
        if wanted != TEMPLATES[name]:
            raise ConfigError(f"TEMPLATE — {name} expects {sorted(wanted)}, run.py fills {sorted(TEMPLATES[name])}")


def fill(name: str, data: dict[str, str], **plain: str) -> str:
    """One pass, so a value that itself contains `{proposal}` or `{diff}` is never expanded again. Every value in
    `data` comes from outside run.py and goes in between two markers carrying a random word chosen for this prompt:
    its text was written without knowing the word, so it cannot close its block and pose as instructions."""
    check_templates(name)
    nonce = secrets.token_hex(6)
    while any(nonce in v for v in data.values()):
        nonce = secrets.token_hex(6)
    values = {**plain, "nonce": nonce}
    values.update({k: f"<<<DATA {nonce}\n{v.strip()}\nDATA {nonce}>>>" for k, v in data.items()})
    return re.sub(r"\{([a-z_]+)\}", lambda m: values[m.group(1)], template_text(name))


# ── configuration ─────────────────────────────────────────────────────────────
def parse_spec(spec: object) -> tuple[str, str]:
    m = SPEC_RE.fullmatch(spec) if isinstance(spec, str) else None
    if not m or m.group(1) not in PROVIDERS:
        raise ConfigError(f"MODEL SPEC — {spec!r} is not provider:model with a known provider ({', '.join(PROVIDERS)})")
    return m.group(1), m.group(2)


def limit_problem(cfg: dict, section: str, key: str) -> str | None:
    value = (cfg.get(section) or {}).get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"LIMITS — [{section}] {key} must be a whole number of 1 or more, config.toml has {value!r}"
    return None


def check_config(cfg: dict) -> list[str]:
    problems = []
    stage = cfg.get("stage")
    if stage not in (1, 2) or isinstance(stage, bool):
        problems.append(f"STAGE GATE — stage must be 1 or 2, config.toml has {stage!r}")
    providers = set()
    for section, key in ROLES:
        spec = (cfg.get(section) or {}).get(key)
        try:
            provider, _ = parse_spec(spec)
        except ConfigError as e:
            problems.append(f"{e} ([{section}] {key})")
            continue
        providers.add(provider)
        if stage == 1 and provider != "claude":
            problems.append(f"STAGE GATE — stage 1 runs Claude models only, but [{section}] {key} = {spec!r}; "
                            "stage 2 is the owner's decision (ADR-0005)")
    cl = cfg.get("claude") or {}
    tools = {t.strip() for t in str(cl.get("tools", "")).split(",") if t.strip()}
    if not tools or not tools <= READ_ONLY_TOOLS:
        problems.append(f"TOOLS — [claude] tools must be read-only (a subset of {', '.join(sorted(READ_ONLY_TOOLS))}), "
                        f"config.toml has {cl.get('tools')!r}")
    budget = cl.get("max_budget_usd")
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not 0 < budget < float("inf"):
        problems.append(f"BUDGET CONFIG — [claude] max_budget_usd must be a positive number, config.toml has {budget!r}")
    limits = [("architecture", "max_rounds"), ("code", "max_rounds"), ("code", "max_diff_chars"), ("claude", "timeout_s")]
    if "codex" in providers:
        limits.append(("codex", "timeout_s"))
        if (cfg.get("codex") or {}).get("sandbox") != "read-only":
            problems.append(f"SANDBOX — [codex] sandbox must be \"read-only\" (the checker writes nothing), config.toml has "
                            f"{(cfg.get('codex') or {}).get('sandbox')!r}")
    problems += [p for p in (limit_problem(cfg, s, k) for s, k in limits) if p]
    return problems


def deny_rules() -> list[str]:
    """The Read deny rules every nested Claude call gets through --settings (restricted mode ignores the project's own
    settings): the project's rules, then the same kinds of secret file at every folder depth. Empty when the project
    has none — then something is wrong, and nothing runs."""
    try:
        deny = json.loads(SETTINGS.read_text(encoding="utf-8"))["permissions"]["deny"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    own = [r for r in deny if isinstance(r, str) and r.startswith("Read(")] if isinstance(deny, list) else []
    return own + [r for r in NESTED_DENY if r not in own] if own else []


def preflight(cfg: dict, dry: bool, *templates: str) -> list[str]:
    """What must hold before a loop starts, dry run included (except the switch): a sound config.toml, the templates
    the loop fills, and the deny rules for its nested calls — which it returns."""
    problems = check_config(cfg)
    if problems:
        raise ConfigError("\n".join(problems))
    if not cfg.get("enabled") and not dry:
        raise Refused("ORCHESTRATION DISABLED — ორკესტრაცია გამორთულია (orchestration/config.toml: enabled = false; "
                      "ADR-0005). ჩართვა მფლობელის გადაწყვეტილებაა (P-001). --dry-run აჩვენებს, რა გაეშვებოდა.", EXIT_DISABLED)
    check_templates(*templates)
    deny = deny_rules()
    if not deny:
        raise ConfigError(DENY_PROBLEM)
    return deny


# ── running one step ──────────────────────────────────────────────────────────
def claude_command() -> list[str]:
    """ORCH_CLAUDE_CMD (the drill's stand-in) or the real `claude` (tools/claude_cli.py)."""
    override = os.environ.get("ORCH_CLAUDE_CMD")
    if not override:
        return find_claude()
    try:
        cmd = json.loads(override)
    except ValueError:
        cmd = None
    if not (isinstance(cmd, list) and cmd and all(isinstance(x, str) and x for x in cmd)):
        raise ConfigError("ORCH_CLAUDE_CMD — must be a JSON list of strings")
    return cmd


@dataclass
class Step:
    name: str
    spec: str
    provider: str
    cmd: list[str]
    timeout: int
    out_file: Path | None = None
    info: dict = field(default_factory=dict)


def plan_step(name: str, spec: str, cfg: dict, run_dir: Path, stem: str) -> Step:
    provider, model = parse_spec(spec)
    if provider == "claude":
        cl = cfg["claude"]
        cmd = [*claude_command(), "-p", "Follow the task given on stdin exactly.", "--model", model, "--restricted",
               "--strict-mcp-config", "--tools", cl["tools"], "--no-session-persistence", "--output-format", "json",
               "--max-budget-usd", str(cl["max_budget_usd"]), "--settings", str(run_dir / "nested-settings.json")]
        return Step(name, spec, provider, cmd, cl["timeout_s"])
    cx = cfg["codex"]
    out_file = run_dir / f"{stem}.md"
    cmd = [shutil.which("codex") or "codex", "exec", "-m", model, "-s", cx["sandbox"], "-C", str(ROOT), "--ephemeral",
           "--skip-git-repo-check", "-o", str(out_file), "-"]
    return Step(name, spec, provider, cmd, cx["timeout_s"], out_file)


def dry_run_line(step: Step, deny: list[str]) -> str:
    text = " ".join(shlex.quote(c) for c in step.cmd)
    if step.provider == "claude":
        text += f"   # --settings: {len(deny)} Read deny rules (.claude/settings.json + every folder depth)"
    return f"  {step.name} ({step.spec}): {text}"


def run_step(cmd: list[str], stdin: str, timeout: int) -> tuple[int, str, str, str]:
    """(rc, stdout, stderr, why): `why` is run.py's own words when the program did not run to its end."""
    try:
        exe = cmd[0] if Path(cmd[0]).is_absolute() else program(cmd[0])
        r = subprocess.run([exe, *cmd[1:]], input=stdin, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, cwd=str(ROOT), env=nested_env())
        return r.returncode, r.stdout, r.stderr, ""
    except subprocess.TimeoutExpired:
        return 124, "", "", f"timeout after {timeout}s"
    except OSError as e:
        return 127, "", str(e), f"{Path(cmd[0]).name} could not start ({type(e).__name__})"


def claude_result(stdout: str) -> dict:
    """`claude -p --output-format json`: the answer plus what the call cost."""
    try:
        body = json.loads(stdout)
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return {"text": "", "is_error": True, "subtype": "unreadable output"}
    return {"text": str(body.get("result") or ""), "cost_usd": body.get("total_cost_usd"), "num_turns": body.get("num_turns"),
            "duration_ms": body.get("duration_ms"), "is_error": bool(body.get("is_error")), "subtype": body.get("subtype")}


def execute(step: Step, prompt: str) -> tuple[str, int, str, str]:
    """(answer, rc, why, stderr). `why` is empty when the step gave an answer; otherwise it is run.py's own words,
    because the step's own error output can carry text from the diff or a file the model read."""
    rc, out, err, why = run_step(step.cmd, prompt, step.timeout)
    if step.provider == "claude":
        res = claude_result(out)
        text = res.pop("text")
        step.info = res
        if not why and res["is_error"]:
            subtype = str(res.get("subtype") or "")
            why = f"claude reported an error ({subtype if SUBTYPE_RE.fullmatch(subtype) else 'of an unknown kind'})"
    else:
        text = step.out_file.read_text(encoding="utf-8") if step.out_file and step.out_file.exists() else out
    if not why and rc != 0:
        why = f"{step.provider} exited with {rc}"
    if not why and not text.strip():
        why = "the model returned no text"
    return text, rc, why, err


def save(path: Path, text: str, meta: dict) -> None:
    clean, kinds = redact(text)
    if kinds:
        meta.setdefault("redacted", []).extend(k for k in kinds if k not in meta.get("redacted", []))
    path.write_text(clean, encoding="utf-8", newline="\n")


def write_meta(run_dir: Path, meta: dict) -> None:
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")


def run_name(base: str, stamp: str, n: int = 1) -> str:
    """A run's folder name: what it is, then the time it started (HHMMSS), then -2, -3 … for a run in the same second."""
    return f"{base}-{stamp}" if n == 1 else f"{base}-{stamp}-{n}"


def time_stamp() -> str:
    return dt.datetime.now().strftime("%H%M%S")


def new_run(base: str) -> tuple[str, Path]:
    """A folder of its own for every run: a retry never writes over the record of the run that failed."""
    stamp = time_stamp()
    for n in range(1, 100):
        run_id = run_name(base, stamp, n)
        try:
            (RUNS / run_id).mkdir(parents=True)
            return run_id, RUNS / run_id
        except FileExistsError:
            continue
    raise Refused(f"RUNS — no free run folder for {base} in {shown(RUNS)}", EXIT_FAIL)


def start_run(run_dir: Path, meta: dict, deny: list[str]) -> None:
    (run_dir / "nested-settings.json").write_text(json.dumps({"permissions": {"deny": deny}}, indent=1),
                                                  encoding="utf-8", newline="\n")
    write_meta(run_dir, meta)


def run_recorded(step: Step, prompt: str, run_dir: Path, meta: dict, stem: str) -> str:
    """One step with its record: the prompt before the call, then the step's cost and the (redacted) answer — a failed
    step's too, and then its own error output, redacted, in meta.json. Without an answer it raises StepFailed."""
    save(run_dir / f"{stem}.prompt.md", prompt, meta)
    text, rc, why, err = execute(step, prompt)
    meta.setdefault("steps", {})[step.name] = {"model": step.spec, **step.info}
    save(run_dir / f"{stem}.md", text, meta)
    if why:
        if err.strip():
            meta["stderr"] = redact(err)[0].strip()[-500:]
        raise StepFailed(step.name, rc, why)
    return text


def final_label(text: str, label: str, allowed: tuple[str, ...]) -> str:
    """The checker's answer is its last non-empty line, exactly `LABEL: value`; anything else is `unstated`."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "unstated"
    last = lines[-1].replace("*", "").replace("`", "").strip().rstrip(".")
    m = re.fullmatch(rf"{label}:\s*([A-Za-z-]+)", last)
    value = m.group(1).lower() if m else ""
    return value if value in allowed else "unstated"


def fail(run_dir: Path, meta: dict, e: StepFailed) -> int:
    meta.update(status="failed", failed_step=e.step, rc=e.rc, error=str(e), finished=now())
    write_meta(run_dir, meta)
    print(f"❌ {e.step} failed (rc={e.rc}): {e}\n   record: {shown(run_dir)}/meta.json — the step's own error output, "
          "redacted, is there; a failed run does not use up a round")
    return EXIT_FAIL


def version(cmd: list[str]) -> str:
    try:
        exe = cmd[0] if Path(cmd[0]).is_absolute() else program(cmd[0])
        r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        return ((r.stdout or r.stderr).strip().splitlines() or ["?"])[0] if r.returncode == 0 else f"error rc={r.returncode}"
    except (OSError, subprocess.SubprocessError) as e:
        return f"missing ({type(e).__name__})"


# ── status ───────────────────────────────────────────────────────────────────
def record_line(rec: dict) -> str:
    """A record is a file anyone could have put in runs/, so only checked values are printed."""
    rid = rec.get("id") if isinstance(rec.get("id"), str) and RUN_ID_RE.fullmatch(rec["id"]) else "?"
    status = rec.get("status") if rec.get("status") in STATUSES else "?"
    label = rec.get("verdict") if rec.get("verdict") in VERDICTS else rec.get("position") if rec.get("position") in POSITIONS else ""
    return f"  {rid}: {status} {label}".rstrip()


def cmd_status(_: argparse.Namespace) -> int:
    cfg = load_config()
    a, c, r, cl = cfg.get("architecture", {}), cfg.get("code", {}), cfg.get("routine", {}), cfg.get("claude", {})
    stage = cfg.get("stage")
    print(f"ORCHESTRATION: {'ENABLED' if cfg.get('enabled') else 'DISABLED'} · stage {stage} (orchestration/config.toml; ADR-0005)")
    print(f"architecture: maker {a.get('maker_model')} → checker {a.get('checker_model')} → synthesis {a.get('synthesis_model')}, "
          f"max {a.get('max_rounds')} round per topic")
    print(f"code: maker {c.get('maker_model')} (this session) → checker {c.get('checker_model')}, max {c.get('max_rounds')} rounds per task")
    print(f"routine: {r.get('model')} (subagents; deterministic gates check the result)")
    print(f"claude steps: tools {cl.get('tools')} · budget ${cl.get('max_budget_usd')} per call · timeout {cl.get('timeout_s')} s")
    claude = claude_command()
    print(f"claude CLI: {version([*claude, '--version'])} ({' '.join(claude)})")
    specs = [str((cfg.get(s) or {}).get(k, "")) for s, k in ROLES]
    if (isinstance(stage, int) and stage >= 2) or any(s.startswith("codex:") for s in specs):
        print(f"codex CLI:  {version(['codex', '--version'])}")
        print(f"codex login: {version(['codex', 'login', 'status'])}")
    if (HERE / "decide.py").exists():  # the public kit ships without the dispatcher: there is nothing to report there
        d = cfg.get("decision") or {}
        print(f"dispatcher: {'ENABLED' if d.get('enabled') else 'DISABLED'} ({d.get('provider')}; ADR-0009) — "
              "details: bash .claude/hooks/py.sh orchestration/decide.py status")
    recs = records()
    arch = [x for x in recs if x.get("loop") == "arch"]
    code = [x for x in recs if x.get("loop") == "code"]
    print(f"runs: {len(recs)} (architecture {len(arch)}, code {len(code)}) in {shown(RUNS)}")
    for x in recs[-5:]:
        print(record_line(x))
    problems = check_config(cfg)
    if not deny_rules():
        problems.append(DENY_PROBLEM)
    try:
        check_templates(*TEMPLATES)
    except ConfigError as e:
        problems.append(str(e))
    for p in problems:
        print(f"CONFIG PROBLEM: {p}")
    return EXIT_INPUT if problems else 0


# ── architecture loop ─────────────────────────────────────────────────────────
def context_files(extra: list[str]) -> list[Path]:
    files = [ROOT / "intent.md", ROOT / "REVIEW.md"]
    files += sorted((ROOT / "docs" / "domain").glob("*.md"))
    files += sorted((ROOT / "docs" / "adr").glob("ADR-*.md"))
    for e in extra:
        p = (ROOT / e).resolve()
        if not p.is_relative_to(ROOT) or not p.is_file():
            raise Refused(f"CONTEXT — not a file inside the project: {e}")
        if is_secret_path(p.relative_to(ROOT).as_posix()):
            raise Refused(f"CONTEXT — {p.relative_to(ROOT).as_posix()} is a secret file; it never goes into a prompt")
        files.append(p)
    return [f for f in files if f.exists()]


def cmd_arch(a: argparse.Namespace) -> int:
    topic = redact(" ".join((a.topic or "").split()))[0]
    if not topic:
        raise Refused("TOPIC — --topic needs the question to decide")
    cfg = load_config()
    deny = preflight(cfg, a.dry_run, "architect-maker.md", "architect-checker.md", "architect-synthesis.md")
    arch = cfg["architecture"]
    key = topic_key(topic)
    done = completed("arch", key)
    if done >= arch["max_rounds"]:
        raise Refused(f"ROUND CAP — ამ თემაზე უკვე {done} ციკლი შესრულდა (ლიმიტი {arch['max_rounds']}). "
                      "გადაწყვეტს მფლობელი; ახალი კითხვა = ახალი თემა.", EXIT_CAP)
    ctx_list = "\n".join(f"- {p.relative_to(ROOT).as_posix()}" for p in context_files(a.context or []))
    base = f"{dt.date.today().isoformat()}-arch-{slug(topic)}-{key}"
    maker_prompt = redact(fill("architect-maker.md", {"topic": topic, "context_files": ctx_list}))[0]
    if a.dry_run:
        run_dir = RUNS / run_name(base, time_stamp())
        print(f"DRY-RUN arch — run id {run_dir.name}, stage {cfg['stage']} (nothing is called, nothing is written)")
        for name, stem in (("maker", "maker"), ("checker", "checker"), ("synthesis", "synthesis")):
            print(dry_run_line(plan_step(name, arch[f"{name}_model"], cfg, run_dir, stem), deny))
        print(f"  maker prompt: {len(maker_prompt)} chars; context files:\n{ctx_list}")
        return 0
    run_id, run_dir = new_run(base)
    maker, checker, synth = (plan_step(n, arch[f"{n}_model"], cfg, run_dir, n) for n in ("maker", "checker", "synthesis"))
    meta = {"id": run_id, "loop": "arch", "key": key, "topic": topic, "stage": cfg["stage"], "status": "running",
            "started": now(), "models": {s.name: s.spec for s in (maker, checker, synth)}}
    start_run(run_dir, meta, deny)
    try:
        proposal = run_recorded(maker, maker_prompt, run_dir, meta, "maker")
        checker_prompt = redact(fill("architect-checker.md", {"topic": topic, "context_files": ctx_list,
                                                              "proposal": proposal}))[0]
        audit = run_recorded(checker, checker_prompt, run_dir, meta, "checker")
        position = final_label(audit, "POSITION", POSITIONS)
        if position == "unstated":
            raise StepFailed("checker", 0, "the audit does not end with a line `POSITION: agree | agree-with-changes | disagree`")
        synth_prompt = redact(fill("architect-synthesis.md", {"topic": topic, "proposal": proposal, "audit": audit}))[0]
        run_recorded(synth, synth_prompt, run_dir, meta, "synthesis")
    except StepFailed as e:
        return fail(run_dir, meta, e)
    meta.update(status="complete", finished=now(), position=position)
    write_meta(run_dir, meta)
    print(f"✅ architecture loop complete: {shown(run_dir)}/ (checker position: {position}). "
          "Next: turn synthesis.md into an ADR with /adr; the owner decides with /approve.")
    return 0


# ── code loop (checker step) ──────────────────────────────────────────────────
def git_out(*args: str) -> str:
    r = subprocess.run([program("git"), "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])} failed (rc={r.returncode}): {(r.stderr or '').strip()[-200:]}")
    return r.stdout


def reviewed_diff(base: str) -> tuple[str, list[str]]:
    """The task's change — committed since `base`, plus what is staged or changed in tracked files (a new file counts
    once it is `git add`ed) — without secret files: their names are returned, their content never read. No rename
    detection: a secret file renamed to an ordinary name shows as its own deletion, so its old lines stay out too."""
    ranges = ([f"{base}...HEAD"], ["HEAD"])
    names = {n for r in ranges for n in git_out("diff", "--no-renames", "--name-only", "-z", *r, "--").split("\0") if n}
    left_out = sorted(n for n in names if is_secret_path(n))
    paths = ["--", ".", *(f":(top,exclude,literal){n}" for n in left_out)]
    diff = "".join(git_out("diff", "--no-renames", "--no-ext-diff", "--no-textconv", *r, *paths) for r in ranges)
    return diff, left_out


def find_task(g: cg.Graph, plan_id: str, task: str) -> tuple[cg.Node, str]:
    """The plan — approved or in progress — and the task's own item in it, `- [ ] T3 …` (never T30 or T3.1)."""
    plan = next((n for n in g.nodes.values() if n.type == "plan" and n.id == plan_id), None)
    if not plan:
        raise Refused(f"PLAN — {plan_id!r} not found in docs/plans/")
    if plan.status not in ("approved", "in-progress"):
        raise Refused(f"PLAN — {plan_id} is {plan.status}; the checker runs only on an approved / in-progress plan")
    item = re.compile(rf"\s*[-*]\s*\[[ xX]\]\s*{re.escape(task)}(?![A-Za-z0-9._-])")
    line = next((ln for ln in (ROOT / plan.path).read_text(encoding="utf-8").splitlines() if item.match(ln)), "")
    if not line:
        raise Refused(f"BAD TASK — no task item `- [ ] {task} …` in {plan.path}")
    return plan, line.strip()


def review_input(base: str, limit: int) -> tuple[str, list[str], bool]:
    """The diff the checker reads: secret files left out (their names said at its end), cut at `limit` characters."""
    try:
        if subprocess.run([program("git"), "-C", str(ROOT), "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
                          capture_output=True).returncode != 0:
            raise Refused(f"BAD BASE — {base!r} is not a commit in this repository")
        diff, left_out = reviewed_diff(base)
    except (GitError, OSError) as e:
        raise Refused(f"GIT ERROR — {e}", EXIT_FAIL) from None
    if not diff.strip():
        raise Refused(f"NO DIFF — nothing to review: no change against {base}, nothing staged or changed in tracked files"
                      + (f" (secret files left out: {len(left_out)})" if left_out else ""))
    truncated = len(diff) > limit
    diff = diff[:limit] + ("\n…(diff truncated)…\n" if truncated else "")
    if left_out:
        diff += f"\n(left out of this diff — secret files, never shown: {', '.join(left_out)})\n"
    return diff, left_out, truncated


def cmd_code_check(a: argparse.Namespace) -> int:
    if not TASK_RE.fullmatch(a.task or ""):
        raise Refused(f"BAD TASK — {a.task!r}: a task id is letters, digits, '.', '_' or '-', up to 32 characters (e.g. T3)")
    if not BASE_RE.fullmatch(a.base or ""):
        raise Refused(f"BAD BASE — {a.base!r} is not a branch, tag or commit name")
    cfg = load_config()
    deny = preflight(cfg, a.dry_run, "code-checker.md")
    code = cfg["code"]
    g = cg.load(ROOT)
    plan_id = a.plan.upper()
    plan, task_line = find_task(g, plan_id, a.task)
    key = f"{plan_id}-{a.task}"
    done = completed("code", key)
    if done >= code["max_rounds"]:
        raise Refused(f"ROUND CAP — {key}: უკვე {done} შემოწმება (ლიმიტი {code['max_rounds']}). "
                      "მესამე ბრუნი არ არის: ღია critical/high შენიშვნებზე გადაწყვეტს მფლობელი (UNVERIFIED).", EXIT_CAP)
    diff, left_out, truncated = review_input(a.base, code["max_diff_chars"])
    specs = [g.nodes[ln.resolved] for ln in plan.links if ln.kind == "spec" and ln.resolved in g.nodes]
    spec_text = (ROOT / specs[0].path).read_text(encoding="utf-8") if specs else "(plan has no resolvable spec link)"
    review_path = ROOT / "REVIEW.md"
    if not review_path.exists():
        raise Refused("REVIEW CONTRACT — REVIEW.md is missing; the checker has no review contract — restore it first")
    rnd = done + 1
    prompt = redact(fill("code-checker.md", {"task_text": task_line, "spec_text": spec_text,
                                             "review_md": review_path.read_text(encoding="utf-8"), "diff": diff},
                         round=str(rnd), max_rounds=str(code["max_rounds"]), plan_id=plan_id, task=a.task))[0]
    base = f"{dt.date.today().isoformat()}-code-{slug(plan_id)}-{slug(a.task)}-r{rnd}"
    if a.dry_run:
        run_dir = RUNS / run_name(base, time_stamp())
        print(f"DRY-RUN code-check — {key}, round {rnd}/{code['max_rounds']}, stage {cfg['stage']} "
              "(nothing is called, nothing is written)")
        print(dry_run_line(plan_step("checker", code["checker_model"], cfg, run_dir, "review"), deny))
        print(f"  prompt: {len(prompt)} chars; diff {len(diff)} chars{' (truncated)' if truncated else ''}"
              + (f"; secret files left out: {len(left_out)}" if left_out else ""))
        return 0
    run_id, run_dir = new_run(base)
    checker = plan_step("checker", code["checker_model"], cfg, run_dir, "review")
    meta = {"id": run_id, "loop": "code", "key": key, "round": rnd, "stage": cfg["stage"], "status": "running",
            "started": now(), "models": {"maker": code["maker_model"], "checker": code["checker_model"]}}
    if left_out:
        meta["left_out"] = left_out
    start_run(run_dir, meta, deny)
    try:
        review = run_recorded(checker, prompt, run_dir, meta, "review")
        verdict = final_label(review, "VERDICT", VERDICTS)
        if verdict == "unstated":
            raise StepFailed("checker", 0, "the review does not end with a line `VERDICT: approve | changes-requested | blocked`")
    except StepFailed as e:
        return fail(run_dir, meta, e)
    meta.update(status="complete", finished=now(), verdict=verdict)
    write_meta(run_dir, meta)
    print(f"checker verdict: {verdict} — {shown(run_dir)}/review.md (round {rnd}/{code['max_rounds']})")
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
    try:
        return {"status": cmd_status, "arch": cmd_arch, "code-check": cmd_code_check}[a.cmd](a)
    except Refused as e:
        print(str(e))
        return e.rc


if __name__ == "__main__":
    sys.exit(main())
