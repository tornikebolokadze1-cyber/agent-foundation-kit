#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secret, hidden-text and injection detection — one list of patterns, three readers.

  .claude/hooks/sentinel.py   redacts a credential from a tool's output BEFORE the model sees it, flags
                              instruction-like text in untrusted output, blocks a prompt that carries a key
  tools/observe.py            never prints a secret in the observatory report
  tools/gates/drill.py        seeds one random token per kind and proves each one is caught

Standard library only. Each provider pattern matches that provider's token prefix, and the three readers
share this one list, so a value one of them calls a secret the others do too. No entropy threshold on purpose: gitleaks
already has one (and the blind spot that comes with it) — the two checks miss different things.
"""
from __future__ import annotations

import re

# The replacement text. Built from parts so this file never contains a literal marker the guard's
# S2 rule (writing a redaction marker into a file) would refuse.
MARKER_PREFIX = "[" + "REDACTED:"
MARKER_RE = re.compile(r"\[" + r"REDACTED:[a-z0-9-]+\]")

# (kind, pattern). A pattern with a group named `secret` replaces only that group.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
                               r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?")),
    ("anthropic-key", re.compile(r"\bsk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{40,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{15,}")),
    ("stripe-key", re.compile(r"\b(?:sk|pk|rk)_live_[A-Za-z0-9]{20,}")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("notion-token", re.compile(r"\bntn_[A-Za-z0-9]{30,}")),
    ("digitalocean-token", re.compile(r"\bdop_v1_[a-f0-9]{40,}")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer-token", re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{20,}=*)")),
    # credentials embedded in a URL — the password between `user:` and `@host`: only the password group is hidden.
    ("url-credential", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<secret>[^\s/:@]+)@")),
]

# A line that announces itself as fake is documentation, not a leak.
DECOY_RE = re.compile(r"EXAMPLE|PLACEHOLDER|YOUR_|<your|xxxx|XXXX|REDACTED|dummy|DUMMY|sample|SAMPLE|"
                      r"changeme|CHANGEME|FAKE|fake")

# Characters that hide text from a human reader but not from a model (Unicode tag block = "ASCII
# smuggling"; bidirectional controls = "Trojan Source"). Ordinary text — Georgian included — has neither.
# Ranges are built with chr() so this source file itself stays plain ASCII (the `instructions` gate checks that).
HIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("unicode-tags", re.compile("[" + chr(0xE0000) + "-" + chr(0xE007F) + "]")),
    ("bidi-controls", re.compile("[" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069) + "]")),
]

# Instruction-like text inside content that came from outside (web, MCP, files outside the project).
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+)*"
               r"(?:previous|prior|above|earlier|preceding|system|original)\s+"
               r"(?:instructions?|prompts?|messages?|rules|directions|context)"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer)\b"),
    re.compile(r"(?i)\b(?:new|updated|real)\s+(?:system\s+)?instructions?\s*:"),
    re.compile(r"<\|im_(?:start|end)\|>|<\|(?:system|endoftext)\|>|\[/?INST\]|<<SYS>>"),
    re.compile(r"(?i)\bdo\s+not\s+(?:tell|inform|alert|mention\s+(?:this\s+)?to)\s+the\s+(?:user|owner|human)"),
    re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|forward|leak)\b.{0,60}"
               r"\b(?:api[\s_-]?keys?|tokens?|passwords?|credentials?|secrets?|\.env)\b"),
    re.compile(r"(?:დაივიწყე|უგულებელყავი|არ\s+გაითვალისწინო).{0,40}(?:ინსტრუქცი|მითითებ|წესებ)"),
]


DECOY_WINDOW = 60  # characters on either side of the token, on its own line


def _is_decoy(text: str, start: int, end: int) -> bool:
    """A token is documentation when it, or the text right beside it on its line, says so. A decoy word elsewhere on a
    long line (minified JSON) or inside a key's body proves nothing about this token (review S2)."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    token = text[start:end] if "\n" not in text[start:end] else ""
    near = text[max(line_start, start - DECOY_WINDOW):start] + " " + token + " " + text[end:min(line_end, end + DECOY_WINDOW)]
    return bool(DECOY_RE.search(near))


def find_secrets(text: str, skip_decoys: bool = False) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every credential-looking span, earliest first, without overlaps."""
    hits: list[tuple[str, int, int]] = []
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            s, e = (m.start("secret"), m.end("secret")) if "secret" in pat.groupindex else m.span()
            if skip_decoys and _is_decoy(text, s, e):
                continue
            hits.append((kind, s, e))
    hits.sort(key=lambda h: (h[1], -(h[2] - h[1])))
    out: list[tuple[str, int, int]] = []
    for h in hits:
        if not out or h[1] >= out[-1][2]:
            out.append(h)
    return out


def redact(text: str) -> tuple[str, list[str]]:
    """The text with every credential replaced by its redaction marker, and the kinds found."""
    hits = find_secrets(text)
    if not hits:
        return text, []
    parts, pos = [], 0
    for kind, s, e in hits:
        parts += [text[pos:s], f"{MARKER_PREFIX}{kind}]"]
        pos = e
    parts.append(text[pos:])
    return "".join(parts), [k for k, _, _ in hits]


def redact_obj(obj):
    """Redact every string inside a JSON-like value, keeping its exact shape (keys, types, order)."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        out, kinds = [], []
        for item in obj:
            v, k = redact_obj(item)
            out.append(v)
            kinds += k
        return out, kinds
    if isinstance(obj, dict):
        out_d, kinds = {}, []
        for key, item in obj.items():
            v, k = redact_obj(item)
            out_d[key] = v
            kinds += k
        return out_d, kinds
    return obj, []


def hidden_chars(text: str) -> list[str]:
    return [kind for kind, pat in HIDDEN_PATTERNS if pat.search(text)]


def injection_hits(text: str, limit: int = 3) -> list[str]:
    """Short excerpts of instruction-like text (at most `limit`), for a warning the model reads."""
    out: list[str] = []
    for pat in INJECTION_PATTERNS:
        for m in pat.finditer(text):
            out.append(" ".join(m.group(0).split())[:80])
            if len(out) >= limit:
                return out
    return out


def text_of(obj) -> str:
    """All strings inside a JSON-like value, joined — what a scan should look at."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return "\n".join(text_of(x) for x in obj)
    if isinstance(obj, dict):
        return "\n".join(text_of(x) for x in obj.values())
    return ""
