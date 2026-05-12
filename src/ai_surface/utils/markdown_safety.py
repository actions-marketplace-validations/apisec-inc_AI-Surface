"""Markdown-safety helpers shared by reporters and the diff renderer.

These functions exist because every string we render into markdown can
flow back to GitHub as a PR comment, and many of those strings originate
from attacker-controlled source files (the scanner's whole job is to read
PR contents). The helpers neutralise three classes of injection:

* **Code-fence break-out** — a snippet line containing ``` would close the
  fence and let everything after it render as raw markdown / HTML.
  ``safe_fence`` chooses a fence longer than any backtick run inside the
  body so the snippet can't break out.
* **Inline markdown structural chars** — leading ``#``, ``>``, ``-``, ``*``,
  ``|``, ``+`` change the document shape when interpolated into headings
  or bullets. ``sanitise_inline`` strips them.
* **Embedded HTML / control chars** — angle brackets, raw ANSI escapes,
  C0/C1 control characters in source code can rewrite a terminal title
  bar, smuggle hidden HTML, or just make the output unreadable.
  ``sanitise_inline`` strips control chars and replaces ``<`` / ``>``.

Callers should sanitise once at the rendering boundary, not inside detectors
(detector findings are stored unsanitised so other reporters — JSON
specifically — can decide their own escaping strategy).
"""
from __future__ import annotations

import re

# C0 / C1 control chars (excluding TAB / LF / CR which downstream renderers
# handle on their own). Stripping these prevents ANSI escapes / terminal-
# title hijacks via ``\x1b]0;...\x07`` and similar tricks.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitise_inline(value: str, max_len: int = 200) -> str:
    """Render ``value`` safe for inline markdown (headings, bullets, tables).

    The result has no control chars, no angle brackets, no backticks (so an
    attacker can't open a code span and emit raw markdown after the close),
    no leading markdown structural characters, and is collapsed to a single
    line. Truncated with an ellipsis at ``max_len``.
    """
    if not value:
        return ""
    s = _CONTROL_CHARS_RE.sub("", value)
    s = s.replace("<", "").replace(">", "")
    s = s.replace("`", "'")
    s = s.lstrip("#>-*|+ \t")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def safe_fence(snippet: str) -> tuple[str, str]:
    """Return ``(open_fence, body)`` so wrapping ``body`` in two ``open_fence``
    lines never lets the snippet break out of the code block.

    The body is stripped of control chars so embedded ANSI escapes can't
    survive into a terminal log either. Whitespace inside the body is
    otherwise preserved so the snippet stays readable.
    """
    body = _CONTROL_CHARS_RE.sub("", snippet)
    longest_run = 0
    current = 0
    for ch in body:
        if ch == "`":
            current += 1
            if current > longest_run:
                longest_run = current
        else:
            current = 0
    fence_len = max(3, longest_run + 1)
    return "`" * fence_len, body


__all__ = ["sanitise_inline", "safe_fence"]
