"""Minimal, dependency-free YAML frontmatter parser.

If PyYAML is installed it is used for full fidelity; otherwise a constrained
parser handles the subset of YAML that SKILL.md frontmatter uses:

- ``key: scalar``
- ``key: [a, b, c]``  (inline flow lists)
- block lists::

      key:
        - a
        - b

- quoted and unquoted scalars, booleans, ints, and ``null``.

Keeping this dependency-free lets ``cybersentinel validate`` run in any
environment (CI, air-gapped lab) without ``pip install``.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

try:  # pragma: no cover - exercised only when PyYAML is present
    import yaml  # type: ignore

    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


class FrontmatterError(ValueError):
    """Raised when frontmatter is missing or cannot be parsed."""


def split_frontmatter(text: str) -> Tuple[str, str]:
    """Return ``(frontmatter_yaml, body)`` for a document starting with ``---``.

    Raises :class:`FrontmatterError` if the opening/closing ``---`` fence is
    missing.
    """
    # Normalise newlines and a possible UTF-8 BOM.
    text = text.lstrip("﻿")
    if not text.startswith("---"):
        raise FrontmatterError("document does not start with a '---' frontmatter fence")

    lines = text.splitlines()
    # First line must be exactly the opening fence.
    if lines[0].strip() != "---":
        raise FrontmatterError("first line must be exactly '---'")

    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            fm = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1 :])
            return fm, body
    raise FrontmatterError("closing '---' frontmatter fence not found")


def _coerce_scalar(value: str) -> Any:
    v = value.strip()
    if v == "" or v.lower() in {"null", "~"}:
        return None
    if (v[0], v[-1]) in {('"', '"'), ("'", "'")} and len(v) >= 2:
        return v[1:-1]
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if _is_int(v):
        return int(v)
    return v


def _is_int(v: str) -> bool:
    try:
        int(v)
        return True
    except ValueError:
        return False


def _parse_inline_list(value: str) -> list:
    inner = value.strip()[1:-1].strip()
    if not inner:
        return []
    return [_coerce_scalar(item) for item in _split_top_level(inner)]


def _split_top_level(inner: str) -> list:
    """Split a flow list body on commas not inside quotes."""
    out, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [s.strip() for s in out]


def _mini_parse(fm: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    lines = fm.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line != line.lstrip():
            raise FrontmatterError(f"unexpected indentation at line: {raw!r}")
        if ":" not in line:
            raise FrontmatterError(f"expected 'key: value' at line: {raw!r}")
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest.startswith("[") and rest.endswith("]"):
            data[key] = _parse_inline_list(rest)
            i += 1
        elif rest == "":
            # Could be a block list or an empty value.
            items = []
            j = i + 1
            while j < n and (lines[j].lstrip().startswith("- ") or lines[j].strip() == "-"):
                item = lines[j].lstrip()[1:].strip()
                items.append(_coerce_scalar(item))
                j += 1
            data[key] = items if items else None
            i = j
        else:
            data[key] = _coerce_scalar(rest)
            i += 1
    return data


def parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    """Parse a SKILL.md string into ``(frontmatter_dict, body)``."""
    fm, body = split_frontmatter(text)
    if _HAVE_YAML:
        try:
            data = yaml.safe_load(fm) or {}
        except Exception as exc:  # pragma: no cover
            raise FrontmatterError(f"invalid YAML frontmatter: {exc}") from exc
        if not isinstance(data, dict):
            raise FrontmatterError("frontmatter must be a mapping")
        return data, body
    return _mini_parse(fm), body
