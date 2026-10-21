"""Small source helpers. This is a line scanner, not a parser."""

from __future__ import annotations

import re


def strip_comment(line: str, marker: str = "#") -> str:
    """Drop a trailing comment without eating the marker inside a string."""
    out: list[str] = []
    quote: str | None = None
    triple = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if triple and line.startswith(quote, i):
                out.append(line[i + 1 : i + 3])
                i += 3
                quote = None
                triple = False
                continue
            if ch == "\\" and not triple and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if not triple and ch == quote:
                quote = None
            i += 1
            continue
        if ch in {"'", '"'} and line.startswith(ch * 3, i):
            quote = ch
            triple = True
            out.append(ch * 3)
            i += 3
            continue
        if ch in {"'", '"'}:
            quote = ch
            triple = False
            out.append(ch)
            i += 1
            continue
        if marker != "#" and line.startswith(marker, i):
            break
        if marker == "#" and ch == "#":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def string_spans(line: str) -> list[tuple[int, int]]:
    """Half-open spans of quotes on a single line, including the quotes."""
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch not in {"'", '"'}:
            i += 1
            continue
        if line.startswith(ch * 3, i):
            end = line.find(ch * 3, i + 3)
            if end < 0:
                spans.append((i, n))
                break
            spans.append((i, end + 3))
            i = end + 3
            continue
        j = i + 1
        while j < n:
            if line[j] == "\\":
                j += 2
                continue
            if line[j] == ch:
                break
            j += 1
        spans.append((i, min(j + 1, n)))
        i = min(j + 1, n)
    return spans


def in_string(line: str, index: int) -> bool:
    return any(start <= index < end for start, end in string_spans(line))


def blank_strings(text: str) -> str:
    """Replace string contents with spaces so keyword checks see code, not data."""
    chars = list(text)
    for start, end in string_spans(text):
        for pos in range(start + 1, max(start + 1, end - 1)):
            if chars[pos] != "\n":
                chars[pos] = " "
    return "".join(chars)


def match_outside_strings(line: str, pattern: re.Pattern[str]) -> re.Match[str] | None:
    for match in pattern.finditer(line):
        if not in_string(line, match.start()):
            return match
    return None


def docstring_mask(lines: list[str]) -> list[bool]:
    """True for lines that sit inside a multiline triple-quoted block.

    The opening line stays unmasked so real code on that line is still scanned.
    String-span checks cover quotes that begin and end on one line.
    """
    masked = [False] * len(lines)
    delimiter: str | None = None
    for index, line in enumerate(lines):
        if delimiter is not None:
            masked[index] = True
            if line.count(delimiter) % 2 == 1:
                delimiter = None
            continue
        for quote in ('"""', "'''"):
            if line.count(quote) % 2 == 1:
                delimiter = quote
                break
    return masked


def paren_depth(text: str) -> int:
    depth = 0
    for ch in blank_strings(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth


def call_window(lines: list[str], index: int, comment: str = "#") -> tuple[int, str]:
    """Return the start line index and text of the call that touches ``index``."""
    start = index
    for _ in range(8):
        if start == 0:
            break
        window = "\n".join(strip_comment(lines[j], comment) for j in range(start, index + 1))
        prev = strip_comment(lines[start - 1], comment).rstrip()
        continues = prev.endswith((",", "\\", "(", "{", "["))
        if paren_depth(window) > 0 or continues:
            start -= 1
            included = strip_comment(lines[start], comment)
            joined = "\n".join(strip_comment(lines[j], comment) for j in range(start, index + 1))
            if "(" in included and paren_depth(joined) >= 0:
                break
            continue
        break
    text = "\n".join(strip_comment(lines[j], comment) for j in range(start, index + 1))
    return start, text


def indent_of(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))
