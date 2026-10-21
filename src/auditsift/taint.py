"""Track names that picked up a value from an HTTP request inside one function.

The pass is deliberately local. It is there so path, shell, and request-target
checks can see ``name = request.args.get(...)`` a few lines above the sink.
"""

from __future__ import annotations

import re

from auditsift.syntax import indent_of, strip_comment

_REQUEST = re.compile(r"\brequest\s*\.")
_DEF = re.compile(r"^(?:async\s+def|def)\s+\w+\s*\(")
_ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)(.+)$")
_ROUTE = re.compile(r"\.(?:route|get|post|put|patch|delete|head)\s*\(")
_SKIP_PARAMS = {"self", "cls"}


def tainted_before(lines: list[str]) -> list[set[str]]:
    """Names that are already tainted when each line begins."""
    before: list[set[str]] = []
    stack: list[tuple[int, set[str]]] = [(0, set())]
    pending_route = False

    for line in lines:
        stripped = strip_comment(line).strip()
        indent = indent_of(line) if stripped else stack[-1][0]
        if stripped:
            while len(stack) > 1 and indent < stack[-1][0]:
                stack.pop()
        before.append(set(stack[-1][1]))
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@"):
            if _ROUTE.search(stripped):
                pending_route = True
            continue
        if _DEF.match(stripped):
            params = _parameter_names(stripped)
            tainted = set(params) if pending_route else set()
            pending_route = False
            stack.append((indent + 1, tainted))
            continue
        if stripped.startswith("class "):
            pending_route = False
            stack.append((indent + 1, set()))
            continue
        pending_route = False
        matched = _ASSIGN.match(stripped)
        if not matched:
            continue
        name, rhs = matched.group(1), matched.group(2)
        scope = stack[-1][1]
        if expression_tainted(rhs, scope):
            scope.add(name)
        else:
            scope.discard(name)
    return before


def expression_tainted(expr: str, tainted: set[str]) -> bool:
    if _REQUEST.search(expr):
        return True
    for inner in re.findall(r"\{([^{}]+)\}", expr):
        if expression_tainted(inner, tainted):
            return True
    code = _without_quotes(expr)
    for name in tainted:
        if re.search(rf"\b{re.escape(name)}\b", code):
            return True
    return False


def _without_quotes(expr: str) -> str:
    return re.sub(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", "''", expr)


def _parameter_names(header: str) -> list[str]:
    match = re.search(r"\((.*)\)", header)
    if not match:
        return []
    names: list[str] = []
    for part in match.group(1).split(","):
        piece = part.strip().split("=")[0].strip().lstrip("*")
        if piece and piece.isidentifier() and piece not in _SKIP_PARAMS:
            names.append(piece)
    return names
