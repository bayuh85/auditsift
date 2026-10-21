"""Build a compact attack-surface summary without running the model."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from auditsift.diffutil import find_git_root
from auditsift.models import redact_secret
from auditsift.rules import (
    AWS_KEY,
    GH_TOKEN,
    PRIVATE_KEY,
    SECRET_ASSIGN,
    SLACK_TOKEN,
    _secret_kind,
    _skip_secret_file,
)
from auditsift.walk import SourceFile, collect, is_manifest

_ENTRY_PATTERNS = (
    ("flask", re.compile(r"\bFlask\s*\(")),
    ("fastapi", re.compile(r"\bFastAPI\s*\(")),
    ("django", re.compile(r"\bdjango\.setup\s*\(|\bexecute_from_command_line\s*\(")),
    ("express", re.compile(r"\bexpress\s*\(")),
    ("main", re.compile(r"""__name__\s*==\s*['\"]__main__['\"]""")),
    ("go-main", re.compile(r"\bfunc\s+main\s*\(")),
    ("node-listen", re.compile(r"\.(?:listen|createServer)\s*\(")),
)
_PY_ROUTE = re.compile(
    r"@(\w+)\.(?P<verb>route|get|post|put|patch|delete|head)\(\s*(['\"])(?P<pattern>[^'\"]+)\3(?P<tail>[^)]*)\)"
)
_JS_ROUTE = re.compile(
    r"\b(?:app|router)\.(?P<verb>get|post|put|patch|delete|head|all)\(\s*(['\"])(?P<pattern>[^'\"]+)\2"
)
_METHODS = re.compile(r"['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", re.I)


def build_inventory(target: str | Path) -> tuple[dict, list[SourceFile], Path | None]:
    raw = Path(target)
    root = raw.resolve()
    anchor = root if root.is_dir() else root.parent
    git_root = find_git_root(anchor)
    files = collect(root, git_root)
    languages: Counter[str] = Counter()
    entry_points: list[dict] = []
    routes: list[dict] = []
    manifests: list[dict] = []
    secrets: list[dict] = []
    total_bytes = 0
    for source in files:
        total_bytes += len(source.text.encode("utf-8", errors="replace"))
        if source.language:
            languages[source.language] += 1
        kind = is_manifest(source.path)
        if kind:
            manifests.append({"path": source.rel, "kind": kind})
        entry_points.extend(_entries(source))
        routes.extend(_routes(source))
        secrets.extend(_secrets(source))
    summary = {
        "root": raw.as_posix(),
        "files": len(files),
        "bytes": total_bytes,
        "languages": dict(sorted(languages.items())),
        "entry_points": entry_points,
        "routes": routes,
        "manifests": manifests,
        "secrets": secrets,
    }
    return summary, files, git_root


def _entries(source: SourceFile) -> list[dict]:
    found: list[dict] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for kind, pattern in _ENTRY_PATTERNS:
            if pattern.search(line):
                found.append({"path": source.rel, "line": line_no, "kind": kind})
    return found


def _routes(source: SourceFile) -> list[dict]:
    found: list[dict] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        match = _PY_ROUTE.search(line)
        if match:
            verb = match.group("verb")
            methods = "GET" if verb == "route" else verb.upper()
            explicit = [item.upper() for item in _METHODS.findall(match.group("tail") or "")]
            if explicit:
                methods = ",".join(explicit)
            found.append(
                {
                    "path": source.rel,
                    "line": line_no,
                    "method": methods,
                    "pattern": match.group("pattern"),
                }
            )
            continue
        js = _JS_ROUTE.search(line)
        if js:
            found.append(
                {
                    "path": source.rel,
                    "line": line_no,
                    "method": js.group("verb").upper(),
                    "pattern": js.group("pattern"),
                }
            )
    return found


def _secrets(source: SourceFile) -> list[dict]:
    if _skip_secret_file(source.rel):
        return []
    found: list[dict] = []
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        kind = _secret_kind(line)
        if not kind:
            continue
        found.append(
            {
                "path": source.rel,
                "line": line_no,
                "kind": kind,
                "redacted": _redacted_preview(line),
            }
        )
    return found


def _redacted_preview(line: str) -> str:
    assigned = SECRET_ASSIGN.search(line)
    if assigned:
        return redact_secret(assigned.group("value"))
    for pattern in (AWS_KEY, GH_TOKEN, SLACK_TOKEN):
        match = pattern.search(line)
        if match:
            return redact_secret(match.group(0))
    if PRIVATE_KEY.search(line):
        return "-----BEGIN…KEY"
    return "•••"
