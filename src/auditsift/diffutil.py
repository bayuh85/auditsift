"""Limit findings to lines a git diff actually changed."""

from __future__ import annotations

import subprocess
from pathlib import Path

from auditsift.errors import AuditError


def find_git_root(start: Path) -> Path | None:
    probe = start if start.is_dir() else start.parent
    if not probe.exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout.strip()
    return Path(text) if text else None


def diff_changed_lines(repo: Path, ref: str) -> dict[str, set[int]]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "diff", "-U0", "--no-color", ref, "--"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AuditError("git is not installed; --diff needs git") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "git diff failed").strip()
        raise AuditError(detail)
    changed = parse_unified_diff(proc.stdout)
    for path in _untracked(repo):
        file_path = repo / path
        if not file_path.is_file():
            continue
        total = len(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
        changed.setdefault(path, set()).update(range(1, max(total, 1) + 1))
    return changed


def parse_unified_diff(text: str) -> dict[str, set[int]]:
    """Map repo-relative paths to added or replaced line numbers in the new file."""
    changed: dict[str, set[int]] = {}
    path: str | None = None
    new_line: int | None = None
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            name = raw[4:].strip().strip('"')
            if name == "/dev/null":
                path = None
                continue
            if name.startswith("b/"):
                name = name[2:]
            path = name
            changed.setdefault(path, set())
            new_line = None
            continue
        if raw.startswith("--- ") or raw.startswith("diff ") or raw.startswith("index "):
            continue
        if raw.startswith("@@"):
            new_line = _hunk_start(raw)
            continue
        if path is None or new_line is None:
            continue
        if raw.startswith("+"):
            changed[path].add(new_line)
            new_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            new_line += 1
    return changed


def filter_candidates(candidates, changed: dict[str, set[int]] | None):
    if changed is None:
        return list(candidates)
    kept = []
    for candidate in candidates:
        lines = changed.get(candidate.path)
        if not lines:
            continue
        if any(number in lines for number in range(candidate.line, candidate.end_line + 1)):
            kept.append(candidate)
    return kept


def _hunk_start(header: str) -> int | None:
    # @@ -12,0 +13,2 @@ optional text
    try:
        plus = header.split("+", 1)[1]
    except IndexError:
        return None
    number = plus.split(",", 1)[0].split(" ", 1)[0]
    if not number.isdigit():
        return None
    return int(number)


def _untracked(repo: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    paths: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) < 4 or line[:2] != "??":
            continue
        path = line[3:].strip()
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        paths.append(path)
    return paths
