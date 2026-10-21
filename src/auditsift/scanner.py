"""Turn a tree of source files into rule candidates."""

from __future__ import annotations

from pathlib import Path

from auditsift.diffutil import filter_candidates, find_git_root
from auditsift.models import Candidate
from auditsift.rules import run_rules
from auditsift.walk import collect


def scan_target(target: str | Path, changed: dict[str, set[int]] | None = None) -> list[Candidate]:
    root = Path(target).resolve()
    git_root = find_git_root(root if root.is_dir() else root.parent)
    files = collect(root, git_root)
    found: list[Candidate] = []
    for source in files:
        found.extend(run_rules(source))
    found = filter_candidates(found, changed)
    found.sort(key=lambda item: (item.path, item.line, item.rule_id))
    return found
