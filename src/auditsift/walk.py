"""Walk a project tree and skip dependency and build directories."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".eggs",
    ".idea",
    ".vscode",
}

LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "composer.lock",
    "gemfile.lock",
}

LANG_BY_SUFFIX = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".java": "java",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".tf": "terraform",
}

MANIFEST_KINDS = {
    "requirements.txt": "pip",
    "pyproject.toml": "pyproject",
    "pipfile": "pipenv",
    "package.json": "npm",
    "go.mod": "go",
    "cargo.toml": "cargo",
    "gemfile": "bundler",
    "composer.json": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
}

MAX_BYTES = 1_000_000


@dataclass
class SourceFile:
    path: Path
    rel: str
    language: str | None
    text: str


def language_for(path: Path) -> str | None:
    return LANG_BY_SUFFIX.get(path.suffix.lower())


def is_manifest(path: Path) -> str | None:
    name = path.name.lower()
    if name in MANIFEST_KINDS:
        return MANIFEST_KINDS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pip"
    return None


def interesting(path: Path) -> bool:
    name = path.name
    lowered = name.lower()
    if lowered in LOCKFILES or name.endswith(".min.js") or name.endswith(".map"):
        return False
    if is_manifest(path):
        return True
    if lowered in {"dockerfile", "makefile"} or lowered.startswith(".env"):
        return True
    return language_for(path) is not None


def read_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_BYTES or size == 0:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:1024]:
        return None
    return data.decode("utf-8", errors="replace")


def iter_files(root: Path):
    if root.is_file():
        if interesting(root):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in SKIP_DIRS and not name.endswith(".egg-info") and name != "artifacts"
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if interesting(path):
                yield path


def display_path(path: Path, root: Path, git_root: Path | None) -> str:
    base = root
    if git_root is not None and _inside(root, git_root) and _inside(path, git_root):
        base = git_root
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


def collect(root: Path, git_root: Path | None) -> list[SourceFile]:
    files: list[SourceFile] = []
    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        files.append(
            SourceFile(
                path=path,
                rel=display_path(path, root, git_root),
                language=language_for(path),
                text=text,
            )
        )
    return files


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
