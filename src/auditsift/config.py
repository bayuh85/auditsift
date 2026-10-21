"""Environment and .env loading. The process environment wins over the file."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from auditsift.errors import AuditError

DEFAULT_BASE_URL = "https://atmorouter.dev/v1"
DEFAULT_TRIAGE_MODEL = "openai/gpt-4o-mini"
DEFAULT_VERIFY_MODEL = "openai/gpt-4.1-nano"


@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: str | None
    triage_model: str
    verify_model: str
    api_style: str
    timeout: float


def parse_dotenv(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key:
            found[key] = value
    return found


def load_settings(
    environ: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = None,
) -> Settings:
    """Build settings.

    With ``environ`` omitted, start from the process environment and fill any
    gaps from ``.env`` in the working directory. With ``environ`` provided, that
    mapping is the whole environment and does not inherit the process.
    """
    if environ is None:
        env = dict(os.environ)
        path = Path(dotenv_path) if dotenv_path else Path.cwd() / ".env"
        if path.is_file():
            for key, value in parse_dotenv(path.read_text(encoding="utf-8")).items():
                env.setdefault(key, value)
    else:
        env = {}
        if dotenv_path:
            path = Path(dotenv_path)
            if path.is_file():
                env.update(parse_dotenv(path.read_text(encoding="utf-8")))
        env.update(environ)

    style = (env.get("AUDITSIFT_API_STYLE") or "openai").strip().lower()
    if style not in {"openai", "anthropic"}:
        raise AuditError(f"unsupported AUDITSIFT_API_STYLE: {style}")
    try:
        timeout = float(env.get("AUDITSIFT_TIMEOUT") or 45)
    except ValueError as exc:
        raise AuditError("AUDITSIFT_TIMEOUT must be a number of seconds") from exc
    key = env.get("AUDITSIFT_API_KEY") or env.get("ATMOROUTER_API_KEY") or None
    if key is not None and not key.strip():
        key = None
    return Settings(
        base_url=(env.get("AUDITSIFT_BASE_URL") or DEFAULT_BASE_URL).rstrip("/"),
        api_key=key,
        triage_model=env.get("AUDITSIFT_TRIAGE_MODEL") or DEFAULT_TRIAGE_MODEL,
        verify_model=env.get("AUDITSIFT_VERIFY_MODEL") or DEFAULT_VERIFY_MODEL,
        api_style=style,
        timeout=timeout,
    )
