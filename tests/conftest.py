from __future__ import annotations

from pathlib import Path

import pytest

from auditsift.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        base_url="https://atmorouter.dev/v1",
        api_key=None,
        triage_model="openai/gpt-4o-mini",
        verify_model="openai/gpt-4.1-nano",
        api_style="openai",
        timeout=5,
    )


def write_source(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
