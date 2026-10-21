"""OpenAI-compatible and Anthropic-compatible chat calls.

The default base URL is AtmoRouter. Nothing in here runs during an offline scan.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from auditsift.config import Settings
from auditsift.errors import AuditError

Transport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]


class LLMError(AuditError):
    """The model call failed. Findings from the offline scan are kept."""


@dataclass
class Completion:
    text: str
    tokens_in: int
    tokens_out: int
    model: str


def estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


class LLMClient:
    def __init__(self, settings: Settings, transport: Transport | None = None) -> None:
        self.settings = settings
        self.transport = transport or urllib_transport

    def complete(self, *, model: str, system: str, user: str) -> Completion:
        if not self.settings.api_key:
            raise LLMError("no API key configured")
        url, headers, payload = build_request(self.settings, model, system, user)
        try:
            data = self.transport(url, headers, payload, self.settings.timeout)
        except LLMError:
            raise
        except Exception as exc:
            raise LLMError(str(exc)) from exc
        if self.settings.api_style == "anthropic":
            return parse_anthropic(data, model, system, user)
        return parse_openai(data, model, system, user)


def build_request(settings: Settings, model: str, system: str, user: str) -> tuple[str, dict[str, str], dict[str, Any]]:
    if settings.api_style == "anthropic":
        url = settings.base_url.rstrip("/") + "/messages"
        headers = {
            "content-type": "application/json",
            "x-api-key": settings.api_key or "",
            "anthropic-version": "2023-06-01",
        }
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": 800,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        return url, headers, payload
    url = settings.base_url.rstrip("/") + "/chat/completions"
    headers = {
        "content-type": "application/json",
        "authorization": f"Bearer {settings.api_key or ''}",
    }
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    return url, headers, payload


def parse_openai(data: dict[str, Any], model: str, system: str, user: str) -> Completion:
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("model response did not include a chat message") from exc
    text = _message_text(message.get("content"))
    usage = data.get("usage") or {}
    tokens_in = usage.get("prompt_tokens")
    tokens_out = usage.get("completion_tokens")
    if tokens_in is None:
        tokens_in = estimate_tokens(system) + estimate_tokens(user)
    if tokens_out is None:
        tokens_out = estimate_tokens(text)
    return Completion(text=text, tokens_in=int(tokens_in), tokens_out=int(tokens_out), model=model)


def parse_anthropic(data: dict[str, Any], model: str, system: str, user: str) -> Completion:
    blocks = data.get("content") or []
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, dict) and block.get("text"):
            parts.append(str(block["text"]))
    text = "".join(parts)
    usage = data.get("usage") or {}
    tokens_in = usage.get("input_tokens")
    tokens_out = usage.get("output_tokens")
    if tokens_in is None:
        tokens_in = estimate_tokens(system) + estimate_tokens(user)
    if tokens_out is None:
        tokens_out = estimate_tokens(text)
    return Completion(text=text, tokens_in=int(tokens_in), tokens_out=int(tokens_out), model=model)


def extract_json(text: str) -> dict[str, Any]:
    raw = text.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]
        raw = raw.strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise
        value = json.loads(raw[start : end + 1])
    if not isinstance(value, dict):
        raise json.JSONDecodeError("expected an object", raw, 0)
    return value


def urllib_transport(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise LLMError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(str(exc.reason)) from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError("model response was not JSON") from exc
    if not isinstance(parsed, dict):
        raise LLMError("model response was not a JSON object")
    return parsed


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)
    return "" if content is None else str(content)
