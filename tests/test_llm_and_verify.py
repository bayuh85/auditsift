from __future__ import annotations

import json

import pytest

from auditsift.config import Settings, load_settings, parse_dotenv
from auditsift.llm import (
    Completion,
    LLMClient,
    LLMError,
    build_request,
    extract_json,
    parse_anthropic,
    parse_openai,
)
from auditsift.pipeline import audit, exit_code_for
from auditsift.render import render_sarif
from auditsift.verify import evidence_in_snippet
from tests.conftest import write_source

ROOT_CODE = "def run(user):\n    return eval(user)\n"


class Scripted:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, *, model, system, user):
        self.calls.append({"model": model, "system": system, "user": user})
        text, tokens_in, tokens_out = self.responses.pop(0)
        return Completion(text=text, tokens_in=tokens_in, tokens_out=tokens_out, model=model)


def _settings(**overrides) -> Settings:
    data = {
        "base_url": "https://atmorouter.dev/v1",
        "api_key": "ar-test",
        "triage_model": "openai/gpt-4o-mini",
        "verify_model": "openai/gpt-4.1-nano",
        "api_style": "openai",
        "timeout": 5,
    }
    data.update(overrides)
    return Settings(**data)


def _confirm(user: str) -> str:
    code = user.split("-----8<-----", 1)[1].split("----->8-----", 1)[0].strip()
    evidence = code.splitlines()[-1].strip()
    return json.dumps({"verdict": "confirm", "evidence": evidence, "reason": "the call is in the snippet"})


def test_default_gateway_and_key_override(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ATMOROUTER_API_KEY=ar-from-file\nAUDITSIFT_BASE_URL=https://example.test/v1\n",
        encoding="utf-8",
    )
    bare = load_settings(environ={})
    assert bare.base_url == "https://atmorouter.dev/v1"
    assert bare.api_key is None
    assert bare.triage_model == "openai/gpt-4o-mini"
    assert bare.verify_model == "openai/gpt-4.1-nano"
    filled = load_settings(environ={}, dotenv_path=env_file)
    assert filled.api_key == "ar-from-file"
    overridden = load_settings(
        environ={"AUDITSIFT_API_KEY": "ar-override"},
        dotenv_path=env_file,
    )
    assert overridden.api_key == "ar-override"
    assert overridden.base_url == "https://example.test/v1"


def test_parse_dotenv_ignores_comments_and_quotes():
    parsed = parse_dotenv('# note\nexport ATMOROUTER_API_KEY="ar-your-key-here"\n\n')
    assert parsed == {"ATMOROUTER_API_KEY": "ar-your-key-here"}


def test_unsupported_api_style_is_rejected():
    with pytest.raises(Exception, match="AUDITSIFT_API_STYLE"):
        load_settings(environ={"AUDITSIFT_API_STYLE": "xmlrpc"})


def test_openai_and_anthropic_payloads():
    settings = _settings(base_url="https://atmorouter.dev/v1/")
    url, headers, payload = build_request(settings, "openai/gpt-4o-mini", "sys", "user")
    assert url == "https://atmorouter.dev/v1/chat/completions"
    assert headers["authorization"] == "Bearer ar-test"
    assert payload["messages"][0]["content"] == "sys"
    assert payload["temperature"] == 0
    anthropic = _settings(api_style="anthropic")
    url, headers, payload = build_request(anthropic, "claude-haiku", "sys", "user")
    assert url == "https://atmorouter.dev/v1/messages"
    assert headers["x-api-key"] == "ar-test"
    assert headers["anthropic-version"] == "2023-06-01"
    assert payload["system"] == "sys"
    assert payload["messages"] == [{"role": "user", "content": "user"}]


def test_parsers_read_usage_and_estimate_when_it_is_missing():
    counted = parse_openai(
        {"choices": [{"message": {"content": "hello"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 1}},
        "m",
        "system",
        "user",
    )
    assert (counted.tokens_in, counted.tokens_out) == (3, 1)
    estimated = parse_openai({"choices": [{"message": {"content": "hello"}}]}, "m", "system", "user")
    assert estimated.tokens_in > 0
    assert estimated.tokens_out > 0
    anthropic = parse_anthropic(
        {"content": [{"type": "text", "text": "{}"}], "usage": {"input_tokens": 4, "output_tokens": 2}},
        "m",
        "s",
        "u",
    )
    assert (anthropic.text, anthropic.tokens_in, anthropic.tokens_out) == ("{}", 4, 2)


def test_extract_json_from_a_fence():
    assert extract_json('```json\n{"verdict": "confirm"}\n```')["verdict"] == "confirm"


def test_client_posts_through_the_injected_transport():
    seen = {}

    def transport(url, headers, payload, timeout):
        seen["url"] = url
        seen["timeout"] = timeout
        return {"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 2, "completion_tokens": 2}}

    client = LLMClient(_settings(), transport=transport)
    result = client.complete(model="openai/gpt-4o-mini", system="s", user="u")
    assert seen["url"].endswith("/chat/completions")
    assert seen["timeout"] == 5
    assert result.text == "ok"


def test_triage_enriches_and_verify_confirms_with_a_real_quote(tmp_path):
    write_source(tmp_path, "app.py", ROOT_CODE)
    client = Scripted(
        [
            ('{"impact": "Attackers run code.", "fix": "Parse a subset."}', 11, 5),
            (None, 8, 4),
        ]
    )

    def complete(*, model, system, user):
        client.calls.append({"model": model, "system": system, "user": user})
        if "verify stage" in system:
            text = _confirm(user)
            return Completion(text=text, tokens_in=8, tokens_out=4, model=model)
        return Completion(
            text='{"impact": "Attackers run code.", "fix": "Parse a subset."}',
            tokens_in=11,
            tokens_out=5,
            model=model,
        )

    client.complete = complete
    report = audit(tmp_path, settings=_settings(), client=client)
    assert report.findings[0].verdict == "confirmed"
    assert report.findings[0].impact == "Attackers run code."
    assert report.findings[0].fix == "Parse a subset."
    assert report.findings[0].evidence
    assert evidence_in_snippet(report.findings[0].evidence, report.findings[0].snippet)
    phases = {row.phase: row for row in report.usage}
    assert phases["triage"].tokens_in == 11
    assert phases["triage"].tokens_out == 5
    assert phases["verify"].tokens_in == 8
    assert phases["verify"].model == "openai/gpt-4.1-nano"
    assert phases["map"].model is None
    verify_call = next(call for call in client.calls if "verify stage" in call["system"])
    assert "Attackers run code." not in verify_call["user"]
    assert "triage stage" not in verify_call["system"]


def test_rejected_findings_are_dropped_and_do_not_trip_the_gate(tmp_path):
    write_source(tmp_path, "app.py", ROOT_CODE)
    client = Scripted([])

    def complete(*, model, system, user):
        if "verify stage" in system:
            body = {"verdict": "reject", "evidence": "return eval(user)", "reason": "helper is unreachable"}
            return Completion(text=json.dumps(body), tokens_in=1, tokens_out=1, model=model)
        return Completion(text='{"impact": "x", "fix": "y"}', tokens_in=1, tokens_out=1, model=model)

    client.complete = complete
    report = audit(tmp_path, settings=_settings(), client=client)
    assert report.findings == []
    assert len(report.rejected) == 1
    assert report.rejected[0].verdict == "rejected"
    assert exit_code_for(report.findings, "high") == 0
    sarif = render_sarif(report)
    assert sarif["runs"][0]["results"] == []


def test_confirm_without_a_real_quote_is_rejected(tmp_path):
    write_source(tmp_path, "app.py", ROOT_CODE)

    def complete(*, model, system, user):
        if "verify stage" in system:
            body = {"verdict": "confirm", "evidence": "this quote is not in the code", "reason": "sure"}
            return Completion(text=json.dumps(body), tokens_in=2, tokens_out=2, model=model)
        return Completion(text='{"impact": "x", "fix": "y"}', tokens_in=2, tokens_out=2, model=model)

    client = Scripted([])
    client.complete = complete
    report = audit(tmp_path, settings=_settings(), client=client)
    assert report.findings == []
    assert report.rejected[0].reason == "evidence quote was not present in the code"


def test_verify_transport_error_keeps_the_offline_finding(tmp_path):
    write_source(tmp_path, "app.py", ROOT_CODE)

    def complete(*, model, system, user):
        if "verify stage" in system:
            raise LLMError("gateway timeout")
        return Completion(text='{"impact": "kept", "fix": "still here"}', tokens_in=3, tokens_out=1, model=model)

    client = Scripted([])
    client.complete = complete
    report = audit(tmp_path, settings=_settings(), client=client)
    assert len(report.findings) == 1
    assert report.findings[0].verdict == "unverified"
    assert "gateway timeout" in (report.findings[0].reason or "")
    assert exit_code_for(report.findings, "high") == 1
    assert any("verify failed" in note for note in report.notes)


def test_short_evidence_is_not_enough():
    assert evidence_in_snippet("eval", "return eval(user)") is False
    assert evidence_in_snippet("`return eval(user)`", "return eval(user)") is True
