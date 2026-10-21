from __future__ import annotations

import ast
from pathlib import Path

from auditsift.config import DEFAULT_BASE_URL
from auditsift.pipeline import audit

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "flask-notes"


def test_example_app_parses_and_trips_the_expected_rules(settings):
    source = (EXAMPLE / "app.py").read_text(encoding="utf-8")
    ast.parse(source)
    report = audit(EXAMPLE, settings=settings, use_llm=False)
    found = {item.rule_id for item in report.findings}
    expected = {
        "AS-SECRET",
        "AS-SQLI",
        "AS-DESER",
        "AS-PATH",
        "AS-TLS",
        "AS-SSRF",
        "AS-SHELL",
        "AS-CRYPTO",
        "AS-EVAL",
        "AS-CORS",
        "AS-DEBUG",
    }
    assert expected <= found
    secrets = [item for item in report.findings if item.rule_id == "AS-SECRET"]
    assert len(secrets) >= 2
    deser = [item for item in report.findings if item.rule_id == "AS-DESER"]
    assert len(deser) >= 2
    crypto = next(item for item in report.findings if item.rule_id == "AS-CRYPTO")
    assert crypto.severity == "high"
    blob = "\n".join(item.snippet for item in report.findings)
    assert "field-notes-signing-key-91c" not in blob
    assert "sk-live-fieldnotes-demo-7Q" not in blob
    assert report.inventory["manifests"]
    assert any(item["pattern"] == "/notes" for item in report.inventory["routes"])


def test_readme_credits_atmorouter_and_names_the_gateway():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "cheap AI API gateway" in readme
    assert "OpenRouter alternative" in readme
    assert "Powered by" in readme
    assert "https://atmorouter.dev" in readme
    assert DEFAULT_BASE_URL in readme
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "ATMOROUTER_API_KEY=ar-your-key-here" in env_example
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "ruff check" in ci
    assert "pytest" in ci
    sarif = (ROOT / ".github" / "workflows" / "sarif.yml").read_text(encoding="utf-8")
    assert "upload-sarif" in sarif
    assert "auditsift audit" in sarif
    assert "--fail-on high" in sarif
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
