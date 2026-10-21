from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

from auditsift.cli import main
from auditsift.llm import Completion
from auditsift.mcp_server import dispatch, serve
from auditsift.models import Finding
from auditsift.pipeline import audit, exit_code_for
from auditsift.render import render, render_markdown, render_sarif
from tests.conftest import write_source

ROOT = Path(__file__).resolve().parents[1]
EVAL = "def run(user):\n    return eval(user)\n"


def test_sarif_is_2_1_0_and_points_at_a_line(tmp_path, settings):
    write_source(tmp_path, "app.py", EVAL)
    report = audit(tmp_path, settings=settings, use_llm=False)
    sarif = render_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    result = sarif["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]["region"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert region["startLine"] >= 1
    assert result["ruleId"] == "AS-EVAL"
    assert result["level"] == "error"
    assert result["message"]["text"]
    assert "://" not in uri
    assert not uri.startswith("/")
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "AS-EVAL"
    assert rule["properties"]["security-severity"] == "8.0"
    assert report.findings[0].id.startswith("AS-EVAL-")
    markdown = render_markdown(report)
    assert "AS-EVAL" in markdown
    assert "cost estimate" not in markdown
    assert "| triage |" in markdown


def test_severity_gate_ranks():
    def finding(severity: str) -> Finding:
        return Finding(
            id="x",
            rule_id="AS-EVAL",
            title="t",
            severity=severity,
            path="app.py",
            start_line=1,
            end_line=1,
            message="m",
            snippet="eval(user)",
        )

    assert exit_code_for([], "high") == 0
    assert exit_code_for([finding("low")], "high") == 0
    assert exit_code_for([finding("high")], "high") == 1
    assert exit_code_for([finding("critical")], "high") == 1
    assert exit_code_for([finding("high")], "critical") == 0


def test_scan_json_fail_on_and_cost_ledger(tmp_path, capsys):
    write_source(tmp_path, "app.py", EVAL)
    code = main(["scan", str(tmp_path), "--format", "json", "--fail-on", "high"])
    captured = capsys.readouterr()
    assert code == 1
    payload = json.loads(captured.out)
    assert payload["tool"] == "auditsift"
    assert payload["findings"][0]["rule_id"] == "AS-EVAL"
    assert "cost estimate" in captured.err
    assert "triage" in captured.err
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0


def test_missing_path_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "path not found" in capsys.readouterr().err


def test_audit_offline_writes_json_sarif_and_markdown(tmp_path, capsys):
    write_source(tmp_path, "app.py", EVAL)
    out = tmp_path / "results"
    code = main(
        [
            "audit",
            str(tmp_path),
            "--offline",
            "--fail-on",
            "high",
            "--out",
            str(out),
            "--format",
            "md",
        ]
    )
    assert code == 1
    sarif = json.loads((out / "auditsift.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert (out / "auditsift.md").read_text(encoding="utf-8").startswith("# auditsift report")
    saved = json.loads((out / "auditsift.json").read_text(encoding="utf-8"))
    assert saved["findings"][0]["rule_id"] == "AS-EVAL"
    rendered = main(["report", str(out / "auditsift.json"), "--format", "text"])
    assert rendered == 0
    assert "AS-EVAL" in capsys.readouterr().out


def test_map_text_lists_a_route(tmp_path, capsys):
    write_source(
        tmp_path,
        "app.py",
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/notes')\ndef notes():\n    return []\n",
    )
    assert main(["map", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "routes" in output
    assert "/notes" in output


def test_offline_audit_does_not_touch_the_network(monkeypatch, tmp_path, capsys):
    def boom(*_args, **_kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setenv("ATMOROUTER_API_KEY", "ar-test")
    write_source(tmp_path, "app.py", EVAL)
    assert main(["audit", str(tmp_path), "--offline"]) == 0
    assert "skipped (--offline)" in capsys.readouterr().out


def test_cli_audit_uses_triage_and_verify(monkeypatch, tmp_path, capsys):
    class Fake:
        def __init__(self, settings, transport=None):
            self.settings = settings

        def complete(self, *, model, system, user):
            if "verify stage" in system:
                body = json.dumps({"verdict": "confirm", "evidence": "return eval(user)", "reason": "quoted"})
                return Completion(text=body, tokens_in=6, tokens_out=3, model=model)
            body = '{"impact": "from-model", "fix": "from-model-fix"}'
            return Completion(text=body, tokens_in=4, tokens_out=2, model=model)

    monkeypatch.setenv("ATMOROUTER_API_KEY", "ar-test")
    monkeypatch.delenv("AUDITSIFT_API_KEY", raising=False)
    monkeypatch.setattr("auditsift.pipeline.LLMClient", Fake)
    write_source(tmp_path, "app.py", EVAL)
    assert main(["audit", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["verdict"] == "confirmed"
    assert payload["findings"][0]["impact"] == "from-model"
    assert payload["usage"][2]["tokens_in"] == 4
    assert payload["usage"][3]["tokens_out"] == 3


def test_module_help_lists_subcommands():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "auditsift", "--help"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0
    for name in ("map", "scan", "audit", "report", "serve"):
        assert name in proc.stdout


def test_mcp_initialize_list_and_scan(tmp_path):
    init = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        }
    )
    assert init["result"]["serverInfo"]["name"] == "auditsift"
    assert init["result"]["protocolVersion"] == "2024-11-05"
    assert dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [item["name"] for item in tools["result"]["tools"]]
    assert names == ["auditsift_map", "auditsift_scan", "auditsift_audit"]
    write_source(tmp_path, "app.py", EVAL)
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "auditsift_scan", "arguments": {"path": str(tmp_path)}},
        }
    )
    assert response["result"]["isError"] is False
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["findings"][0]["rule_id"] == "AS-EVAL"
    missing = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "auditsift_map", "arguments": {}},
        }
    )
    assert missing["result"]["isError"] is True


def test_mcp_serve_roundtrip():
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26"},
    }
    incoming = json.dumps(message) + "\n"
    from io import StringIO

    outgoing = StringIO()
    serve(StringIO(incoming), outgoing)
    answer = json.loads(outgoing.getvalue().splitlines()[0])
    assert answer["result"]["protocolVersion"] == "2025-03-26"
    assert answer["result"]["capabilities"]["tools"]["listChanged"] is False


def test_render_json_round_trip(tmp_path, settings):
    write_source(tmp_path, "app.py", EVAL)
    report = audit(tmp_path, settings=settings, use_llm=False)
    clone = type(report).from_dict(json.loads(render(report, "json")))
    assert clone.findings[0].rule_id == "AS-EVAL"
    assert clone.usage[0].phase == "map"
