from __future__ import annotations

import json

from auditsift.inventory import build_inventory
from auditsift.pipeline import audit
from tests.conftest import write_source


def test_map_records_routes_manifests_and_languages(tmp_path, settings):
    write_source(
        tmp_path,
        "app.py",
        "\n".join(
            [
                "from flask import Flask",
                "app = Flask(__name__)",
                "@app.route('/notes', methods=['GET', 'POST'])",
                "def notes():",
                "    return []",
                "if __name__ == '__main__':",
                "    app.run()",
                "",
            ]
        ),
    )
    write_source(tmp_path, "requirements.txt", "flask==3.0.3\n")
    write_source(
        tmp_path,
        "server.js",
        'const app = express();\napp.get("/health", (req, res) => res.send("ok"));\napp.listen(3000);\n',
    )
    summary, _files, _root = build_inventory(tmp_path)
    assert summary["languages"]["python"] == 1
    assert summary["languages"]["javascript"] == 1
    kinds = {item["kind"] for item in summary["entry_points"]}
    assert {"flask", "main", "express", "node-listen"} <= kinds
    routes = {(item["method"], item["pattern"]) for item in summary["routes"]}
    assert ("GET,POST", "/notes") in routes
    assert ("GET", "/health") in routes
    assert summary["manifests"] == [{"path": "requirements.txt", "kind": "pip"}]
    report = audit(tmp_path, settings=settings, use_llm=False)
    assert report.inventory["files"] == summary["files"]


def test_map_redacts_secrets_and_skips_example_files(tmp_path):
    secret = "sk-live-" + "map-preview-77"
    write_source(tmp_path, "app.py", f'API_TOKEN = "{secret}"\n')
    write_source(tmp_path, ".env.example", "ATMOROUTER_API_KEY=ar-your-key-here\n")
    summary, _files, _root = build_inventory(tmp_path)
    encoded = json.dumps(summary)
    assert secret not in encoded
    assert summary["secrets"][0]["redacted"]
    assert summary["secrets"][0]["kind"] == "assigned credential"
    assert all(item["path"] != ".env.example" for item in summary["secrets"])


def test_empty_directory_has_an_empty_inventory(tmp_path):
    summary, files, _root = build_inventory(tmp_path)
    assert files == []
    assert summary["files"] == 0
    assert summary["routes"] == []
    assert summary["secrets"] == []
