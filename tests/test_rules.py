"""Offline rules: each vulnerable pattern fires, and the safe counterpart does not."""

from __future__ import annotations

from auditsift.pipeline import audit
from tests.conftest import write_source


def _ids(tmp_path, settings, name, text):
    write_source(tmp_path, name, text)
    report = audit(tmp_path, settings=settings, use_llm=False)
    return report, {item.rule_id for item in report.findings}


def test_assigned_secret_and_redaction(tmp_path, settings):
    value = "sk-live-" + "fieldnotes-demo-7Q"
    report, found = _ids(tmp_path, settings, "app.py", f'API_TOKEN = "{value}"\n')
    assert "AS-SECRET" in found
    blob = report.findings[0].snippet
    assert value not in blob
    assert "…" in blob


def test_aws_key_detected_and_example_key_ignored(tmp_path, settings):
    live = "AKIA" + "1234567890ABCDEF"
    write_source(tmp_path, "live.py", f'KEY = "{live}"\n')
    write_source(tmp_path, "fake.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    report = audit(tmp_path, settings=settings, use_llm=False)
    hits = [item for item in report.findings if item.rule_id == "AS-SECRET"]
    assert len(hits) == 1
    assert hits[0].path.endswith("live.py")
    assert live not in hits[0].snippet


def test_placeholder_secret_is_ignored(tmp_path, settings):
    _report, found = _ids(tmp_path, settings, "app.py", 'API_TOKEN = "ar-your-key-here"\n')
    assert "AS-SECRET" not in found


def test_secret_in_a_comment_is_still_a_secret(tmp_path, settings):
    value = "sk-live-" + "commented-token-99"
    _report, found = _ids(tmp_path, settings, "app.py", f'# API_TOKEN = "{value}"\n')
    assert "AS-SECRET" in found


def test_env_lookup_is_not_a_hardcoded_secret(tmp_path, settings):
    text = 'import os\nAPI_TOKEN = os.environ["API_TOKEN"]\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SECRET" not in found


def test_sqli_fstring_detected(tmp_path, settings):
    text = "def list_notes(owner):\n    query = f\"SELECT id FROM notes WHERE owner = '{owner}'\"\n"
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SQLI" in found


def test_parameterized_sql_is_ignored(tmp_path, settings):
    text = (
        "def list_notes(db, owner):\n"
        '    query = "SELECT id, body FROM notes WHERE owner = ?"\n'
        "    return db.execute(query, (owner,)).fetchall()\n"
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SQLI" not in found


def test_sql_concatenation_detected(tmp_path, settings):
    text = 'query = "SELECT id FROM notes WHERE owner = \'" + owner + "\'"\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SQLI" in found


def test_sql_comment_is_ignored(tmp_path, settings):
    text = "# query = f\"SELECT id FROM notes WHERE owner = '{owner}'\"\n"
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SQLI" not in found


def test_dynamic_shell_detected(tmp_path, settings):
    text = (
        "def convert():\n"
        '    filename = request.form.get("filename", "")\n'
        '    subprocess.run(f"convert {filename} out.pdf", shell=True)\n'
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SHELL" in found


def test_static_shell_is_ignored(tmp_path, settings):
    text = 'def convert():\n    subprocess.run("date", shell=True)\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SHELL" not in found


def test_multiline_shell_with_tainted_command(tmp_path, settings):
    text = (
        'def run():\n    cmd = request.args.get("cmd")\n    subprocess.run(\n        cmd,\n        shell=True,\n    )\n'
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SHELL" in found


def test_unrelated_fstring_does_not_make_static_shell_dynamic(tmp_path, settings):
    text = 'def run(name):\n    msg = f"hello {name}"\n    subprocess.run("date", shell=True)\n    return msg\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SHELL" not in found


def test_os_system_with_request_data(tmp_path, settings):
    text = 'def run():\n    os.system(request.args.get("cmd"))\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-SHELL" in found


def test_eval_and_exec_detected(tmp_path, settings):
    text = "def run(user):\n    exec(user)\n    return eval(user)\n"
    report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-EVAL" in found
    assert len([item for item in report.findings if item.rule_id == "AS-EVAL"]) == 2


def test_model_eval_and_literal_eval_are_ignored(tmp_path, settings):
    text = "def activate(model, text):\n    model.eval()\n    return ast.literal_eval(text)\n"
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-EVAL" not in found


def test_eval_inside_a_string_is_ignored(tmp_path, settings):
    text = 'def note():\n    return "do not eval(this)"\n'
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-EVAL" not in found


def test_pickle_and_unsafe_yaml(tmp_path, settings):
    text = (
        "def load(blob, spec):\n"
        "    first = pickle.loads(blob)\n"
        "    second = yaml.load(spec, Loader=yaml.Loader)\n"
        "    return first, second\n"
    )
    report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-DESER" in found
    assert len([item for item in report.findings if item.rule_id == "AS-DESER"]) == 2


def test_safe_yaml_loaders_are_ignored(tmp_path, settings):
    text = (
        "def load(spec):\n"
        "    return yaml.safe_load(spec)\n"
        "def load_more(spec):\n"
        "    return yaml.load(spec, Loader=yaml.SafeLoader)\n"
        "def load_block(spec):\n"
        "    return yaml.load(\n"
        "        spec,\n"
        "        Loader=yaml.SafeLoader,\n"
        "    )\n"
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-DESER" not in found


def test_commented_pickle_is_ignored(tmp_path, settings):
    text = "def load(blob):\n    # pickle.loads(blob)\n    return blob\n"
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-DESER" not in found


def test_md5_password_is_high_and_checksum_opt_out_is_clean(tmp_path, settings):
    bad = (
        "def login():\n"
        '    password = request.form.get("password", "")\n'
        "    return hashlib.md5(password.encode()).hexdigest()\n"
    )
    good = "def checksum(data):\n    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n"
    modern = "def digest(data):\n    return hashlib.sha256(data).hexdigest()\n"
    write_source(tmp_path, "bad.py", bad)
    write_source(tmp_path, "good.py", good)
    write_source(tmp_path, "modern.py", modern)
    report = audit(tmp_path, settings=settings, use_llm=False)
    crypto = [item for item in report.findings if item.rule_id == "AS-CRYPTO"]
    assert len(crypto) == 1
    assert crypto[0].severity == "high"
    assert crypto[0].path.endswith("bad.py")


def test_md5_without_password_is_medium(tmp_path, settings):
    text = "def digest(data):\n    return hashlib.md5(data).hexdigest()\n"
    report, found = _ids(tmp_path, settings, "app.py", text)
    assert found == {"AS-CRYPTO"}
    assert report.findings[0].severity == "medium"


def test_tls_verification_disabled(tmp_path, settings):
    text = 'def fetch():\n    return requests.get("https://example.com", verify=False)\n'
    report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-TLS" in found
    assert "AS-SSRF" not in found
    assert report.findings[0].fix


def test_path_traversal_from_route_param(tmp_path, settings):
    text = (
        '@app.route("/files/<path:name>")\n'
        "def download(name):\n"
        '    return send_file(os.path.join("/var/fieldnotes", name))\n'
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-PATH" in found


def test_path_traversal_from_assignment(tmp_path, settings):
    text = (
        "def export_note():\n"
        '    name = request.args.get("name")\n'
        '    return send_file(os.path.join("/var/notes", name))\n'
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-PATH" in found


def test_static_open_and_cleared_taint_are_ignored(tmp_path, settings):
    text = (
        "def read_config():\n"
        '    return open("config.json").read()\n'
        "def export_note():\n"
        '    name = request.args.get("name")\n'
        '    name = "readme.txt"\n'
        "    return send_file(name)\n"
    )
    _report, found = _ids(tmp_path, settings, "app.py", text)
    assert "AS-PATH" not in found


def test_cors_star_detected_and_specific_origin_ignored(tmp_path, settings):
    bad = 'CORS(app, resources={r"/*": {"origins": "*"}}) \n'
    good = 'CORS(app, resources={r"/api/*": {"origins": "https://notes.example"}})\n'
    write_source(tmp_path, "bad.py", bad)
    write_source(tmp_path, "good.py", good)
    report = audit(tmp_path, settings=settings, use_llm=False)
    hits = [item for item in report.findings if item.rule_id == "AS-CORS"]
    assert len(hits) == 1
    assert hits[0].path.endswith("bad.py")
    assert hits[0].severity == "medium"


def test_ssrf_requires_external_input(tmp_path, settings):
    bad = 'def preview():\n    target = request.args.get("url", "")\n    return requests.get(target, timeout=5)\n'
    good = 'def preview():\n    return requests.get("https://example.com", timeout=5)\n'
    write_source(tmp_path, "bad.py", bad)
    write_source(tmp_path, "good.py", good)
    report = audit(tmp_path, settings=settings, use_llm=False)
    hits = [item for item in report.findings if item.rule_id == "AS-SSRF"]
    assert len(hits) == 1
    assert hits[0].path.endswith("bad.py")


def test_debug_flag_detected_and_comment_ignored(tmp_path, settings):
    text = "def main():\n    # app.run(debug=True)\n    app.run(debug=True)\n"
    report, found = _ids(tmp_path, settings, "app.py", text)
    assert found == {"AS-DEBUG"}
    assert report.findings[0].severity == "low"


def test_venv_and_node_modules_are_skipped(tmp_path, settings):
    write_source(tmp_path / ".venv" / "lib", "bad.py", "def run(user):\n    return eval(user)\n")
    write_source(tmp_path / "node_modules" / "pkg", "bad.js", "eval(user)\n")
    write_source(tmp_path, "ok.py", "def ok():\n    return 1\n")
    report = audit(tmp_path, settings=settings, use_llm=False)
    assert report.findings == []


def test_offline_findings_include_a_fix(tmp_path, settings):
    _report, _found = _ids(tmp_path, settings, "app.py", "def run(user):\n    return eval(user)\n")
    report = audit(tmp_path, settings=settings, use_llm=False)
    assert report.findings[0].fix
    assert report.findings[0].impact
    assert report.findings[0].verdict == "unverified"
