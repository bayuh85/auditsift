from __future__ import annotations

import os
import subprocess

from auditsift.diffutil import parse_unified_diff
from auditsift.pipeline import audit
from tests.conftest import write_source


def test_parse_added_and_replaced_lines():
    text = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -3 +3 @@
-return 1
+return eval(user)
@@ -10,0 +11,2 @@
+import os
+exec(code)
"""
    changed = parse_unified_diff(text)
    assert changed["app.py"] == {3, 11, 12}


def test_parse_new_file_and_ignore_deletion():
    text = """diff --git a/new.py b/new.py
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+import os
+eval(user)
diff --git a/old.py b/old.py
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-eval(user)
"""
    changed = parse_unified_diff(text)
    assert changed["new.py"] == {1, 2}
    assert "old.py" not in changed


def test_diff_filter_drops_unchanged_vulnerable_lines(tmp_path, settings):
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Dev",
            "GIT_AUTHOR_EMAIL": "dev@example.com",
            "GIT_COMMITTER_NAME": "Dev",
            "GIT_COMMITTER_EMAIL": "dev@example.com",
        }
    )
    subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
    write_source(tmp_path, "app.py", "def run(user):\n    return eval(user)\n")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True, capture_output=True, env=env)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env=env,
    )
    write_source(tmp_path, "app.py", "# touched\ndef run(user):\n    return eval(user)\n")
    report = audit(tmp_path, diff="HEAD", settings=settings, use_llm=False)
    assert not any(item.rule_id == "AS-EVAL" for item in report.findings)
    assert any("diff HEAD" in note for note in report.notes)

    write_source(tmp_path, "app.py", "def run(user):\n    return eval(user + ' ')\n")
    changed = audit(tmp_path, diff="HEAD", settings=settings, use_llm=False)
    assert any(item.rule_id == "AS-EVAL" for item in changed.findings)


def test_untracked_file_is_included_in_diff_mode(tmp_path, settings):
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Dev",
            "GIT_AUTHOR_EMAIL": "dev@example.com",
            "GIT_COMMITTER_NAME": "Dev",
            "GIT_COMMITTER_EMAIL": "dev@example.com",
        }
    )
    subprocess.run(["git", "init", "-b", "main"], cwd=tmp_path, check=True, capture_output=True)
    write_source(tmp_path, "keep.py", "def ok():\n    return 1\n")
    subprocess.run(["git", "add", "keep.py"], cwd=tmp_path, check=True, capture_output=True, env=env)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env=env,
    )
    write_source(tmp_path, "new.py", "def run(user):\n    return eval(user)\n")
    report = audit(tmp_path, diff="HEAD", settings=settings, use_llm=False)
    assert any(item.path.endswith("new.py") and item.rule_id == "AS-EVAL" for item in report.findings)
