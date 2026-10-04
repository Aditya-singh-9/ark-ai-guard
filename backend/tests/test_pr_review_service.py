"""Unit tests for the PR review bot's diff parsing and finding selection."""
from types import SimpleNamespace

from app.services.pr_review_service import (
    parse_added_lines,
    select_pr_findings,
    _build_summary,
    _inline_body,
    INLINE_MARKER_PREFIX,
    SUMMARY_MARKER,
)

PATCH = """@@ -1,4 +1,5 @@
 import os
-password = "old"
+password = "hunter2"
+query = f"SELECT * FROM users WHERE id={uid}"
 def main():
     pass
@@ -20,2 +21,3 @@ def other():
     x = 1
+    eval(user_input)
     return x
\\ No newline at end of file"""


def _v(file, line, sev="high", fp=0.1, rule="r1"):
    return SimpleNamespace(
        file_path=file, line_number=line, severity=SimpleNamespace(value=sev),
        false_positive_probability=fp, rule_id=rule, issue=f"{rule} issue",
        cwe_id="CWE-89", cve_id=None, confidence=0.9, ai_summary=None,
        description="desc", suggested_fix="use params",
    )


def test_parse_added_lines_tracks_new_file_numbers():
    assert parse_added_lines(PATCH) == {2, 3, 22}


def test_parse_added_lines_handles_empty():
    assert parse_added_lines(None) == set()
    assert parse_added_lines("") == set()


def test_select_splits_introduced_vs_touched_and_drops_noise():
    changed = {"app/db.py": {2, 3, 22}, ".github/workflows/ci.yml": {5}}
    vulns = [
        _v("app/db.py", 3, "critical"),          # introduced
        _v("app/db.py", 10, "high"),             # touched (pre-existing)
        _v("app/db.py", 22, "low", fp=0.9),      # likely false positive -> dropped
        _v("other.py", 3, "critical"),           # file not in PR -> ignored
        _v("./.github/workflows/ci.yml", 5, "medium"),  # path normalised, keeps leading dot
    ]
    introduced, touched = select_pr_findings(vulns, changed)
    assert [(v.file_path, v.line_number) for v in introduced] == [
        ("app/db.py", 3), ("./.github/workflows/ci.yml", 5)
    ]
    assert [(v.file_path, v.line_number) for v in touched] == [("app/db.py", 10)]


def test_inline_body_contains_dedup_marker():
    body = _inline_body(_v("a.py", 7, rule="sqli"))
    assert f"{INLINE_MARKER_PREFIX}sqli:a.py:7 -->" in body
    assert "CRITICAL" not in body and "HIGH" in body


def test_summary_has_marker_and_counts():
    report = SimpleNamespace(
        nexus_score=72.0, security_score=None, critical_count=1, high_count=4,
        medium_count=2, low_count=0, commit_sha="abcdef1234", duration_seconds=12,
    )
    s = _build_summary(report, [_v("a.py", 1, "critical")], [], 1, "https://x/report", passed=False)
    assert s.startswith(SUMMARY_MARKER)
    assert "| 🔴 Critical | **1** | 1 |" in s
    assert "[Full report](https://x/report)" in s
