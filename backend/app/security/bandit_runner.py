"""
Bandit security scanner runner.
Analyses Python code for common security issues.
Requires: bandit installed (pip install bandit)
"""
import subprocess
import json
import os
from typing import Any
from app.utils.logger import get_logger
from app.utils.config import settings

log = get_logger(__name__)


def _map_severity(bandit_severity: str | None) -> str:
    mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return mapping.get((bandit_severity or "").upper(), "low")


def _has_python_files(repo_path: str) -> bool:
    """Check if the repository contains any Python source files."""
    for root, _dirs, files in os.walk(repo_path):
        # Skip hidden dirs and common non-source dirs
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}
        _dirs[:] = [d for d in _dirs if d not in skip]
        for f in files:
            if f.endswith(".py"):
                return True
    return False


def run_bandit(repo_path: str) -> list[dict[str, Any]]:
    """
    Run Bandit on Python files in the given repository.

    Returns:
        List of vulnerability dicts compatible with our schema.
    """
    if not os.path.isdir(repo_path):
        log.error(f"Bandit: repo path does not exist: {repo_path}")
        return []

    if not _has_python_files(repo_path):
        log.info("Bandit: no Python files found — skipping bandit scan")
        return []

    cmd = [
        "bandit",
        "-r", repo_path,
        "-f", "json",
        "-ll",              # Only medium and above
        "--quiet",
        "--exclude", ".git,node_modules,venv,.venv,__pycache__",
    ]

    log.info(f"Running Bandit on {repo_path}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.SCAN_TIMEOUT_SECONDS,
            cwd=repo_path,
        )
    except subprocess.TimeoutExpired:
        log.warning("Bandit timed out")
        return []
    except FileNotFoundError:
        log.warning("Bandit not installed — skipping bandit scan")
        return []
    except Exception as exc:
        log.error(f"Bandit execution error: {exc}")
        return []

    output = result.stdout.strip()
    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        log.error(f"Bandit JSON parse error: {exc}")
        return []

    results = data.get("results", [])
    log.info(f"Bandit found {len(results)} findings")

    vulns = []
    for r in results:
        cwe = r.get("issue_cwe", {})
        vulns.append({
            "file": r.get("filename", "unknown").replace(repo_path, "").lstrip("/\\"),
            "line": r.get("line_number"),
            "column": None,
            "issue": r.get("issue_text", "Security issue detected"),
            "description": f"Test: {r.get('test_name', '')} | Confidence: {r.get('issue_confidence', '')}",
            "severity": _map_severity(r.get("issue_severity")),
            "rule_id": r.get("test_id", ""),
            "cwe_id": f"CWE-{cwe.get('id')}" if cwe else None,
            "code_snippet": r.get("code", ""),
            "suggested_fix": (
                f"See Bandit test {r.get('test_name')}: "
                f"{r.get('more_info', 'https://bandit.readthedocs.io/')}"
            ),
            "scanner": "bandit",
        })

    return vulns
