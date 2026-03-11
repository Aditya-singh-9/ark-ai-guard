"""
Semgrep security scanner runner.
Executes semgrep with the auto ruleset and parses JSON output.
Requires: semgrep installed in the container (pip install semgrep)
"""
import subprocess
import json
import os
from typing import Any
from app.utils.logger import get_logger
from app.utils.config import settings

log = get_logger(__name__)


def _map_severity(semgrep_severity: str) -> str:
    """Normalise Semgrep severity strings to our internal levels."""
    mapping = {
        "ERROR": "critical",
        "WARNING": "high",
        "INFO": "medium",
        "NOTE": "low",
    }
    return mapping.get(semgrep_severity.upper(), "medium")


def run_semgrep(repo_path: str) -> list[dict[str, Any]]:
    """
    Run Semgrep in the cloned repository directory.

    Args:
        repo_path: Absolute path to the cloned repository.

    Returns:
        List of vulnerability dicts:
        {
            "file": str,
            "line": int,
            "issue": str,
            "description": str,
            "severity": str,
            "rule_id": str,
            "code_snippet": str,
            "suggested_fix": str,
            "scanner": "semgrep"
        }
    """
    if not os.path.isdir(repo_path):
        log.error(f"Semgrep: repo path does not exist: {repo_path}")
        return []

    cmd = [
        "semgrep",
        "--config", "auto",
        "--json",
        "--timeout", "120",
        "--max-memory", "1000",
        "--no-error",          # Don't exit 1 on findings
        "--quiet",
        repo_path,
    ]

    log.info(f"Running Semgrep on {repo_path}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.SCAN_TIMEOUT_SECONDS,
            cwd=repo_path,
        )
    except subprocess.TimeoutExpired:
        log.warning("Semgrep timed out — returning partial results")
        return []
    except FileNotFoundError:
        log.warning("Semgrep not installed — skipping semgrep scan")
        return []
    except Exception as exc:
        log.error(f"Semgrep execution error: {exc}")
        return []

    if not result.stdout.strip():
        log.info("Semgrep: no output")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        log.error(f"Semgrep JSON parse error: {exc} — stdout: {result.stdout[:500]}")
        return []

    findings = data.get("results", [])
    log.info(f"Semgrep found {len(findings)} findings")

    vulns = []
    for finding in findings:
        meta = finding.get("extra", {})
        message = meta.get("message", finding.get("check_id", "Unknown issue"))
        metadata = meta.get("metadata", {})
        fix = (
            metadata.get("fix")
            or metadata.get("suggested_fix")
            or metadata.get("references", [""])[0]
            or ""
        )

        vulns.append({
            "file": finding.get("path", "unknown"),
            "line": finding.get("start", {}).get("line"),
            "column": finding.get("start", {}).get("col"),
            "issue": message[:500],
            "description": meta.get("lines", ""),
            "severity": _map_severity(meta.get("severity", "INFO")),
            "rule_id": finding.get("check_id", ""),
            "cwe_id": str(metadata.get("cwe", [""])[0]) if metadata.get("cwe") else None,
            "code_snippet": meta.get("lines", ""),
            "suggested_fix": str(fix)[:1000] if fix else "Review and apply OWASP remediation guidance.",
            "scanner": "semgrep",
        })

    return vulns
