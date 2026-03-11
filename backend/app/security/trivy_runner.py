"""
Trivy security scanner runner.
Scans filesystem for vulnerabilities, secrets, and misconfigurations.
Requires: trivy installed in the container
"""
import subprocess
import json
import os
from typing import Any
from app.utils.logger import get_logger
from app.utils.config import settings

log = get_logger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def run_trivy(repo_path: str) -> list[dict[str, Any]]:
    """
    Run Trivy filesystem scan for vulnerabilities, secrets, and misconfigs.

    Returns:
        List of normalised vulnerability dicts.
    """
    if not os.path.isdir(repo_path):
        log.error(f"Trivy: repo path does not exist: {repo_path}")
        return []

    cmd = [
        "trivy",
        "fs",
        "--format", "json",
        "--security-checks", "vuln,secret,config",
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--no-progress",
        "--timeout", f"{settings.SCAN_TIMEOUT_SECONDS}s",
        "--quiet",
        repo_path,
    ]

    log.info(f"Running Trivy on {repo_path}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.SCAN_TIMEOUT_SECONDS + 30,
            cwd=repo_path,
        )
    except subprocess.TimeoutExpired:
        log.warning("Trivy timed out")
        return []
    except FileNotFoundError:
        log.warning("Trivy not installed — skipping trivy scan")
        return []
    except Exception as exc:
        log.error(f"Trivy execution error: {exc}")
        return []

    output = result.stdout.strip()
    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        log.error(f"Trivy JSON parse error: {exc}")
        return []

    results_list = data if isinstance(data, list) else data.get("Results", [])
    log.info(f"Trivy returned {len(results_list)} result sets")

    vulns: list[dict] = []

    for result_set in results_list:
        target = result_set.get("Target", "unknown")

        # ── OS/library vulnerabilities ────────────────────────────────────
        for vuln in result_set.get("Vulnerabilities") or []:
            severity_raw = vuln.get("Severity", "UNKNOWN")
            severity = SEVERITY_MAP.get(severity_raw.upper(), "low")
            fixed = vuln.get("FixedVersion", "")
            installed = vuln.get("InstalledVersion", "")
            pkg = vuln.get("PkgName", "")
            cve = vuln.get("VulnerabilityID", "")
            title = vuln.get("Title") or vuln.get("Description") or f"{cve} in {pkg}"

            vulns.append({
                "file": target,
                "line": None,
                "column": None,
                "issue": f"Vulnerable dependency: {pkg}@{installed} — {title[:300]}",
                "description": vuln.get("Description", "")[:1000],
                "severity": severity,
                "rule_id": cve,
                "cwe_id": None,
                "cve_id": cve,
                "code_snippet": None,
                "suggested_fix": (
                    f"Upgrade {pkg} from {installed} to {fixed}"
                    if fixed else f"No fixed version available — monitor {cve}"
                ),
                "package_name": pkg,
                "package_version": installed,
                "fixed_version": fixed or None,
                "scanner": "trivy",
            })

        # ── Secret detection ──────────────────────────────────────────────
        for secret in result_set.get("Secrets") or []:
            severity_raw = secret.get("Severity", "HIGH")
            vulns.append({
                "file": target,
                "line": secret.get("StartLine"),
                "column": None,
                "issue": f"Exposed secret detected: {secret.get('Title', 'Secret')}",
                "description": secret.get("Match", ""),
                "severity": SEVERITY_MAP.get(severity_raw.upper(), "high"),
                "rule_id": secret.get("RuleID", ""),
                "cwe_id": "CWE-798",
                "cve_id": None,
                "code_snippet": secret.get("Match", ""),
                "suggested_fix": "Remove the secret from source code. Rotate credentials immediately. Use environment variables or a secrets manager.",
                "scanner": "trivy",
            })

        # ── Misconfigurations ─────────────────────────────────────────────
        for misconfig in result_set.get("Misconfigurations") or []:
            severity_raw = misconfig.get("Severity", "MEDIUM")
            vulns.append({
                "file": target,
                "line": None,
                "column": None,
                "issue": misconfig.get("Title", "Misconfiguration detected"),
                "description": misconfig.get("Description", ""),
                "severity": SEVERITY_MAP.get(severity_raw.upper(), "medium"),
                "rule_id": misconfig.get("ID", ""),
                "cwe_id": None,
                "cve_id": None,
                "code_snippet": None,
                "suggested_fix": misconfig.get("Resolution", "Review and apply security best practices."),
                "scanner": "trivy",
            })

    log.info(f"Trivy extracted {len(vulns)} total findings")
    return vulns
