"""
ARK Nexus Engine — External Scanner Bridge

Runs the industry-standard scanners (Semgrep, Bandit, Trivy) and converts their
output into the unified NexusFinding schema so they merge seamlessly with the
native layers, get deduplicated, and flow into Layer 7 AI fusion + scoring.

Each scanner degrades gracefully: if the binary isn't installed, its runner
returns an empty list and the scan continues with whatever is available.
"""
from __future__ import annotations

from typing import Any, Optional

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.security.semgrep_runner import run_semgrep
from app.security.bandit_runner import run_bandit
from app.security.trivy_runner import run_trivy
from app.utils.logger import get_logger

log = get_logger(__name__)


# Confidence priors per scanner — these are mature, well-tested tools, so we
# trust them more than broad regex matches (which default to ~0.8).
_SCANNER_CONFIDENCE = {
    "semgrep": 0.88,
    "bandit": 0.82,
    "trivy": 0.92,   # CVE/dependency data is authoritative
}

# Exploitability prior derived from severity when the scanner gives no signal.
_SEVERITY_EXPLOIT = {
    NexusSeverity.CRITICAL: 0.85,
    NexusSeverity.HIGH: 0.65,
    NexusSeverity.MEDIUM: 0.40,
    NexusSeverity.LOW: 0.20,
    NexusSeverity.INFO: 0.05,
}


def _to_severity(value: str | None) -> NexusSeverity:
    try:
        return NexusSeverity((value or "medium").lower())
    except ValueError:
        return NexusSeverity.MEDIUM


def _layer_for(scanner: str, finding: dict[str, Any]) -> NexusLayer:
    """Map an external finding to the most appropriate native layer."""
    if scanner == "trivy":
        if finding.get("package_name"):
            return NexusLayer.DEPS          # vulnerable dependency
        if finding.get("cwe_id") == "CWE-798":
            return NexusLayer.SURFACE        # exposed secret
        return NexusLayer.IAC                # misconfiguration
    # semgrep + bandit are code-level static analysis
    return NexusLayer.SEMANTIC


def _convert(scanner: str, raw: list[dict[str, Any]]) -> list[NexusFinding]:
    findings: list[NexusFinding] = []
    for item in raw:
        severity = _to_severity(item.get("severity"))
        rule_id = item.get("rule_id") or ""
        # Namespace the rule id so it's clear where it came from and dedup is stable.
        prefixed_rule = rule_id if rule_id.startswith(scanner) else f"{scanner}/{rule_id}"

        findings.append(NexusFinding(
            layer=_layer_for(scanner, item),
            rule_id=prefixed_rule,
            issue=(item.get("issue") or "Security issue")[:500],
            description=(item.get("description") or "")[:2000],
            file=item.get("file") or "",
            line=item.get("line") or 0,
            column=item.get("column") or 0,
            code_snippet=(item.get("code_snippet") or "")[:2000],
            severity=severity,
            cwe_id=item.get("cwe_id") or "",
            cve_id=item.get("cve_id") or "",
            confidence=_SCANNER_CONFIDENCE.get(scanner, 0.8),
            exploitability=_SEVERITY_EXPLOIT.get(severity, 0.4),
            suggested_fix=(item.get("suggested_fix") or "")[:2000],
            package_name=item.get("package_name") or "",
            package_version=item.get("package_version") or "",
            fixed_version=item.get("fixed_version") or "",
            scanner=scanner,
        ))
    return findings


def run_semgrep_layer(repo_path: str, file_map: Optional[Any] = None) -> list[NexusFinding]:
    """Run Semgrep and convert to NexusFinding (no-op if not installed)."""
    try:
        return _convert("semgrep", run_semgrep(repo_path))
    except Exception as exc:
        log.warning(f"[External] Semgrep bridge error: {exc}")
        return []


def run_bandit_layer(repo_path: str, file_map: Optional[Any] = None) -> list[NexusFinding]:
    """Run Bandit and convert to NexusFinding (no-op if no Python / not installed)."""
    try:
        return _convert("bandit", run_bandit(repo_path))
    except Exception as exc:
        log.warning(f"[External] Bandit bridge error: {exc}")
        return []


def run_trivy_layer(repo_path: str, file_map: Optional[Any] = None) -> list[NexusFinding]:
    """Run Trivy and convert to NexusFinding (no-op if not installed)."""
    try:
        return _convert("trivy", run_trivy(repo_path))
    except Exception as exc:
        log.warning(f"[External] Trivy bridge error: {exc}")
        return []
