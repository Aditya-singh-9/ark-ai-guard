"""
ARK Policy-as-Code Engine — Define security gates in YAML.

Allows teams to define security policies that block or warn deployments.
Policies are evaluated against scan results to enforce security standards.

Example policy file (ark-policy.yml):
  policies:
    - name: "No critical vulnerabilities"
      condition: critical_count == 0
      action: block
      message: "Cannot deploy with critical vulnerabilities"

    - name: "Minimum security score"
      condition: nexus_score >= 80
      action: warn
      message: "Security score below threshold"

    - name: "No hardcoded secrets"
      condition: secret_count == 0
      action: block
      message: "Hardcoded secrets detected — rotate and remove"
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum

from app.utils.logger import get_logger

log = get_logger(__name__)


class PolicyAction(str, Enum):
    BLOCK = "block"     # Fail the CI/CD gate
    WARN = "warn"       # Allow but flag warning
    NOTIFY = "notify"   # Just send notification


@dataclass
class PolicyRule:
    """A single security policy rule."""
    name: str
    condition: str
    action: PolicyAction
    message: str = ""
    enabled: bool = True


@dataclass
class PolicyViolation:
    """A policy rule that was violated."""
    rule_name: str
    action: PolicyAction
    message: str
    actual_value: Any
    condition: str


@dataclass
class PolicyResult:
    """Result of evaluating all policies against a scan."""
    passed: bool = True
    total_rules: int = 0
    passed_rules: int = 0
    violations: list[PolicyViolation] = field(default_factory=list)
    warnings: list[PolicyViolation] = field(default_factory=list)
    gate_status: str = "pass"  # "pass", "warn", "block"


# ── Default Security Policies ─────────────────────────────────────────────────
# These are the built-in policies that apply to all scans.
# Teams can customize via YAML config.

DEFAULT_POLICIES: list[dict[str, Any]] = [
    {
        "name": "No Critical Vulnerabilities",
        "condition": "critical_count == 0",
        "action": "block",
        "message": "Deployment blocked: critical vulnerabilities detected. Fix them before deploying.",
    },
    {
        "name": "Minimum Security Score",
        "condition": "nexus_score >= 70",
        "action": "warn",
        "message": "Security score is below the recommended threshold of 70.",
    },
    {
        "name": "High Vulnerability Limit",
        "condition": "high_count <= 5",
        "action": "warn",
        "message": "More than 5 high-severity vulnerabilities detected.",
    },
    {
        "name": "No Hardcoded Secrets",
        "condition": "secret_count == 0",
        "action": "block",
        "message": "Hardcoded secrets detected — rotate immediately and remove from code.",
    },
    {
        "name": "No Known CVEs",
        "condition": "cve_count <= 3",
        "action": "warn",
        "message": "Known CVEs detected in dependencies — update to patched versions.",
    },
    {
        "name": "Attack Chain Alert",
        "condition": "attack_chain_count == 0",
        "action": "warn",
        "message": "Multi-step attack chain detected — combination of vulnerabilities increases risk.",
    },
    {
        "name": "Compliance Check",
        "condition": "compliance_violations == 0",
        "action": "notify",
        "message": "Compliance framework violations detected — review before audit.",
    },
]


def parse_policies(policy_config: list[dict[str, Any]]) -> list[PolicyRule]:
    """Parse policy configuration into PolicyRule objects."""
    rules: list[PolicyRule] = []
    for cfg in policy_config:
        try:
            rules.append(PolicyRule(
                name=cfg.get("name", "Unnamed Policy"),
                condition=cfg.get("condition", "True"),
                action=PolicyAction(cfg.get("action", "warn").lower()),
                message=cfg.get("message", ""),
                enabled=cfg.get("enabled", True),
            ))
        except (ValueError, KeyError) as exc:
            log.warning(f"[Policy] Invalid policy rule: {exc}")
    return rules


def evaluate_policies(
    scan_data: dict[str, Any],
    custom_policies: list[dict[str, Any]] | None = None,
) -> PolicyResult:
    """
    Evaluate security policies against scan results.

    Args:
        scan_data: Dict with scan metrics:
            - critical_count, high_count, medium_count, low_count
            - nexus_score, security_score
            - total_vulns, secret_count, cve_count
            - attack_chain_count, compliance_violations
        custom_policies: Optional custom policies (overrides defaults if provided)

    Returns:
        PolicyResult with pass/fail status and violations
    """
    policies = parse_policies(custom_policies or DEFAULT_POLICIES)
    result = PolicyResult(total_rules=len(policies))

    for rule in policies:
        if not rule.enabled:
            result.passed_rules += 1
            continue

        try:
            # Safely evaluate the condition against scan data
            passed = _safe_eval(rule.condition, scan_data)

            if passed:
                result.passed_rules += 1
            else:
                violation = PolicyViolation(
                    rule_name=rule.name,
                    action=rule.action,
                    message=rule.message,
                    actual_value=_get_actual_value(rule.condition, scan_data),
                    condition=rule.condition,
                )

                if rule.action == PolicyAction.BLOCK:
                    result.violations.append(violation)
                    result.passed = False
                    result.gate_status = "block"
                elif rule.action == PolicyAction.WARN:
                    result.warnings.append(violation)
                    if result.gate_status != "block":
                        result.gate_status = "warn"
                else:  # NOTIFY
                    result.warnings.append(violation)

        except Exception as exc:
            log.warning(f"[Policy] Error evaluating '{rule.name}': {exc}")
            result.passed_rules += 1  # Don't block on eval errors

    log.info(
        f"[Policy] Evaluated {result.total_rules} rules — "
        f"Gate: {result.gate_status}, Violations: {len(result.violations)}, "
        f"Warnings: {len(result.warnings)}"
    )
    return result


def _safe_eval(condition: str, data: dict[str, Any]) -> bool:
    """
    Safely evaluate a policy condition.
    Only supports simple comparisons: ==, !=, <, <=, >, >=
    No arbitrary code execution.
    """
    # Parse condition: "variable operator value"
    match = re.match(
        r'(\w+)\s*(==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)?)',
        condition.strip()
    )
    if not match:
        log.warning(f"[Policy] Cannot parse condition: {condition}")
        return True  # Don't block on unparseable conditions

    var_name, operator, value_str = match.groups()
    actual = float(data.get(var_name, 0))
    expected = float(value_str)

    ops = {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        "<":  lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">":  lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
    }

    return ops[operator](actual, expected)


def _get_actual_value(condition: str, data: dict[str, Any]) -> Any:
    """Extract the actual value of the variable in a condition."""
    match = re.match(r'(\w+)', condition.strip())
    if match:
        return data.get(match.group(1), "unknown")
    return "unknown"


def build_scan_policy_data(
    scan_report: Any,
    mythos_report: Any | None = None,
) -> dict[str, Any]:
    """
    Build the scan_data dict that policies are evaluated against.
    Takes a ScanReport and optional MythosReport.
    """
    data = {
        "critical_count": getattr(scan_report, "critical_count", 0) or 0,
        "high_count": getattr(scan_report, "high_count", 0) or 0,
        "medium_count": getattr(scan_report, "medium_count", 0) or 0,
        "low_count": getattr(scan_report, "low_count", 0) or 0,
        "total_vulns": getattr(scan_report, "total_vulnerabilities", 0) or 0,
        "nexus_score": getattr(scan_report, "nexus_score", 0) or 0,
        "security_score": getattr(scan_report, "security_score", 0) or 0,
        "secret_count": 0,
        "cve_count": 0,
        "attack_chain_count": 0,
        "compliance_violations": 0,
    }

    if mythos_report:
        data["attack_chain_count"] = sum(
            1 for a in getattr(mythos_report, "analyses", [])
            if hasattr(a, "attack_chain_probability") and a.attack_chain_probability > 0.5
        )

        # Count compliance violations
        summary = getattr(mythos_report, "compliance_summary", {})
        data["compliance_violations"] = sum(
            s.get("violated_controls", 0)
            for s in summary.values()
        )

    return data
