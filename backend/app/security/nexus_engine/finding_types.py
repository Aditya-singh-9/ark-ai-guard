"""
ARK Nexus Engine — Typed finding dataclasses and CWE/CVSS mapping.

All 7 layers produce NexusFinding instances, ensuring a consistent schema
across the entire engine.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NexusSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class NexusLayer(int, Enum):
    SURFACE   = 1
    SEMANTIC  = 2
    CRYPTO    = 3
    DEPS      = 4
    DATAFLOW  = 5
    IAC       = 6
    AI_FUSION = 7


# ── CWE lookup table ──────────────────────────────────────────────────────────
CWE_MAP: dict[str, str] = {
    # Injection
    "sql-injection":         "CWE-89",
    "command-injection":     "CWE-78",
    "template-injection":    "CWE-94",
    "ldap-injection":        "CWE-90",
    "xpath-injection":       "CWE-643",
    # XSS
    "xss":                   "CWE-79",
    "dom-xss":               "CWE-79",
    "reflected-xss":         "CWE-79",
    # Auth / Secrets
    "hardcoded-secret":      "CWE-798",
    "hardcoded-credential":  "CWE-259",
    "jwt-none-algorithm":    "CWE-347",
    "jwt-no-verify":         "CWE-347",
    "broken-auth":           "CWE-287",
    # Crypto
    "weak-hash":             "CWE-327",
    "insecure-random":       "CWE-330",
    "ecb-mode":              "CWE-327",
    "timing-oracle":         "CWE-208",
    "high-entropy-string":   "CWE-798",
    # Deserialization
    "insecure-deserialization": "CWE-502",
    "pickle-rce":            "CWE-502",
    # Path / File
    "path-traversal":        "CWE-22",
    "open-redirect":         "CWE-601",
    # Request
    "ssrf":                  "CWE-918",
    "csrf":                  "CWE-352",
    # Network / IaC
    "cors-wildcard":         "CWE-942",
    "ssl-disabled":          "CWE-295",
    "iac-priv-escalation":   "CWE-269",
    "container-escape":      "CWE-284",
    # Supply chain
    "typosquat":             "CWE-1357",
    "vulnerable-dependency": "CWE-1035",
    # Data flow
    "taint-source-to-sink":  "CWE-20",
    # General
    "debug-mode":            "CWE-489",
    "info-disclosure":       "CWE-200",
}


# ── Severity → base exploitability weight ─────────────────────────────────────
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.00,
    "high":     0.70,
    "medium":   0.40,
    "low":      0.15,
    "info":     0.05,
}


@dataclass
class NexusFinding:
    """Universal finding produced by any Nexus Engine layer."""

    # Identity
    layer: NexusLayer
    rule_id: str                        # e.g. "nexus/l2/taint-sqli"
    issue: str                          # Human-readable title
    description: str

    # Location
    file: str                           # Relative path inside repo
    line: int = 0
    column: int = 0
    code_snippet: str = ""

    # Classification
    severity: NexusSeverity = NexusSeverity.MEDIUM
    cwe_id: str = ""                    # Auto-resolved from rule_id if blank
    cve_id: str = ""

    # Scoring metadata (used for Nexus Score calculation)
    confidence: float = 0.8            # 0–1, how certain we are
    exploitability: float = 0.5        # 0–1, likelihood of real exploit
    blast_radius: int = 1              # # of services/users potentially impacted

    # Remediation
    suggested_fix: str = ""

    # Dependency-specific (Layer 4)
    package_name: str = ""
    package_version: str = ""
    fixed_version: str = ""

    # AI augmentation (set by Layer 7)
    ai_summary: str = ""
    false_positive_probability: float = 0.0  # 0–1, higher = more likely FP

    # Misc
    scanner: str = "nexus"

    def __post_init__(self) -> None:
        if not self.cwe_id:
            for key, cwe in CWE_MAP.items():
                if key in self.rule_id.lower() or key in self.issue.lower():
                    self.cwe_id = cwe
                    break

    def to_dict(self) -> dict:
        return {
            "layer_id":     self.layer.value,
            "rule_id":      self.rule_id,
            "issue":        self.issue,
            "description":  self.description,
            "file":         self.file,
            "line":         self.line,
            "column":       self.column,
            "code_snippet": self.code_snippet,
            "severity":     self.severity.value,
            "cwe_id":       self.cwe_id,
            "cve_id":       self.cve_id,
            "confidence":   self.confidence,
            "exploitability": self.exploitability,
            "blast_radius": self.blast_radius,
            "suggested_fix": self.suggested_fix,
            "package_name":  self.package_name,
            "package_version": self.package_version,
            "fixed_version": self.fixed_version,
            "ai_summary":   self.ai_summary,
            "false_positive_probability": self.false_positive_probability,
            "scanner":      self.scanner,
        }
