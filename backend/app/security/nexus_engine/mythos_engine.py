"""
ARK Mythos Engine™ — Offline Cybersecurity AI Model

A built-in, zero-dependency cybersecurity expert system that provides
AI-grade analysis WITHOUT any external API calls. Works 100% offline.

Capabilities:
  1. False-positive reduction via contextual heuristics
  2. Exploitability scoring using CVSS-like vector analysis
  3. OWASP/CWE/MITRE ATT&CK framework mapping
  4. Human-readable AI-style summaries for each finding
  5. Attack chain reconstruction (multi-finding correlation)
  6. Business impact estimation
  7. Fix priority calculation using risk-based scoring

The Mythos Engine is always available as the baseline model.
When Gemini (online) is also available, results are fused for best accuracy.
"""
from __future__ import annotations
import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional
import os
import json

from .finding_types import NexusFinding, NexusSeverity
from app.utils.logger import get_logger
from app.utils.config import settings

log = get_logger(__name__)

# Cache for local LLM to avoid reloading weights
_LOCAL_LLM_CACHE = None

def _get_local_mythos_llm():
    """Attempt to load the local Mythos 7B GGUF weights via llama-cpp-python."""
    global _LOCAL_LLM_CACHE
    if _LOCAL_LLM_CACHE is not None:
        return _LOCAL_LLM_CACHE

    try:
        from llama_cpp import Llama
    except ImportError:
        _LOCAL_LLM_CACHE = False
        return False

    model_path = os.environ.get("MYTHOS_LOCAL_MODEL_PATH", "ark_ml/mythos-7b-v1.gguf")
    if not os.path.exists(model_path):
        # Graceful degradation if weights haven't been trained/downloaded yet
        _LOCAL_LLM_CACHE = False
        return False

    try:
        log.info(f"[Mythos LLM] Loading local 7B model weights from {model_path}...")
        _LOCAL_LLM_CACHE = Llama(
            model_path=model_path,
            n_ctx=4096,           # SFT length
            n_gpu_layers=-1,      # Offload everything possible
            chat_format="chatml",
            verbose=False
        )
        return _LOCAL_LLM_CACHE
    except Exception as exc:
        log.warning(f"[Mythos LLM] Failed to load local weights: {exc}")
        _LOCAL_LLM_CACHE = False
        return False

# ── OWASP Top 10 2021 Mapping ──────────────────────────────────────────────────
OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "keywords": [
        "auth", "permission", "role", "admin", "idor", "privilege", "csrf",
        "access-control", "rbac", "authorization", "missing-auth",
    ]},
    "A02": {"name": "Cryptographic Failures", "keywords": [
        "crypto", "encrypt", "hash", "md5", "sha1", "des", "ecb", "key",
        "secret", "credential", "password", "entropy", "pbkdf2", "tls", "ssl",
        "private-key", "certificate",
    ]},
    "A03": {"name": "Injection", "keywords": [
        "sqli", "sql-injection", "command-injection", "xss", "template-injection",
        "eval", "exec", "os.system", "subprocess", "shell", "ldap", "xpath",
        "nosql", "innerHTML", "document.write",
    ]},
    "A04": {"name": "Insecure Design", "keywords": [
        "design", "architecture", "rate-limit", "brute-force", "missing-rate",
    ]},
    "A05": {"name": "Security Misconfiguration", "keywords": [
        "debug", "config", "cors", "wildcard", "default", "misconfiguration",
        "docker", "k8s", "kubernetes", "terraform", "iac", "helm",
    ]},
    "A06": {"name": "Vulnerable & Outdated Components", "keywords": [
        "cve", "dependency", "outdated", "vulnerable", "upgrade", "package",
        "typosquat", "supply-chain",
    ]},
    "A07": {"name": "Identification & Authentication Failures", "keywords": [
        "jwt", "session", "token", "login", "cookie", "oauth", "password",
        "brute", "credential-stuffing",
    ]},
    "A08": {"name": "Software & Data Integrity Failures", "keywords": [
        "deserialization", "pickle", "yaml.load", "integrity", "ci-cd",
        "pipeline", "actions", "supply-chain", "slsa",
    ]},
    "A09": {"name": "Security Logging & Monitoring Failures", "keywords": [
        "logging", "monitor", "audit", "log-sensitive", "print-sensitive",
    ]},
    "A10": {"name": "Server-Side Request Forgery (SSRF)", "keywords": [
        "ssrf", "request-forgery", "urlopen", "requests.get", "fetch",
    ]},
}

# ── CWE Mapping (Common Weakness Enumeration) ─────────────────────────────────
CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89", "sql-injection": "CWE-89",
    "xss": "CWE-79", "innerHTML": "CWE-79", "template-injection": "CWE-94",
    "command-injection": "CWE-78", "os.system": "CWE-78", "subprocess": "CWE-78",
    "path-traversal": "CWE-22", "directory-traversal": "CWE-22",
    "eval": "CWE-95", "exec": "CWE-95",
    "deserialization": "CWE-502", "pickle": "CWE-502", "marshal": "CWE-502",
    "ssrf": "CWE-918",
    "open-redirect": "CWE-601",
    "hardcoded-secret": "CWE-798", "hardcoded-password": "CWE-798",
    "private-key": "CWE-321",
    "weak-hash": "CWE-328", "md5": "CWE-328", "sha1": "CWE-328",
    "weak-random": "CWE-330", "math.random": "CWE-330",
    "insecure-random": "CWE-330",
    "jwt-none": "CWE-347", "jwt-verify-false": "CWE-347",
    "debug-mode": "CWE-489",
    "cors-wildcard": "CWE-942",
    "ssl-verify-false": "CWE-295",
    "csrf": "CWE-352",
    "prototype-pollution": "CWE-1321",
    "xxe": "CWE-611",
    "mass-assignment": "CWE-915",
    "idor": "CWE-639",
    "race-condition": "CWE-362",
    "entropy": "CWE-331",
    "cve": "CWE-1035",  # CVE-related findings
}

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
MITRE_ATTACK_MAP: dict[str, dict[str, str]] = {
    "credential-access": {
        "tactic": "Credential Access",
        "technique": "T1552",
        "name": "Unsecured Credentials",
        "keywords": "secret|password|credential|token|key|api-key",
    },
    "execution": {
        "tactic": "Execution",
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "keywords": "eval|exec|system|subprocess|command-injection",
    },
    "initial-access": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "keywords": "sqli|xss|ssrf|injection|rce|deserialization",
    },
    "persistence": {
        "tactic": "Persistence",
        "technique": "T1098",
        "name": "Account Manipulation",
        "keywords": "auth|jwt|session|cookie|mass-assignment",
    },
    "defense-evasion": {
        "tactic": "Defense Evasion",
        "technique": "T1562",
        "name": "Impair Defenses",
        "keywords": "ssl-verify|debug|cors|misconfiguration",
    },
    "collection": {
        "tactic": "Collection",
        "technique": "T1005",
        "name": "Data from Local System",
        "keywords": "path-traversal|file-read|directory|sensitive-data",
    },
    "impact": {
        "tactic": "Impact",
        "technique": "T1499",
        "name": "Endpoint Denial of Service",
        "keywords": "dos|redos|resource|memory|timeout",
    },
}

# ── Compliance Framework Mapping ───────────────────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "SOC2": {
        "CC6.1": {"name": "Logical and Physical Access Controls", "keywords": [
            "auth", "access-control", "rbac", "permission", "admin", "jwt", "session",
        ]},
        "CC6.6": {"name": "Security Event Monitoring", "keywords": [
            "logging", "monitor", "audit", "log-sensitive",
        ]},
        "CC6.7": {"name": "Restrict Transmission of Confidential Info", "keywords": [
            "ssl", "tls", "encrypt", "https", "cleartext",
        ]},
        "CC6.8": {"name": "Prevent Unauthorized Software", "keywords": [
            "dependency", "cve", "supply-chain", "integrity",
        ]},
        "CC7.2": {"name": "Monitor System Components", "keywords": [
            "config", "debug", "misconfiguration", "iac",
        ]},
        "CC8.1": {"name": "Change Management", "keywords": [
            "ci-cd", "pipeline", "actions", "deploy",
        ]},
    },
    "PCI_DSS_v4": {
        "6.2": {"name": "Secure Development", "keywords": [
            "sqli", "xss", "injection", "eval", "command",
        ]},
        "6.3": {"name": "Security Vulnerabilities Identified & Addressed", "keywords": [
            "cve", "dependency", "upgrade", "patch",
        ]},
        "6.4": {"name": "Public-Facing Web Apps Protected", "keywords": [
            "xss", "csrf", "cors", "injection", "ssrf",
        ]},
        "3.4": {"name": "PAN Data Protected", "keywords": [
            "encrypt", "hash", "secret", "credential", "password",
        ]},
        "8.3": {"name": "Strong Authentication", "keywords": [
            "auth", "password", "jwt", "session", "mfa",
        ]},
    },
    "HIPAA": {
        "164.312(a)": {"name": "Access Control", "keywords": [
            "auth", "access-control", "rbac", "admin",
        ]},
        "164.312(c)": {"name": "Integrity", "keywords": [
            "hash", "integrity", "checksum", "sign",
        ]},
        "164.312(d)": {"name": "Authentication", "keywords": [
            "jwt", "session", "password", "credential",
        ]},
        "164.312(e)": {"name": "Transmission Security", "keywords": [
            "ssl", "tls", "encrypt", "https", "cleartext",
        ]},
    },
    "ISO_27001": {
        "A.9.4": {"name": "Access Control to Program Source Code", "keywords": [
            "secret", "credential", "hardcoded", "api-key",
        ]},
        "A.10.1": {"name": "Cryptographic Controls", "keywords": [
            "crypto", "encrypt", "hash", "key", "tls",
        ]},
        "A.14.2": {"name": "Security in Development Processes", "keywords": [
            "injection", "xss", "sqli", "eval", "debug",
        ]},
        "A.12.6": {"name": "Technical Vulnerability Management", "keywords": [
            "cve", "dependency", "upgrade", "patch",
        ]},
    },
    "OWASP_TOP_10": {
        k: {"name": v["name"], "keywords": v["keywords"]}
        for k, v in OWASP_TOP_10.items()
    },
}


# ── Context-Aware False Positive Heuristics ────────────────────────────────────

# Patterns in file paths that strongly suggest test/example code
_TEST_PATH_PATTERNS = re.compile(
    r'(test[_/]|tests[_/]|spec[_/]|__tests__|fixtures[_/]|'
    r'mock[_/]|example[_/]|demo[_/]|sample[_/]|docs[_/]|'
    r'\.test\.|_test\.py|test_|conftest\.py|setup\.py|'
    r'README|CHANGELOG|\.md$|\.txt$|\.rst$)',
    re.IGNORECASE,
)

# Code snippet patterns indicating false positives
_FP_SNIPPET_PATTERNS = [
    re.compile(r'#\s*(noqa|nosec|type:\s*ignore)', re.IGNORECASE),
    re.compile(r'//\s*(eslint-disable|noinspection|NOSONAR)', re.IGNORECASE),
    re.compile(r'TODO|FIXME|HACK|XXX', re.IGNORECASE),
    re.compile(r'placeholder|example|template|sample|dummy|test', re.IGNORECASE),
    re.compile(r'\{\{\s*\w+\s*\}\}'),  # Template variables {{ var }}
    re.compile(r'<your[-_]|CHANGE[-_]?ME|REPLACE[-_]?ME|xxx', re.IGNORECASE),
]


@dataclass
class MythosAnalysis:
    """Result of Mythos Engine analysis for a single finding."""
    false_positive_probability: float = 0.0
    exploitability_score: float = 0.5
    business_impact: str = ""
    ai_summary: str = ""
    owasp_category: str = ""
    owasp_name: str = ""
    cwe_id: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    compliance_violations: dict[str, list[str]] = field(default_factory=dict)
    attack_chain_probability: float = 0.0
    fix_priority_rank: int = 0
    risk_score: float = 0.0  # 0-100 composite risk score


@dataclass
class MythosReport:
    """Aggregate Mythos report for an entire scan."""
    findings: list[NexusFinding] = field(default_factory=list)
    analyses: list[MythosAnalysis] = field(default_factory=list)
    overall_risk_level: str = "MEDIUM"
    compliance_summary: dict[str, dict] = field(default_factory=dict)
    attack_surface_score: float = 0.0
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    threat_model_summary: str = ""
    executive_brief: str = ""


def run_mythos_engine(findings: list[NexusFinding]) -> MythosReport:
    """
    Run the ARK Mythos Engine™ on all findings.

    This is a 100% offline, zero-API cybersecurity AI that provides:
    - False positive detection
    - Exploitability scoring
    - OWASP/CWE/MITRE mapping
    - Compliance framework analysis
    - Attack chain correlation
    - Business impact assessment
    - AI-quality summaries

    Always available, no API keys needed.
    """
    if not findings:
        return MythosReport()

    log.info(f"[Mythos] Analyzing {len(findings)} findings...")

    report = MythosReport(findings=findings)
    analyses: list[MythosAnalysis] = []

    # Hot-swappable Architecture
    # Tier 2: Check for Local 7B LLM
    llm = _get_local_mythos_llm()
    
    if llm:
        log.info("[Mythos] Local 7B Model Online. Routing findings to Deep AI Reasoning layer...")
        for finding in findings:
            # Wrap heuristic context with local LLM reasoning
            base_analysis = _analyze_finding(finding)
            llm_analysis = _run_local_llm_inference(llm, finding, base_analysis)
            analyses.append(llm_analysis)
    else:
        # Tier 1: Fast Heuristic Rules (Graceful Degradation)
        log.debug("[Mythos] Local 7B Model Offline. Using fallback heuristic logic.")
        for finding in findings:
            analysis = _analyze_finding(finding)
            analyses.append(analysis)

    report.analyses = analyses

    # Correlate attack chains
    _detect_attack_chains(findings, analyses)

    # Compute fix priority ranking
    _compute_priority_ranking(findings, analyses)

    # Generate compliance summary
    report.compliance_summary = _generate_compliance_summary(findings, analyses)

    # OWASP coverage map
    report.owasp_coverage = _compute_owasp_coverage(analyses)

    # Overall risk level
    report.overall_risk_level = _compute_overall_risk(findings, analyses)

    # Attack surface score
    report.attack_surface_score = _compute_attack_surface(findings)

    # Generate executive brief
    report.executive_brief = _generate_executive_brief(findings, analyses, report)

    # Generate threat model summary
    report.threat_model_summary = _generate_threat_model(findings, analyses)

    # Apply Mythos augmentation back to findings
    for finding, analysis in zip(findings, analyses):
        if not finding.cwe_id and analysis.cwe_id:
            finding.cwe_id = analysis.cwe_id
        if not finding.ai_summary and analysis.ai_summary:
            finding.ai_summary = f"[Mythos] {analysis.ai_summary}"
        finding.false_positive_probability = max(
            finding.false_positive_probability,
            analysis.false_positive_probability,
        )
        finding.exploitability = (
            finding.exploitability * 0.5 + analysis.exploitability_score * 0.5
        )

    log.info(
        f"[Mythos] Analysis complete — Risk: {report.overall_risk_level}, "
        f"Attack Surface: {report.attack_surface_score:.0f}/100"
    )
    return report


def _run_local_llm_inference(llm, finding: NexusFinding, base: MythosAnalysis) -> MythosAnalysis:
    """Enhance the fast heuristic base analysis with deep local 7B logic."""
    try:
        prompt = f"""<|system|> You are the ARK Mythos Security AI. Provide a deep security analysis.
<|user|> Analyze this vulnerability:
Issue: {finding.issue}
Code:
<|vuln|>
{finding.code_snippet}
<|vuln|>
<|assistant|>"""

        response = llm(
            prompt,
            max_tokens=256,
            temperature=0.1,
            stop=["<|user|>", "<|eos|>"]
        )
        llm_text = response["choices"][0]["text"].strip()
        
        # Override heuristic summary with deep LLM reasoning
        base.ai_summary = llm_text
        # Optional: You can extend this to parse JSON for precise FP rates and score overrides
    except Exception as exc:
        log.debug(f"[Mythos LLM] Inference error: {exc}")
        
    return base

def _analyze_finding(finding: NexusFinding) -> MythosAnalysis:
    """Run full Mythos analysis on a single finding."""
    analysis = MythosAnalysis()

    rule_lower = (finding.rule_id or "").lower()
    issue_lower = (finding.issue or "").lower()
    snippet_lower = (finding.code_snippet or "").lower()
    file_lower = (finding.file or "").lower()
    combined = f"{rule_lower} {issue_lower} {finding.description or ''}".lower()

    # 1. False positive detection
    analysis.false_positive_probability = _calc_fp_probability(
        finding, file_lower, snippet_lower, combined
    )

    # 2. Exploitability scoring
    analysis.exploitability_score = _calc_exploitability(
        finding, combined, file_lower
    )

    # 3. OWASP mapping
    analysis.owasp_category, analysis.owasp_name = _map_owasp(combined)

    # 4. CWE mapping
    analysis.cwe_id = _map_cwe(combined, rule_lower)

    # 5. MITRE ATT&CK mapping
    analysis.mitre_tactic, analysis.mitre_technique = _map_mitre(combined)

    # 6. Compliance framework violations
    analysis.compliance_violations = _map_compliance(combined)

    # 7. Business impact assessment
    analysis.business_impact = _assess_business_impact(finding, combined)

    # 8. AI-style summary
    analysis.ai_summary = _generate_finding_summary(finding, analysis)

    # 9. Composite risk score
    sev_weight = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
    analysis.risk_score = (
        sev_weight.get(finding.severity.value, 0.5) * 40
        + analysis.exploitability_score * 30
        + (1.0 - analysis.false_positive_probability) * 15
        + min(finding.blast_radius / 10, 1.0) * 15
    )

    return analysis


def _calc_fp_probability(
    finding: NexusFinding, file_lower: str, snippet_lower: str, combined: str
) -> float:
    """Calculate false positive probability using contextual heuristics."""
    fp_score = 0.0

    # Test/example/doc file → much more likely FP
    if _TEST_PATH_PATTERNS.search(file_lower):
        fp_score += 0.35

    # Code snippet contains suppression comments or placeholder values
    for pattern in _FP_SNIPPET_PATTERNS:
        if pattern.search(snippet_lower):
            fp_score += 0.15
            break

    # Very short code snippet → less context → more likely FP
    if len(snippet_lower) < 20:
        fp_score += 0.1

    # Low confidence from scanner already
    if finding.confidence < 0.5:
        fp_score += 0.15

    # Config/env patterns in non-config files
    if any(x in combined for x in ("config", "env", "setting")) and \
       not any(x in file_lower for x in (".env", "config", "setting")):
        fp_score += 0.1

    # Generic patterns that are noisy
    if any(x in combined for x in ("cookie-no-", "http-not-https", "localstorage")):
        fp_score += 0.15

    # Comments in code
    stripped = snippet_lower.strip()
    if stripped.startswith(("#", "//", "/*", "*", "<!--", '"""', "'''")):
        fp_score += 0.40

    return min(fp_score, 0.95)


def _calc_exploitability(
    finding: NexusFinding, combined: str, file_lower: str
) -> float:
    """Score exploitability 0.0–1.0 using CVSS-like vector analysis."""
    score = 0.5  # baseline

    # Attack vector: network-accessible vs local
    if any(x in combined for x in ("sql", "xss", "ssrf", "injection", "rce", "command")):
        score += 0.25  # network-exploitable
    elif any(x in combined for x in ("path-traversal", "file-read", "lfi")):
        score += 0.15
    elif any(x in combined for x in ("secret", "credential", "password", "key")):
        score += 0.10  # requires repo access

    # Attack complexity
    if any(x in combined for x in ("eval(", "exec(", "pickle", "marshal", "yaml.load")):
        score += 0.15  # trivial to exploit
    elif any(x in combined for x in ("deserialization", "prototype-pollution")):
        score += 0.10

    # User interaction required?
    if any(x in combined for x in ("xss", "csrf", "open-redirect", "clickjacking")):
        score -= 0.05  # requires user interaction

    # Is it in a handler/route (directly reachable)?
    if any(x in file_lower for x in ("route", "view", "handler", "controller", "api")):
        score += 0.10

    # Is it in internal/utility code (less reachable)?
    if any(x in file_lower for x in ("util", "helper", "internal", "lib")):
        score -= 0.10

    return max(0.0, min(1.0, score))


def _map_owasp(combined: str) -> tuple[str, str]:
    """Map finding to OWASP Top 10 2021 category."""
    best_match = ("", "")
    best_score = 0

    for category, info in OWASP_TOP_10.items():
        score = sum(1 for kw in info["keywords"] if kw in combined)
        if score > best_score:
            best_score = score
            best_match = (category, info["name"])

    return best_match


def _map_cwe(combined: str, rule_lower: str) -> str:
    """Map finding to CWE identifier."""
    for keyword, cwe in CWE_MAP.items():
        if keyword in combined or keyword in rule_lower:
            return cwe
    return ""


def _map_mitre(combined: str) -> tuple[str, str]:
    """Map finding to MITRE ATT&CK tactic and technique."""
    for _, info in MITRE_ATTACK_MAP.items():
        keywords = info["keywords"].split("|")
        if any(kw in combined for kw in keywords):
            return info["tactic"], f'{info["technique"]} — {info["name"]}'
    return "", ""


def _map_compliance(combined: str) -> dict[str, list[str]]:
    """Map finding to compliance framework violations."""
    violations: dict[str, list[str]] = {}

    for framework, controls in COMPLIANCE_FRAMEWORKS.items():
        if framework == "OWASP_TOP_10":
            continue  # handled separately
        matched = []
        for ctrl_id, ctrl_info in controls.items():
            if any(kw in combined for kw in ctrl_info["keywords"]):
                matched.append(f'{ctrl_id}: {ctrl_info["name"]}')
        if matched:
            violations[framework] = matched

    return violations


def _assess_business_impact(finding: NexusFinding, combined: str) -> str:
    """Generate business impact assessment."""
    impacts = []

    if any(x in combined for x in ("secret", "credential", "password", "api-key", "token")):
        impacts.append("Account compromise and unauthorized access to external services")
    if any(x in combined for x in ("sqli", "sql-injection", "database")):
        impacts.append("Data breach — full database exfiltration possible")
    if any(x in combined for x in ("xss", "cross-site", "innerHTML")):
        impacts.append("User session hijacking and phishing via stored XSS")
    if any(x in combined for x in ("rce", "eval", "exec", "command-injection", "deserialization")):
        impacts.append("Full server compromise — remote code execution")
    if any(x in combined for x in ("ssrf", "request-forgery")):
        impacts.append("Internal network reconnaissance and cloud metadata theft")
    if any(x in combined for x in ("cve", "dependency")):
        impacts.append("Known exploits available — automated attack tools exist")
    if any(x in combined for x in ("docker", "k8s", "terraform", "iac")):
        impacts.append("Infrastructure compromise — blast radius extends to entire environment")

    if not impacts:
        sev = finding.severity.value
        if sev == "critical":
            impacts.append("Severe security vulnerability requiring immediate remediation")
        elif sev == "high":
            impacts.append("Significant security risk that should be addressed this sprint")
        elif sev == "medium":
            impacts.append("Moderate security concern — plan remediation in upcoming sprint")
        else:
            impacts.append("Low-risk finding — address during regular code maintenance")

    return "; ".join(impacts[:2])


def _generate_finding_summary(finding: NexusFinding, analysis: MythosAnalysis) -> str:
    """Generate an AI-quality human-readable summary for a finding."""
    parts = []

    # Severity context
    sev = finding.severity.value.upper()
    parts.append(f"[{sev}]")

    # What's the issue
    parts.append(finding.issue[:100])

    # Where
    if finding.file:
        loc = finding.file
        if finding.line:
            loc += f":{finding.line}"
        parts.append(f"in {loc}")

    # OWASP context
    if analysis.owasp_category:
        parts.append(f"(OWASP {analysis.owasp_category}: {analysis.owasp_name})")

    # Exploitability
    if analysis.exploitability_score >= 0.8:
        parts.append("— Trivially exploitable by an attacker")
    elif analysis.exploitability_score >= 0.6:
        parts.append("— Exploitable with moderate effort")
    elif analysis.exploitability_score >= 0.4:
        parts.append("— Requires specific conditions to exploit")

    # FP note
    if analysis.false_positive_probability >= 0.5:
        parts.append("[Likely false positive — verify manually]")

    return " ".join(parts)


def _detect_attack_chains(
    findings: list[NexusFinding], analyses: list[MythosAnalysis]
) -> None:
    """
    Correlate findings to detect multi-step attack chains.
    E.g., XSS + session token in localStorage = full account takeover chain.
    """
    attack_types: dict[str, list[int]] = {}

    for i, (f, a) in enumerate(zip(findings, analyses)):
        combined = f"{f.rule_id} {f.issue} {f.description}".lower()
        for category in ["injection", "auth", "crypto", "config", "ssrf", "secret"]:
            if category in combined:
                attack_types.setdefault(category, []).append(i)

    # Check for known attack chain combinations
    chains = [
        ({"injection", "auth"}, 0.85, "Injection + Auth flaw = complete account takeover"),
        ({"secret", "auth"}, 0.80, "Exposed secrets + auth bypass = full system compromise"),
        ({"injection", "config"}, 0.75, "Injection + misconfig = escalated attack surface"),
        ({"ssrf", "secret"}, 0.90, "SSRF + secrets = cloud infrastructure compromise"),
        ({"crypto", "auth"}, 0.70, "Weak crypto + auth issues = credential compromise"),
    ]

    found_categories = set(attack_types.keys())
    for required, probability, description in chains:
        if required.issubset(found_categories):
            # Mark all involved findings with chain probability
            for cat in required:
                for idx in attack_types[cat]:
                    analyses[idx].attack_chain_probability = max(
                        analyses[idx].attack_chain_probability, probability
                    )


def _compute_priority_ranking(
    findings: list[NexusFinding], analyses: list[MythosAnalysis]
) -> None:
    """Rank findings by fix priority using composite risk score."""
    scored = [(i, a.risk_score) for i, a in enumerate(analyses)]
    scored.sort(key=lambda x: x[1], reverse=True)

    for rank, (idx, _) in enumerate(scored, 1):
        analyses[idx].fix_priority_rank = rank


def _generate_compliance_summary(
    findings: list[NexusFinding], analyses: list[MythosAnalysis]
) -> dict[str, dict]:
    """Generate per-framework compliance summary."""
    summary: dict[str, dict] = {}

    for framework in ["SOC2", "PCI_DSS_v4", "HIPAA", "ISO_27001"]:
        all_controls = set(COMPLIANCE_FRAMEWORKS.get(framework, {}).keys())
        violated_controls: set[str] = set()

        for analysis in analyses:
            for ctrl in analysis.compliance_violations.get(framework, []):
                ctrl_id = ctrl.split(":")[0].strip()
                violated_controls.add(ctrl_id)

        total = len(all_controls)
        violated = len(violated_controls)
        compliant = total - violated
        pct = round(compliant / total * 100, 1) if total else 100.0

        summary[framework] = {
            "total_controls": total,
            "compliant_controls": compliant,
            "violated_controls": violated,
            "compliance_percentage": pct,
            "violations": sorted(violated_controls),
            "status": "PASS" if pct >= 100 else "WARN" if pct >= 80 else "FAIL",
        }

    return summary


def _compute_owasp_coverage(analyses: list[MythosAnalysis]) -> dict[str, int]:
    """Count findings per OWASP category."""
    coverage: dict[str, int] = {}
    for a in analyses:
        if a.owasp_category:
            key = f"{a.owasp_category}: {a.owasp_name}"
            coverage[key] = coverage.get(key, 0) + 1
    return dict(sorted(coverage.items(), key=lambda x: x[1], reverse=True))


def _compute_overall_risk(
    findings: list[NexusFinding], analyses: list[MythosAnalysis]
) -> str:
    """Compute overall risk level."""
    if not findings:
        return "NONE"

    crit = sum(1 for f in findings if f.severity == NexusSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == NexusSeverity.HIGH)

    # Check for attack chains
    has_chain = any(a.attack_chain_probability > 0.7 for a in analyses)

    if crit >= 3 or (crit >= 1 and has_chain):
        return "CRITICAL"
    elif crit >= 1 or high >= 5:
        return "HIGH"
    elif high >= 2:
        return "MEDIUM"
    elif high >= 1 or len(findings) > 10:
        return "LOW"
    return "MINIMAL"


def _compute_attack_surface(findings: list[NexusFinding]) -> float:
    """Estimate attack surface score 0-100."""
    affected_files: set[str] = set()
    entry_points = 0
    has_external_deps = False

    for f in findings:
        if f.file:
            affected_files.add(f.file)
        combined = f"{f.rule_id} {f.issue}".lower()
        if any(x in combined for x in ("route", "handler", "api", "endpoint")):
            entry_points += 1
        if any(x in combined for x in ("cve", "dependency", "package")):
            has_external_deps = True

    file_score = min(len(affected_files) * 5, 40)
    entry_score = min(entry_points * 10, 30)
    dep_score = 15 if has_external_deps else 0
    finding_score = min(len(findings) * 2, 15)

    return min(file_score + entry_score + dep_score + finding_score, 100)


def _generate_executive_brief(
    findings: list[NexusFinding],
    analyses: list[MythosAnalysis],
    report: MythosReport,
) -> str:
    """Generate a professional executive summary."""
    crit = sum(1 for f in findings if f.severity == NexusSeverity.CRITICAL)
    high = sum(1 for f in findings if f.severity == NexusSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == NexusSeverity.MEDIUM)
    low = sum(1 for f in findings if f.severity == NexusSeverity.LOW)

    chains = sum(1 for a in analyses if a.attack_chain_probability > 0.5)
    top_owasp = list(report.owasp_coverage.items())[:3]

    parts = [
        f"ARK Mythos Security Assessment: {len(findings)} findings identified.",
        f"Severity: {crit} Critical, {high} High, {med} Medium, {low} Low.",
        f"Overall Risk: {report.overall_risk_level}.",
        f"Attack Surface Score: {report.attack_surface_score:.0f}/100.",
    ]

    if chains:
        parts.append(f"⚠ {chains} multi-step attack chain(s) detected.")

    if top_owasp:
        owasp_str = ", ".join(f"{k} ({v})" for k, v in top_owasp)
        parts.append(f"Top OWASP categories: {owasp_str}.")

    # Compliance status
    for fw, status in report.compliance_summary.items():
        if status["status"] != "PASS":
            parts.append(
                f"{fw}: {status['compliance_percentage']}% compliant "
                f"({status['violated_controls']} controls violated)."
            )

    return " ".join(parts)


def _generate_threat_model(
    findings: list[NexusFinding], analyses: list[MythosAnalysis]
) -> str:
    """Generate STRIDE-based threat model summary."""
    stride = {
        "Spoofing": 0, "Tampering": 0, "Repudiation": 0,
        "Information Disclosure": 0, "Denial of Service": 0,
        "Elevation of Privilege": 0,
    }

    for f, a in zip(findings, analyses):
        combined = f"{f.rule_id} {f.issue} {f.description}".lower()
        if any(x in combined for x in ("auth", "jwt", "session", "forgery", "spoof")):
            stride["Spoofing"] += 1
        if any(x in combined for x in ("injection", "xss", "tampering", "integrity")):
            stride["Tampering"] += 1
        if any(x in combined for x in ("logging", "audit", "monitor")):
            stride["Repudiation"] += 1
        if any(x in combined for x in ("secret", "leak", "exposure", "disclosure", "path-traversal")):
            stride["Information Disclosure"] += 1
        if any(x in combined for x in ("dos", "redos", "resource", "memory", "timeout")):
            stride["Denial of Service"] += 1
        if any(x in combined for x in ("admin", "privilege", "escalation", "rbac", "eval", "exec", "rce")):
            stride["Elevation of Privilege"] += 1

    active = {k: v for k, v in stride.items() if v > 0}
    if not active:
        return "No significant STRIDE threats identified."

    parts = ["STRIDE Threat Analysis:"]
    for threat, count in sorted(active.items(), key=lambda x: x[1], reverse=True):
        parts.append(f"  • {threat}: {count} finding(s)")

    return "\n".join(parts)
