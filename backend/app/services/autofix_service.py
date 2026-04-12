"""
ARK AI Auto-Fix Service — Generate code fixes for vulnerabilities.

Uses a dual-model approach:
  1. Mythos (offline): Generates template-based fixes for common patterns
  2. Gemini (online): Generates context-aware, AI-powered fixes when available

Can optionally create GitHub Pull Requests with the fixes.
"""
from __future__ import annotations
import os
import re
import json
from typing import Any, Optional
from dataclasses import dataclass, field

from app.utils.logger import get_logger
from app.utils.config import settings

log = get_logger(__name__)


@dataclass
class AutoFix:
    """A generated code fix for a vulnerability."""
    finding_id: str
    file_path: str
    line_number: int
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float  # 0.0–1.0 how confident we are the fix is correct
    model: str  # "mythos" or "gemini"
    breaking_risk: str  # "none", "low", "medium", "high"
    test_suggestion: str  # suggested test to verify the fix


# ── Offline Fix Templates (Mythos) ────────────────────────────────────────────

FIX_TEMPLATES: dict[str, dict[str, Any]] = {
    # SQL Injection
    "sqli": {
        "patterns": [
            (r'execute\s*\(\s*["\'].*%s.*["\']', 'execute("...%s...", (param,))'),
            (r'f".*\{(\w+)\}.*".*execute', 'Use parameterized query with %s placeholder'),
            (r'\.format\(.*\).*execute', 'Use parameterized query with %s placeholder'),
        ],
        "explanation": "Replace string-concatenated SQL with parameterized queries to prevent SQL injection.",
        "test": "Test with SQL metacharacters: ' OR 1=1 --, UNION SELECT, etc.",
        "breaking_risk": "low",
    },

    # XSS
    "xss": {
        "patterns": [
            (r'innerHTML\s*=', 'textContent = '),
            (r'document\.write\s*\(', 'Use DOM API: element.textContent = '),
            (r'dangerouslySetInnerHTML', 'Use DOMPurify.sanitize() before rendering'),
        ],
        "explanation": "Sanitize user input before rendering in DOM to prevent Cross-Site Scripting.",
        "test": "Test with XSS payloads: <script>alert(1)</script>, <img onerror=...>",
        "breaking_risk": "low",
    },

    # Command Injection
    "command-injection": {
        "patterns": [
            (r'os\.system\s*\(', 'subprocess.run([], shell=False)'),
            (r'subprocess\.\w+\([^)]*shell\s*=\s*True', 'subprocess.run([cmd, arg], shell=False)'),
            (r'eval\s*\(', 'Use ast.literal_eval() for safe evaluation'),
            (r'exec\s*\(', 'Avoid exec(); use structured dispatch instead'),
        ],
        "explanation": "Replace shell execution with safe subprocess calls using argument arrays.",
        "test": "Test with shell metacharacters: ; ls, | cat /etc/passwd, $(whoami)",
        "breaking_risk": "medium",
    },

    # Hardcoded Secrets
    "hardcoded-secret": {
        "patterns": [
            (r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}', 'Use os.environ.get("VAR_NAME")'),
        ],
        "explanation": "Move secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "test": "Verify the application reads from environment variables correctly.",
        "breaking_risk": "medium",
    },

    # Insecure Deserialization
    "deserialization": {
        "patterns": [
            (r'pickle\.loads?\s*\(', 'json.loads() for safe deserialization'),
            (r'yaml\.load\s*\(', 'yaml.safe_load()'),
            (r'marshal\.load\s*\(', 'json.load() for safe deserialization'),
        ],
        "explanation": "Replace unsafe deserializers with safe alternatives to prevent remote code execution.",
        "test": "Verify data format compatibility with the new safe deserializer.",
        "breaking_risk": "medium",
    },

    # SSL/TLS
    "ssl-verify": {
        "patterns": [
            (r'verify\s*=\s*False', 'verify=True'),
            (r'ssl\._create_unverified_context', 'ssl.create_default_context()'),
        ],
        "explanation": "Enable SSL certificate verification to prevent person-in-the-middle attacks.",
        "test": "Verify HTTPS connections succeed with valid certificates.",
        "breaking_risk": "low",
    },

    # Debug Mode
    "debug-mode": {
        "patterns": [
            (r'DEBUG\s*=\s*True', 'DEBUG = os.environ.get("DEBUG", "False").lower() == "true"'),
            (r'debug\s*=\s*True', 'debug=False  # Never enable debug in production'),
        ],
        "explanation": "Disable debug mode in production to prevent information disclosure.",
        "test": "Ensure error pages do not expose stack traces or internal state.",
        "breaking_risk": "none",
    },

    # Weak Crypto
    "weak-crypto": {
        "patterns": [
            (r'md5\s*\(', 'hashlib.sha256('),
            (r'sha1\s*\(', 'hashlib.sha256('),
            (r'DES\b', 'AES'),
            (r'MODE_ECB', 'MODE_GCM'),
        ],
        "explanation": "Replace weak cryptographic algorithms with strong alternatives.",
        "test": "Verify all callers handle the updated hash/cipher output format.",
        "breaking_risk": "medium",
    },

    # CORS
    "cors-wildcard": {
        "patterns": [
            (r'Access-Control-Allow-Origin.*\*', 'Access-Control-Allow-Origin: <specific-origin>'),
            (r'origins\s*=\s*\[?\s*["\']?\*', 'origins=["https://your-domain.com"]'),
        ],
        "explanation": "Replace wildcard CORS with specific allowed origins to prevent cross-origin attacks.",
        "test": "Verify legitimate frontend origins can still make requests.",
        "breaking_risk": "medium",
    },

    # JWT Issues
    "jwt-insecure": {
        "patterns": [
            (r'algorithms?\s*=\s*\[?\s*["\']none', 'algorithms=["HS256"]'),
            (r'verify\s*=\s*False.*jwt', 'verify=True'),
        ],
        "explanation": "Enforce JWT signature verification and strong algorithms.",
        "test": "Test with a modified JWT token — the server should reject it.",
        "breaking_risk": "low",
    },

    # Docker
    "docker-root": {
        "patterns": [
            (r'USER\s+root', 'USER nonroot'),
        ],
        "explanation": "Run containers as non-root to limit blast radius of container escapes.",
        "test": "Verify application runs correctly as non-root user.",
        "breaking_risk": "medium",
    },
}


def generate_offline_fixes(findings: list[dict]) -> list[AutoFix]:
    """
    Generate fixes using the offline Mythos template engine.
    Always available, no API key required.
    """
    fixes: list[AutoFix] = []

    for finding in findings:
        rule_id = (finding.get("rule_id") or "").lower()
        issue = (finding.get("issue") or "").lower()
        snippet = finding.get("code_snippet") or ""
        combined = f"{rule_id} {issue}"

        # Find matching template
        matched_template = None
        for key, template in FIX_TEMPLATES.items():
            if key in combined:
                matched_template = template
                break

        if not matched_template:
            continue

        # Try to apply pattern-based fix
        fixed_code = snippet
        applied = False
        for pattern, replacement in matched_template["patterns"]:
            if re.search(pattern, snippet, re.IGNORECASE):
                fixed_code = re.sub(pattern, replacement, snippet, flags=re.IGNORECASE)
                applied = True
                break

        if not applied:
            fixed_code = f"// TODO: {matched_template['explanation']}\n{snippet}"

        fixes.append(AutoFix(
            finding_id=finding.get("rule_id", "unknown"),
            file_path=finding.get("file", ""),
            line_number=finding.get("line", 0),
            original_code=snippet,
            fixed_code=fixed_code,
            explanation=matched_template["explanation"],
            confidence=0.75 if applied else 0.50,
            model="mythos",
            breaking_risk=matched_template.get("breaking_risk", "low"),
            test_suggestion=matched_template.get("test", ""),
        ))

    log.info(f"[AutoFix] Mythos generated {len(fixes)} fixes")
    return fixes


async def generate_ai_fixes(findings: list[dict]) -> list[AutoFix]:
    """
    Generate AI-powered fixes using Gemini (online).
    Falls back to offline fixes if Gemini is unavailable.
    """
    gemini_key = settings.GEMINI_API_KEY
    if not gemini_key:
        log.info("[AutoFix] No Gemini API key — using offline fixes only")
        return generate_offline_fixes(findings)

    try:
        import google.generativeai as genai
        import asyncio

        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel(settings.GEMINI_MODEL)

        # Take top 10 most critical findings for AI fix generation
        priority = sorted(
            findings,
            key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                (f.get("severity") or "medium").lower(), 2
            ),
            reverse=True,
        )[:10]

        compact = [{
            "rule_id": f.get("rule_id", ""),
            "issue": f.get("issue", ""),
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "snippet": (f.get("code_snippet") or "")[:200],
            "severity": f.get("severity", "medium"),
            "suggested_fix": f.get("suggested_fix", ""),
        } for f in priority]

        prompt = f"""You are a senior security engineer. Generate code fixes for these vulnerabilities.

For each vulnerability, provide:
- idx: same index as input
- fixed_code: the corrected code (complete, drop-in replacement)
- explanation: 1-2 sentence explanation of what was wrong and why the fix works
- confidence: 0.0–1.0 confidence score
- breaking_risk: "none", "low", "medium", or "high"
- test_suggestion: how to verify the fix works

Return ONLY valid JSON array. No markdown fences.
Format: [{{"idx": 0, "fixed_code": "...", "explanation": "...", "confidence": 0.9, "breaking_risk": "low", "test_suggestion": "..."}}]

Vulnerabilities:
{json.dumps(compact, indent=2)}
"""

        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config={"temperature": 0.1, "max_output_tokens": 2048},
            )
        )

        raw = response.text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        ai_fixes_data = json.loads(raw)

        fixes: list[AutoFix] = []
        for ai_fix in ai_fixes_data:
            idx = int(ai_fix.get("idx", 0))
            if idx < len(priority):
                f = priority[idx]
                fixes.append(AutoFix(
                    finding_id=f.get("rule_id", "unknown"),
                    file_path=f.get("file", ""),
                    line_number=f.get("line", 0),
                    original_code=f.get("code_snippet", ""),
                    fixed_code=ai_fix.get("fixed_code", ""),
                    explanation=ai_fix.get("explanation", ""),
                    confidence=float(ai_fix.get("confidence", 0.8)),
                    model="gemini",
                    breaking_risk=ai_fix.get("breaking_risk", "low"),
                    test_suggestion=ai_fix.get("test_suggestion", ""),
                ))

        # Merge with offline fixes for findings Gemini didn't cover
        offline = generate_offline_fixes(findings)
        covered_rules = {f.finding_id for f in fixes}
        for of in offline:
            if of.finding_id not in covered_rules:
                fixes.append(of)

        log.info(f"[AutoFix] Generated {len(fixes)} fixes (Gemini + Mythos)")
        return fixes

    except Exception as exc:
        log.warning(f"[AutoFix] Gemini fix generation failed: {exc} — falling back to offline")
        return generate_offline_fixes(findings)
