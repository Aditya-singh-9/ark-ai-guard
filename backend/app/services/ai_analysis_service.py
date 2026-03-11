"""
AI Architecture Analysis Service using Google Gemini.
Sends repository structure and vulnerability summary to Gemini
and parses structured recommendations.
"""
import json
import re
from typing import Any, Optional
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

try:
    import google.generativeai as genai

    genai.configure(api_key=settings.GEMINI_API_KEY)
    _gemini_model = genai.GenerativeModel(settings.GEMINI_MODEL)
    GEMINI_AVAILABLE = bool(settings.GEMINI_API_KEY)
except ImportError:
    _gemini_model = None
    GEMINI_AVAILABLE = False
    log.warning("google-generativeai not installed — AI analysis will return mock data")
except Exception as exc:
    _gemini_model = None
    GEMINI_AVAILABLE = False
    log.warning(f"Gemini initialization failed: {exc}")


_ANALYSIS_PROMPT = """\
You are a senior DevSecOps engineer. Analyse the following GitHub repository structure
and security scan summary, then provide actionable recommendations.

## Repository Structure
{structure_summary}

## Detected Tech Stack
- Language: {language}
- Frameworks: {frameworks}
- Package manifests: {manifests}
- Has Docker: {has_docker}
- Has CI/CD: {has_cicd}
- Total files: {file_count}

## Security Scan Summary
- Total vulnerabilities: {total_vulns}
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

## Top Findings
{top_findings}

Please respond ONLY with valid JSON in this exact schema (no markdown):
{{
  "security_assessment": "<2-3 sentence overall security posture assessment>",
  "architecture_recommendations": [
    "<recommendation 1>",
    "<recommendation 2>",
    "<recommendation 3>"
  ],
  "security_improvements": [
    "<security fix 1>",
    "<security fix 2>",
    "<security fix 3>"
  ],
  "priority_actions": [
    "<immediate action 1>",
    "<immediate action 2>"
  ],
  "code_quality_notes": "<1-2 sentences about code organisation>",
  "risk_level": "<LOW | MEDIUM | HIGH | CRITICAL>"
}}
"""


async def analyse_repository(
    structure: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Send repository data to Gemini and return structured recommendations.

    Args:
        structure: Output from RepoClonerService.analyse_structure()
        vulnerabilities: Normalised finding dicts from all scanners.

    Returns:
        Parsed AI recommendations dict.
    """
    if not GEMINI_AVAILABLE or _gemini_model is None:
        log.warning("Gemini unavailable — returning default analysis")
        return _default_analysis(structure, vulnerabilities)

    # Build a short digest of top findings
    top_five = vulnerabilities[:5]
    findings_text = "\n".join(
        f"- [{v.get('severity', 'medium').upper()}] {v.get('file', '?')}: {v.get('issue', '?')[:120]}"
        for v in top_five
    )

    counts = _count_by_severity(vulnerabilities)
    prompt = _ANALYSIS_PROMPT.format(
        structure_summary=json.dumps(structure.get("directory_tree", [])[:20], indent=2),
        language=structure.get("language", "unknown"),
        frameworks=", ".join(structure.get("frameworks", [])) or "none detected",
        manifests=", ".join(structure.get("package_manifests", [])) or "none",
        has_docker=structure.get("has_docker", False),
        has_cicd=structure.get("has_cicd", False),
        file_count=structure.get("file_count", 0),
        total_vulns=len(vulnerabilities),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        top_findings=findings_text or "No findings",
    )

    log.info("Sending analysis request to Gemini…")
    try:
        response = _gemini_model.generate_content(prompt)
        raw_text = response.text.strip()

        # Strip potential markdown code fences
        raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
        raw_text = re.sub(r"\s*```$", "", raw_text)

        result = json.loads(raw_text)
        log.info("Gemini analysis received successfully")
        return result

    except json.JSONDecodeError as exc:
        log.error(f"Gemini response not valid JSON: {exc}")
        return _default_analysis(structure, vulnerabilities)
    except Exception as exc:
        log.error(f"Gemini API error: {exc}")
        return _default_analysis(structure, vulnerabilities)


def _count_by_severity(vulns: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.get("severity", "medium").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _default_analysis(
    structure: dict, vulnerabilities: list[dict]
) -> dict[str, Any]:
    """Fallback analysis when Gemini is unavailable."""
    counts = _count_by_severity(vulnerabilities)
    total = len(vulnerabilities)

    if counts["critical"] > 0:
        risk = "CRITICAL"
    elif counts["high"] > 2:
        risk = "HIGH"
    elif total > 5:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    lang = structure.get("language", "unknown")
    frameworks = structure.get("frameworks", [])

    return {
        "security_assessment": (
            f"The repository scanned uses {lang}"
            + (f" with {', '.join(frameworks)}" if frameworks else "")
            + f". {total} issues were detected: {counts['critical']} critical, "
            + f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low."
        ),
        "architecture_recommendations": [
            "Separate concerns: keep business logic, data access, and API layers distinct.",
            "Add an API gateway or middleware layer for rate limiting and input validation.",
            "Consider adopting a secrets management solution like HashiCorp Vault or AWS Secrets Manager.",
        ],
        "security_improvements": [
            "Rotate any credentials identified in this scan immediately.",
            "Enable dependency auto-update tools (Dependabot / Renovate).",
            "Add pre-commit hooks running Semgrep and secret scanners on every commit.",
        ],
        "priority_actions": [
            f"Address all {counts['critical']} critical findings immediately.",
            f"Patch {counts['high']} high severity dependency vulnerabilities this sprint.",
        ],
        "code_quality_notes": (
            "Consider adding comprehensive automated tests with ≥80% line coverage "
            "and enforcing a linting and formatting standard (Ruff for Python, ESLint for JS)."
        ),
        "risk_level": risk,
    }
