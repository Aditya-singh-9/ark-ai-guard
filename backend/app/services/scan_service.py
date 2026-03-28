"""
Scan orchestration service.
Coordinates the full pipeline: clone → scan → AI → persist → cleanup.
"""
import json
import time
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session

from app.models.scan_report import ScanReport, ScanStatus
from app.models.vulnerability import Vulnerability, Severity, ScannerType
from app.models.repository import Repository
from app.services.repo_cloner import repo_cloner
from app.services.ai_analysis_service import analyse_repository
from app.services.cicd_generator import generate_cicd_pipeline
from app.security.semgrep_runner import run_semgrep
from app.security.bandit_runner import run_bandit
from app.security.trivy_runner import run_trivy
from app.security.native_scanner import run_native_scanner
from app.utils.logger import get_logger

log = get_logger(__name__)

# Cap max findings stored in DB per scan to avoid unbounded growth
MAX_FINDINGS_STORED = 500


def _severity_enum(sev_str: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(sev_str.lower(), Severity.MEDIUM)


def _scanner_enum(scanner_str: str) -> ScannerType:
    mapping = {
        "semgrep": ScannerType.SEMGREP,
        "bandit": ScannerType.BANDIT,
        "trivy": ScannerType.TRIVY,
    }
    return mapping.get(scanner_str.lower(), ScannerType.SEMGREP)


async def run_full_scan(
    db: Session,
    repository: Repository,
    scan_report: ScanReport,
    access_token: str | None = None,
) -> ScanReport:
    """
    Execute the full security scanning pipeline for a repository.

    Steps:
    1. Clone the repository
    2. Analyse project structure
    3. Run Semgrep, Bandit, Trivy in parallel (subprocess)
    4. Deduplicate and cap findings
    5. Send to AI for recommendations
    6. Generate CI/CD pipeline YAML
    7. Compute security score
    8. Persist everything to DB
    9. Cleanup cloned files

    Args:
        db: SQLAlchemy Session
        repository: Repository model instance
        scan_report: ScanReport model (status=PENDING, already committed)
        access_token: Decrypted GitHub token for private repo access

    Returns:
        Updated ScanReport with status=COMPLETED or FAILED
    """
    scan_id = scan_report.id
    start_time = time.time()

    log.info(f"[Scan {scan_id}] Starting for {repository.full_name}")

    # Mark as running
    scan_report.status = ScanStatus.RUNNING
    db.commit()

    clone_path: str | None = None

    try:
        # ── Step 1: Clone ────────────────────────────────────────────────
        log.info(f"[Scan {scan_id}] Cloning {repository.clone_url or repository.url}")
        clone_path = repo_cloner.clone_repository(
            clone_url=repository.clone_url or repository.url,
            scan_id=scan_id,
            access_token=access_token,
        )

        # ── Step 2: Structure Analysis ───────────────────────────────────
        log.info(f"[Scan {scan_id}] Analysing structure…")
        structure = repo_cloner.analyse_structure(clone_path)

        scan_report.detected_language = structure.get("language")
        scan_report.detected_frameworks = json.dumps(structure.get("frameworks", []))
        db.commit()

        # ── Step 3: Run Security Scanners ────────────────────────────────
        log.info(f"[Scan {scan_id}] Running security scanners…")

        # Native scanner always runs first (no external tools required)
        native_findings = run_native_scanner(clone_path)

        # Semgrep and Bandit run if installed (best-effort)
        semgrep_findings = run_semgrep(clone_path)
        bandit_findings = run_bandit(clone_path)
        trivy_findings = run_trivy(clone_path)

        all_findings: list[dict[str, Any]] = (
            native_findings + semgrep_findings + bandit_findings + trivy_findings
        )

        log.info(
            f"[Scan {scan_id}] Raw findings — "
            f"Native: {len(native_findings)}, "
            f"Semgrep: {len(semgrep_findings)}, "
            f"Bandit: {len(bandit_findings)}, "
            f"Trivy: {len(trivy_findings)}"
        )

        # ── Step 4: Deduplicate and Cap ──────────────────────────────────
        all_findings = _deduplicate_findings(all_findings)
        all_findings = all_findings[:MAX_FINDINGS_STORED]

        # Count by severity
        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in all_findings:
            sev = f.get("severity", "medium").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        scan_report.total_vulnerabilities = len(all_findings)
        scan_report.critical_count = severity_counts["critical"]
        scan_report.high_count = severity_counts["high"]
        scan_report.medium_count = severity_counts["medium"]
        scan_report.low_count = severity_counts["low"]

        # ── Step 5: Persist Vulnerabilities ─────────────────────────────
        log.info(f"[Scan {scan_id}] Persisting {len(all_findings)} findings…")
        for f in all_findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                file_path=_safe_str(f.get("file"), 500),
                line_number=f.get("line"),
                column_number=f.get("column"),
                issue=_safe_str(f.get("issue", "Unknown issue"), 1000),
                description=_safe_str(f.get("description"), 2000),
                severity=_severity_enum(f.get("severity", "medium")),
                scanner=_scanner_enum(f.get("scanner", "semgrep")),
                rule_id=_safe_str(f.get("rule_id"), 200),
                cve_id=_safe_str(f.get("cve_id"), 50),
                cwe_id=_safe_str(f.get("cwe_id"), 50),
                code_snippet=_safe_str(f.get("code_snippet"), 2000),
                suggested_fix=_safe_str(f.get("suggested_fix"), 2000),
                package_name=_safe_str(f.get("package_name"), 200),
                package_version=_safe_str(f.get("package_version"), 100),
                fixed_version=_safe_str(f.get("fixed_version"), 100),
            )
            db.add(vuln)
        db.flush()

        # ── Step 6: AI Analysis ──────────────────────────────────────────
        log.info(f"[Scan {scan_id}] Running AI analysis…")
        ai_result = await analyse_repository(structure, all_findings)
        scan_report.ai_recommendations = json.dumps(ai_result)
        scan_report.architecture_summary = ai_result.get("security_assessment", "")

        # ── Step 7: Generate CI/CD ───────────────────────────────────────
        log.info(f"[Scan {scan_id}] Generating CI/CD pipeline…")
        cicd_yaml = await generate_cicd_pipeline(repository.full_name, structure)
        scan_report.cicd_yaml = cicd_yaml

        # ── Step 8: Compute Score ────────────────────────────────────────
        scan_report.security_score = scan_report.compute_security_score()

        # Mark complete
        elapsed = time.time() - start_time
        scan_report.status = ScanStatus.COMPLETED
        scan_report.completed_at = datetime.now(timezone.utc)
        scan_report.duration_seconds = round(elapsed, 2)

        # Update repository scan tracking
        repository.last_scanned_at = datetime.now(timezone.utc)
        repository.total_scans = (repository.total_scans or 0) + 1

        db.commit()
        log.info(
            f"[Scan {scan_id}] ✓ Completed in {elapsed:.1f}s "
            f"— score: {scan_report.security_score:.1f} "
            f"— {len(all_findings)} findings"
        )

    except Exception as exc:
        log.error(f"[Scan {scan_id}] ✗ Failed: {exc}", exc_info=True)
        scan_report.status = ScanStatus.FAILED
        scan_report.error_message = str(exc)[:2000]
        scan_report.completed_at = datetime.now(timezone.utc)
        db.commit()

    finally:
        # ── Step 9: Cleanup ──────────────────────────────────────────────
        if clone_path:
            repo_cloner.cleanup(scan_id)

    return scan_report


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Remove duplicate findings by (file, line, rule_id) key.
    Keeps the highest-severity instance.
    """
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    seen: dict[tuple, dict] = {}

    for f in findings:
        key = (
            f.get("file", ""),
            f.get("line"),
            f.get("rule_id", f.get("issue", ""))[:80],
        )
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        else:
            # Keep higher severity
            if severity_rank.get(f.get("severity", ""), 0) > severity_rank.get(
                existing.get("severity", ""), 0
            ):
                seen[key] = f

    # Sort: critical first
    deduped = list(seen.values())
    deduped.sort(
        key=lambda x: severity_rank.get(x.get("severity", "medium"), 2),
        reverse=True,
    )
    return deduped


def _safe_str(value: Any, max_len: int) -> str | None:
    """Safely truncate a value to max_len characters."""
    if value is None:
        return None
    return str(value)[:max_len]
