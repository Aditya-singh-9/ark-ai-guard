"""
Reports router — vulnerability reports and CI/CD generation.

Endpoints:
  GET  /vulnerability-report/{scan_id}   Full vulnerability report for a scan
  POST /generate-cicd                    Generate a CI/CD pipeline for a repo
  GET  /dashboard/stats                  Aggregate security stats for the user
"""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from app.api.auth import get_current_user
from app.database.db import get_db
from app.models.repository import Repository
from app.models.scan_report import ScanReport, ScanStatus
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.cicd_generator import generate_cicd_pipeline
from app.services.repo_cloner import repo_cloner
from app.utils.logger import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["Reports"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class CICDRequest(BaseModel):
    repository_id: int


class CICDResponse(BaseModel):
    repository: str
    language: str
    frameworks: list[str]
    yaml: str


class VulnerabilityItem(BaseModel):
    id: int
    file: Optional[str]
    line: Optional[int]
    issue: str
    description: Optional[str]
    severity: str
    scanner: str
    rule_id: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    code_snippet: Optional[str]
    suggested_fix: Optional[str]
    package_name: Optional[str]
    package_version: Optional[str]
    fixed_version: Optional[str]


class VulnerabilityReport(BaseModel):
    scan_id: int
    repository_name: str
    repository_url: str
    scan_time: str
    completed_at: Optional[str]
    status: str
    security_score: Optional[float]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    detected_language: Optional[str]
    detected_frameworks: list[str]
    ai_recommendations: Optional[dict]
    architecture_summary: Optional[str]
    vulnerabilities: list[VulnerabilityItem]
    cicd_yaml: Optional[str]


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get(
    "/vulnerability-report/{scan_id}",
    response_model=VulnerabilityReport,
    summary="Get Full Vulnerability Report",
)
def get_vulnerability_report(
    scan_id: int,
    severity: Optional[str] = None,   # Filter: critical|high|medium|low
    scanner: Optional[str] = None,    # Filter: semgrep|bandit|trivy
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Return a complete security report for a given scan including all vulnerabilities,
    AI recommendations, security score, and the generated CI/CD pipeline.

    Query parameters:
    - severity: filter results to a single severity level
    - scanner: filter results to a specific scanner
    - limit: max vulnerabilities returned (default 200)
    """
    # Load scan + repository in one query
    scan = (
        db.query(ScanReport)
        .options(joinedload(ScanReport.repository))
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan report not found")

    # Build vulnerability query with optional filters
    vuln_query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        from app.models.vulnerability import Severity
        try:
            sev_enum = Severity(severity.lower())
            vuln_query = vuln_query.filter(Vulnerability.severity == sev_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity: {severity!r}. "
                       "Must be one of: critical, high, medium, low, info",
            )

    if scanner:
        from app.models.vulnerability import ScannerType
        try:
            sc_enum = ScannerType(scanner.lower())
            vuln_query = vuln_query.filter(Vulnerability.scanner == sc_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scanner: {scanner!r}. Must be: semgrep, bandit, trivy",
            )

    from sqlalchemy import case
    from app.models.vulnerability import Severity as SevEnum
    severity_order = case(
        {SevEnum.CRITICAL: 0, SevEnum.HIGH: 1, SevEnum.MEDIUM: 2, SevEnum.LOW: 3, SevEnum.INFO: 4},
        value=Vulnerability.severity,
    )
    vulns = vuln_query.order_by(severity_order).limit(limit).all()

    # Parse stored JSON fields safely
    ai_recs = None
    if scan.ai_recommendations:
        try:
            ai_recs = json.loads(scan.ai_recommendations)
        except json.JSONDecodeError:
            ai_recs = {"security_assessment": scan.ai_recommendations}

    frameworks: list[str] = []
    if scan.detected_frameworks:
        try:
            frameworks = json.loads(scan.detected_frameworks)
        except json.JSONDecodeError:
            frameworks = []

    vuln_items = [
        {
            "id": v.id,
            "file": v.file_path,
            "line": v.line_number,
            "issue": v.issue,
            "description": v.description,
            "severity": v.severity.value if v.severity else "medium",
            "scanner": v.scanner.value if v.scanner else "unknown",
            "rule_id": v.rule_id,
            "cve_id": v.cve_id,
            "cwe_id": v.cwe_id,
            "code_snippet": v.code_snippet,
            "suggested_fix": v.suggested_fix,
            "package_name": v.package_name,
            "package_version": v.package_version,
            "fixed_version": v.fixed_version,
        }
        for v in vulns
    ]

    return {
        "scan_id": scan.id,
        "repository_name": scan.repository.full_name,
        "repository_url": scan.repository.url,
        "scan_time": scan.scan_time.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "status": scan.status.value,
        "security_score": scan.security_score,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "detected_language": scan.detected_language,
        "detected_frameworks": frameworks,
        "ai_recommendations": ai_recs,
        "architecture_summary": scan.architecture_summary,
        "vulnerabilities": vuln_items,
        "cicd_yaml": scan.cicd_yaml,
    }


@router.post(
    "/generate-cicd",
    response_model=CICDResponse,
    summary="Generate CI/CD Pipeline",
)
async def generate_cicd(
    body: CICDRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Generate a GitHub Actions CI/CD pipeline YAML for the specified repository.
    Uses the latest scan's detected tech stack for context.
    Falls back to generic templates if no scan info is available.
    """
    repo = (
        db.query(Repository)
        .filter(Repository.id == body.repository_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Get latest scan for tech stack context
    latest_scan = (
        db.query(ScanReport)
        .filter(
            ScanReport.repository_id == repo.id,
            ScanReport.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanReport.id.desc())
        .first()
    )

    # Build structure dict from scan metadata if available
    if latest_scan:
        try:
            frameworks = json.loads(latest_scan.detected_frameworks or "[]")
        except json.JSONDecodeError:
            frameworks = []
        structure = {
            "language": latest_scan.detected_language or "python",
            "frameworks": frameworks,
            "has_docker": False,
            "package_manifests": [],
        }
    else:
        # No scan yet — use minimal defaults
        structure = {
            "language": "python",
            "frameworks": [],
            "has_docker": False,
            "package_manifests": [],
        }

    yaml_content = await generate_cicd_pipeline(
        repo_name=repo.full_name,
        structure=structure,
    )

    # Persist to latest scan if available
    if latest_scan:
        latest_scan.cicd_yaml = yaml_content
        db.commit()

    return {
        "repository": repo.full_name,
        "language": structure["language"],
        "frameworks": structure["frameworks"],
        "yaml": yaml_content,
    }


@router.get(
    "/dashboard/stats",
    summary="Aggregate Dashboard Statistics",
)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Return aggregate security statistics for the authenticated user's dashboard.
    """
    repos = (
        db.query(Repository)
        .filter(Repository.user_id == current_user.id)
        .all()
    )
    repo_ids = [r.id for r in repos]

    if not repo_ids:
        return {
            "total_repositories": 0,
            "total_scans": 0,
            "average_security_score": None,
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "repositories": [],
        }

    # Latest completed scan per repository
    latest_scans = (
        db.query(ScanReport)
        .filter(
            ScanReport.repository_id.in_(repo_ids),
            ScanReport.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanReport.repository_id, ScanReport.id.desc())
        .all()
    )

    # Keep only the latest scan per repo
    seen_repos: set[int] = set()
    unique_scans: list[ScanReport] = []
    for s in latest_scans:
        if s.repository_id not in seen_repos:
            seen_repos.add(s.repository_id)
            unique_scans.append(s)

    scores = [s.security_score for s in unique_scans if s.security_score is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else None

    total_vulns = sum(s.total_vulnerabilities for s in unique_scans)
    critical = sum(s.critical_count for s in unique_scans)
    high = sum(s.high_count for s in unique_scans)
    medium = sum(s.medium_count for s in unique_scans)
    low = sum(s.low_count for s in unique_scans)

    repo_summaries = []
    for repo in repos:
        scan = next((s for s in unique_scans if s.repository_id == repo.id), None)
        repo_summaries.append(
            {
                "id": repo.id,
                "name": repo.full_name,
                "url": repo.url,
                "language": repo.language,
                "last_scanned_at": (
                    repo.last_scanned_at.isoformat() if repo.last_scanned_at else None
                ),
                "security_score": scan.security_score if scan else None,
                "total_vulnerabilities": scan.total_vulnerabilities if scan else 0,
                "scan_status": scan.status.value if scan else "never_scanned",
            }
        )

    return {
        "total_repositories": len(repos),
        "total_scans": sum(r.total_scans for r in repos),
        "average_security_score": avg_score,
        "total_vulnerabilities": total_vulns,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "repositories": repo_summaries,
    }
