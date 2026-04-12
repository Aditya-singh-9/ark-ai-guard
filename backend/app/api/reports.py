"""
Reports router — vulnerability reports, CI/CD generation, SBOM, trends, and badges.

Endpoints:
  GET  /vulnerability-report/{scan_id}     Full vulnerability report for a scan
  POST /generate-cicd                      Generate a CI/CD pipeline for a repo
  GET  /dashboard/stats                    Aggregate security stats for the user
  GET  /repositories/{id}/trends           Scan score trend history for a repo
  GET  /repositories/{id}/sbom             Download Software Bill of Materials
  GET  /repositories/{id}/badge            Security score badge SVG
  GET  /vulnerability-report/{id}/download Download HTML report
  POST /notifications/test-slack           Test Slack webhook
"""
import json
import subprocess
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
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
            "severity": (v.severity.value if hasattr(v.severity, "value") else v.severity) if v.severity else "medium",
            "scanner": (v.scanner.value if hasattr(v.scanner, "value") else v.scanner) if v.scanner else "unknown",
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
        "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
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

    if latest_scan:
        try:
            frameworks = json.loads(latest_scan.detected_frameworks or "[]")
        except json.JSONDecodeError:
            frameworks = []

        # Try to enrich with structure data from a live clone if available
        has_docker = False
        package_manifests: list[str] = []
        clone_path = repo_cloner.get_repo_path(repo.full_name)
        if clone_path:
            try:
                live_structure = repo_cloner.analyse_structure(clone_path)
                has_docker = live_structure.get("has_docker", False)
                package_manifests = live_structure.get("package_manifests", [])
                # Prefer live frameworks if richer
                if live_structure.get("frameworks"):
                    frameworks = live_structure["frameworks"]
            except Exception:
                pass

        structure = {
            "language": latest_scan.detected_language or "python",
            "frameworks": frameworks,
            "has_docker": has_docker,
            "package_manifests": package_manifests,
        }
    else:
        # No scan yet — infer from repo metadata if possible
        structure = {
            "language": repo.language or "python",
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


# ── Scan Trend History ──────────────────────────────────────────────────────

@router.get(
    "/repositories/{repo_id}/trends",
    summary="Get Scan Score Trend History",
)
def get_scan_trends(
    repo_id: int,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the last N completed scans for a repo as a time series."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    scans = (
        db.query(ScanReport)
        .filter(
            ScanReport.repository_id == repo_id,
            ScanReport.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanReport.id.desc())
        .limit(limit)
        .all()
    )

    trend_points = [
        {
            "scan_id": s.id,
            "date": s.completed_at.isoformat() if s.completed_at else s.scan_time.isoformat(),
            "security_score": s.security_score,
            "total_vulnerabilities": s.total_vulnerabilities,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "duration_seconds": s.duration_seconds,
        }
        for s in reversed(scans)  # chronological order
    ]

    return {
        "repository_id": repo_id,
        "repository_name": repo.full_name,
        "total_scans": len(trend_points),
        "trend": trend_points,
    }


# ── SBOM Generator ─────────────────────────────────────────────────────────────

@router.get(
    "/repositories/{repo_id}/sbom",
    summary="Download Software Bill of Materials (SBOM)",
)
def get_sbom(
    repo_id: int,
    format: str = "cyclonedx",  # cyclonedx | spdx
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download an SBOM for the repository using Trivy."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    repo_path = repo_cloner.get_repo_path(repo.full_name)
    if not repo_path:
        raise HTTPException(status_code=404, detail="Repository not cloned yet. Run a scan first.")

    sbom_format = "cyclonedx" if format != "spdx" else "spdx-json"
    
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", sbom_format, "--no-progress", "--quiet", repo_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        sbom_content = result.stdout or "{}"
    except FileNotFoundError:
        # Trivy not installed — generate a basic SBOM from scan data
        latest_scan = (
            db.query(ScanReport)
            .filter(ScanReport.repository_id == repo_id, ScanReport.status == ScanStatus.COMPLETED)
            .order_by(ScanReport.id.desc()).first()
        )
        vulns = db.query(Vulnerability).filter(
            Vulnerability.scan_id == latest_scan.id if latest_scan else False
        ).all() if latest_scan else []
        
        components = [
            {"type": "library", "name": v.package_name, "version": v.package_version or "unknown"}
            for v in vulns if v.package_name
        ]
        sbom_content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {"component": {"name": repo.full_name, "type": "application"}},
            "components": components,
        }, indent=2)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {exc}")

    content_type = "application/json"
    filename = f"sbom-{repo.name}-{sbom_format}.json"
    return Response(
        content=sbom_content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Security Badge SVG ──────────────────────────────────────────────────────

@router.get(
    "/repositories/{repo_id}/badge",
    summary="Get Security Score Badge SVG",
    include_in_schema=False,
)
def get_security_badge(
    repo_id: int,
    db: Session = Depends(get_db),
):
    """Return a Shields.io-style SVG badge showing the security score."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id)
        .first()
    )
    latest_scan = (
        db.query(ScanReport)
        .filter(ScanReport.repository_id == repo_id, ScanReport.status == ScanStatus.COMPLETED)
        .order_by(ScanReport.id.desc()).first()
    ) if repo else None
    
    if not repo or not latest_scan or latest_scan.security_score is None:
        score_text = "unknown"
        color = "#9e9e9e"
    else:
        score = int(latest_scan.security_score)
        score_text = f"{score}%"
        color = "#4caf50" if score >= 80 else "#ff9800" if score >= 50 else "#f44336"

    label = "ARK Security"
    label_width = len(label) * 6 + 10
    value_width = len(score_text) * 7 + 10
    total_width = label_width + value_width

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total_width}" height="20" fill="#555"/>
  <rect rx="3" x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
  <rect rx="3" width="{total_width}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_width // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_width // 2}" y="14">{label}</text>
    <text x="{label_width + value_width // 2}" y="15" fill="#010101" fill-opacity=".3">{score_text}</text>
    <text x="{label_width + value_width // 2}" y="14">{score_text}</text>
  </g>
</svg>"""

    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=300"},
    )


# ── HTML Report Download ─────────────────────────────────────────────────────

@router.get(
    "/vulnerability-report/{scan_id}/download",
    summary="Download Vulnerability Report as HTML",
)
def download_html_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download a full HTML security report for a scan."""
    scan = (
        db.query(ScanReport)
        .options(joinedload(ScanReport.repository))
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    
    sev_colors = {"critical": "#f44336", "high": "#ff9800", "medium": "#2196f3", "low": "#4caf50"}
    
    vuln_rows = ""
    for v in vulns:
        color = sev_colors.get(v.severity.value if v.severity else "medium", "#9e9e9e")
        vuln_rows += f"""
        <tr>
          <td style="color:{color};font-weight:bold;text-transform:uppercase">{v.severity.value if v.severity else 'N/A'}</td>
          <td><code style="font-size:11px">{v.file_path or ''}</code> L{v.line_number or '?'}</td>
          <td>{v.issue}</td>
          <td style="font-size:12px">{v.suggested_fix or ''}</td>
        </tr>"""

    score = scan.security_score or 0
    score_color = "#4caf50" if score >= 80 else "#ff9800" if score >= 50 else "#f44336"
    scan_date = scan.completed_at or scan.scan_time
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARK Security Report — {scan.repository.full_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0a0a0f; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 16px; padding: 32px; margin-bottom: 24px; border: 1px solid rgba(255,255,255,0.1); }}
  .score {{ font-size: 64px; font-weight: 900; color: {score_color}; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 12px; overflow: hidden; }}
  th {{ background: rgba(255,255,255,0.05); padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; }}
  td {{ padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px; vertical-align: top; }}
  .stat {{ display: inline-block; background: rgba(255,255,255,0.05); border-radius: 8px; padding: 12px 20px; margin: 8px; text-align: center; }}
  .stat-num {{ font-size: 28px; font-weight: 700; }}
  .stat-lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
  .branding {{ text-align: center; margin-top: 40px; color: #4a5568; font-size: 12px; }}
  @media print {{ body {{ background: white; color: black; }} .header {{ background: #f8fafc; color: black; }} }}
</style>
</head>
<body>
<div class="header">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#94a3b8;margin-bottom:8px">⚡ ARK DevSecOps AI — Security Report</div>
      <h1 style="margin:0;font-size:28px">{scan.repository.full_name}</h1>
      <p style="margin:8px 0 0;color:#94a3b8">Scan #{scan.id} • {scan_date.strftime('%B %d, %Y') if scan_date else 'Unknown date'}</p>
    </div>
    <div style="text-align:right">
      <div class="score">{int(score)}%</div>
      <div style="color:#94a3b8;font-size:13px">Security Score</div>
    </div>
  </div>
  <div style="margin-top:24px">
    <span class="stat"><div class="stat-num" style="color:#f44336">{scan.critical_count}</div><div class="stat-lbl">Critical</div></span>
    <span class="stat"><div class="stat-num" style="color:#ff9800">{scan.high_count}</div><div class="stat-lbl">High</div></span>
    <span class="stat"><div class="stat-num" style="color:#2196f3">{scan.medium_count}</div><div class="stat-lbl">Medium</div></span>
    <span class="stat"><div class="stat-num" style="color:#4caf50">{scan.low_count}</div><div class="stat-lbl">Low</div></span>
    <span class="stat"><div class="stat-num">{scan.total_vulnerabilities}</div><div class="stat-lbl">Total</div></span>
  </div>
</div>

<h2 style="color:#94a3b8;font-size:14px;text-transform:uppercase;letter-spacing:1px">Vulnerability Details</h2>
<table>
  <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Recommended Fix</th></tr></thead>
  <tbody>{vuln_rows if vuln_rows else '<tr><td colspan="4" style="text-align:center;padding:40px;color:#94a3b8">No vulnerabilities found — congratulations! 🎉</td></tr>'}</tbody>
</table>

<div class="branding">Generated by ARK DevSecOps AI • {scan_date.strftime('%Y-%m-%d %H:%M UTC') if scan_date else ''}</div>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="ark-report-{scan_id}.html"'},
    )


# ── Slack Webhook Test ───────────────────────────────────────────────────────

class SlackTestRequest(BaseModel):
    webhook_url: str


@router.post(
    "/notifications/test-slack",
    summary="Test Slack Webhook",
)
async def test_slack_webhook(
    body: SlackTestRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Send a test notification to a Slack webhook URL."""
    import httpx
    if not body.webhook_url.startswith("https://hooks.slack.com/"):
        raise HTTPException(status_code=400, detail="Invalid Slack webhook URL.")
    
    payload = {
        "text": f":white_check_mark: ARK DevSecOps AI connected! Scan alerts will be sent here.",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*⚡ ARK DevSecOps AI* — Slack integration active!\nSecurity scan alerts will be delivered here for *{current_user.login or current_user.email or 'your account'}*.",
                },
            }
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(body.webhook_url, json=payload)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Slack returned HTTP {resp.status_code}: {resp.text}")
        return {"status": "ok", "message": "Test notification sent to Slack."}
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to reach Slack: {exc}")

