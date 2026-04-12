"""
Scan management router.

Endpoints:
  POST /scan-repository           Initiate a repository security scan
  GET  /scan-results/{repo_id}    Get the latest scan result for a repo
  GET  /scans/{scan_id}/status    Get a specific scan status (polling)
"""
import asyncio
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_decrypted_token
from app.database.db import get_db
from app.models.repository import Repository
from app.models.scan_report import ScanReport, ScanStatus
from app.models.user import User
from app.services.scan_service import run_full_scan
from app.utils.logger import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["Scanning"])
from app.api.limiter import limiter
from app.utils.config import settings


# ── Schemas ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repository_id: int


class ScanStatusResponse(BaseModel):
    scan_id: int
    repository_id: int
    status: str
    security_score: Optional[float] = None
    nexus_score: Optional[float] = None
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    detected_language: Optional[str] = None
    scan_time: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    scan_phase_detail: Optional[str] = None
    layers_completed: Optional[list] = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_scan(cls, scan: "ScanReport") -> "ScanStatusResponse":
        import json
        layers = None
        try:
            if scan.scan_layers_completed:
                layers = json.loads(scan.scan_layers_completed)
        except Exception:
            pass
        return cls(
            scan_id=scan.id,
            repository_id=scan.repository_id,
            status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            security_score=scan.security_score,
            nexus_score=scan.nexus_score,
            total_vulnerabilities=scan.total_vulnerabilities,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            detected_language=scan.detected_language,
            scan_time=scan.scan_time.isoformat() if scan.scan_time else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            duration_seconds=scan.duration_seconds,
            error_message=scan.error_message,
            scan_phase_detail=scan.scan_phase_detail,
            layers_completed=layers,
        )


class ScanInitiatedResponse(BaseModel):
    scan_id: int
    status: str
    message: str


# ── Background task wrapper ────────────────────────────────────────────────────

def _run_scan_background(
    repo_id: int,
    scan_id: int,
    access_token: str,
) -> None:
    """
    Run the async scan_service.run_full_scan inside a new event loop.
    FastAPI BackgroundTasks are synchronous; we create a fresh loop here.
    """
    import asyncio
    from app.database.db import SessionLocal
    from app.models.repository import Repository
    from app.models.scan_report import ScanReport

    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        scan_report = db.query(ScanReport).filter(ScanReport.id == scan_id).first()
        if repo and scan_report:
            asyncio.run(
                run_full_scan(
                    db=db,
                    repository=repo,
                    scan_report=scan_report,
                    access_token=access_token or None,
                )
            )
    except Exception as exc:
        log.error(f"Background scan error for scan_id={scan_id}: {exc}", exc_info=True)
    finally:
        db.close()


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post(
    "/scan-repository",
    response_model=ScanInitiatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate Repository Security Scan",
)
@limiter.limit(f"{settings.RATE_LIMIT_SCAN_PER_HOUR}/hour")
def initiate_scan(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Start an asynchronous security scan for the specified repository.

    The scan runs in a background task. Poll
    GET /scan-results/{repo_id} or GET /scans/{scan_id}/status to get results.

    Rate limited: up to 10 scans per hour per user.
    """
    # Verify repository ownership
    repo = (
        db.query(Repository)
        .filter(Repository.id == body.repository_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Check for an already-running scan
    running = (
        db.query(ScanReport)
        .filter(
            ScanReport.repository_id == repo.id,
            ScanReport.status.notin_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
        )
        .first()
    )
    if running:
        # If the scan has been running for more than 15 minutes, auto-fail it
        # because the server was likely restarted and it's permanently stuck.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if running.scan_time and (now - running.scan_time).total_seconds() > 900:
            log.warning(f"Cleared stuck scan {running.id} for repo {repo.id} (timed out)")
            running.status = ScanStatus.FAILED
            running.error_message = "Scan timed out (likely due to a server restart)"
            repo.scan_status = "failed"
            db.commit()
            db.refresh(repo)
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A scan is already running for this repository (scan_id={running.id}). "
                       "Please wait for it to complete.",
            )

    # Create a PENDING scan report
    scan_report = ScanReport(repository_id=repo.id, status=ScanStatus.PENDING)
    db.add(scan_report)
    db.commit()
    db.refresh(scan_report)

    scan_id = scan_report.id
    access_token = get_decrypted_token(current_user)

    # Enqueue background task
    background_tasks.add_task(_run_scan_background, repo.id, scan_id, access_token)

    log.info(f"Scan {scan_id} queued for repo {repo.full_name}")

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": (
            f"Scan initiated for {repo.full_name}. "
            f"Poll GET /scan-results/{repo.id} for results."
        ),
    }


@router.get(
    "/scan-results/{repo_id}",
    summary="Get Latest Scan Results",
)
def get_scan_results(
    repo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Return the most recent scan report for the given repository.
    """
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    scan = (
        db.query(ScanReport)
        .filter(ScanReport.repository_id == repo_id)
        .order_by(ScanReport.id.desc())
        .first()
    )
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No scans found for this repository. Run POST /scan-repository first.",
        )
    return ScanStatusResponse.from_orm_scan(scan).model_dump()


@router.get(
    "/scans/{scan_id}/status",
    summary="Poll Scan Status",
)
def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Poll a specific scan's status. Use this for real-time progress updates.
    """
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatusResponse.from_orm_scan(scan).model_dump()


@router.get(
    "/scans/{scan_id}/live-status",
    summary="Live Scan Status — Granular Phase Detail",
)
def get_live_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Poll granular real-time scan phase for the 7-layer Nexus Engine progress.
    Returns scan_phase_detail and layers_completed for live UI updates.
    Poll every 1–2 seconds while scan is running.
    """
    import json
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    layers = []
    try:
        if scan.scan_layers_completed:
            layers = json.loads(scan.scan_layers_completed)
    except Exception:
        pass

    status_str = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
    return {
        "scan_id": scan_id,
        "status": status_str,
        "scan_phase_detail": scan.scan_phase_detail or status_str,
        "layers_completed": layers,
        "nexus_score": scan.nexus_score,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "is_complete": status_str in ("completed", "failed"),
    }


@router.get(
    "/repositories/{repo_id}/scans",
    summary="List All Scans for Repository",
)
def list_repo_scans(
    repo_id: int,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return all scans for a repository, newest first."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    scans = (
        db.query(ScanReport)
        .filter(ScanReport.repository_id == repo_id)
        .order_by(ScanReport.id.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "scan_id": s.id,
            "status": s.status.value,
            "security_score": s.security_score,
            "nexus_score": s.nexus_score,
            "total_vulnerabilities": s.total_vulnerabilities,
            "scan_time": s.scan_time.isoformat() if s.scan_time else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": s.duration_seconds,
            "mythos_risk_level": getattr(s, "mythos_risk_level", None),
            "policy_gate_status": getattr(s, "policy_gate_status", None),
        }
        for s in scans
    ]


# ── Mythos AI Endpoints ──────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/compliance")
async def get_scan_compliance(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get compliance framework analysis (SOC2, PCI DSS, HIPAA, ISO 27001)."""
    import json as _json

    # Ownership check: join through repository to verify user owns this scan
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    compliance = {}
    if hasattr(scan, "compliance_summary") and scan.compliance_summary:
        try:
            compliance = _json.loads(scan.compliance_summary)
        except Exception:
            pass

    return {
        "scan_id": scan_id,
        "compliance": compliance,
        "overall_status": "PASS" if all(
            v.get("status") == "PASS" for v in compliance.values()
        ) else "FAIL" if any(
            v.get("status") == "FAIL" for v in compliance.values()
        ) else "WARN",
    }


@router.get("/scans/{scan_id}/owasp")
async def get_scan_owasp(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get OWASP Top 10 coverage analysis."""
    import json as _json

    # Ownership check
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    owasp = {}
    if hasattr(scan, "owasp_coverage") and scan.owasp_coverage:
        try:
            owasp = _json.loads(scan.owasp_coverage)
        except Exception:
            pass

    return {"scan_id": scan_id, "owasp_top_10": owasp}


@router.get("/scans/{scan_id}/autofixes")
async def get_scan_autofixes(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get AI auto-fix suggestions for vulnerabilities."""
    import json as _json

    # Ownership check
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    fixes = []
    if hasattr(scan, "autofix_suggestions") and scan.autofix_suggestions:
        try:
            fixes = _json.loads(scan.autofix_suggestions)
        except Exception:
            pass

    return {
        "scan_id": scan_id,
        "total_fixes": len(fixes),
        "fixes": fixes,
    }


@router.get("/scans/{scan_id}/policy")
async def get_scan_policy(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get policy-as-code gate status and violations."""
    import json as _json

    # Ownership check
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    violations = []
    if hasattr(scan, "policy_violations") and scan.policy_violations:
        try:
            violations = _json.loads(scan.policy_violations)
        except Exception:
            pass

    return {
        "scan_id": scan_id,
        "gate_status": getattr(scan, "policy_gate_status", "unknown"),
        "violations": violations,
        "total_violations": len([v for v in violations if v.get("action") == "block"]),
        "total_warnings": len([v for v in violations if v.get("action") == "warn"]),
    }


@router.get("/scans/{scan_id}/threat-analysis")
async def get_scan_threat_analysis(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get Mythos™ AI threat analysis including STRIDE, risk level, and attack surface."""
    # Ownership check
    scan = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id, Repository.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "risk_level": getattr(scan, "mythos_risk_level", None),
        "attack_surface_score": getattr(scan, "mythos_attack_surface", None),
        "threat_model": getattr(scan, "threat_model", None),
        "executive_brief": getattr(scan, "executive_brief", None),
    }


@router.post("/scans/{scan_id}/create-pr")
async def create_scan_autofix_pr(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Creates an Auto-Fix Pull Request on GitHub for vulnerabilities found in this scan.
    """
    from app.services.github_service import create_autofix_pr, GitHubAPIError
    import json

    scan = db.query(ScanReport).filter(ScanReport.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Authorize: ensure user owns this repo
    if repo.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    if not getattr(scan, "autofix_suggestions", None):
        raise HTTPException(status_code=400, detail="No autofix suggestions available for this scan")

    # The autofix_suggestions is stored as JSON text in the DB
    try:
        if isinstance(scan.autofix_suggestions, str):
            fixes = json.loads(scan.autofix_suggestions)
        else:
            fixes = scan.autofix_suggestions
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid autofix payload in database")

    if not fixes:
        raise HTTPException(status_code=400, detail="Autofix suggestions list is empty")

    base_branch = scan.branch or "main"
    
    try:
        pr_data = await create_autofix_pr(repo.full_name, base_branch, fixes)
        return {"status": "success", "message": "Pull request created", "pr_url": pr_data.get("html_url")}
    except GitHubAPIError as e:
        raise HTTPException(status_code=502, detail=f"GitHub API Error: {str(e)}")
    except Exception as e:
        log.error(f"Error creating PR: {e}")
        raise HTTPException(status_code=500, detail="Failed to create Auto-Fix PR")
