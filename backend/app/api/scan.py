"""
Scan management router.

Endpoints:
  POST /scan-repository           Initiate a repository security scan
  GET  /scan-results/{repo_id}    Get the latest scan result for a repo
  GET  /scans/{scan_id}/status    Get a specific scan status (polling)
"""
import asyncio
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
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


# ── Schemas ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repository_id: int


class ScanStatusResponse(BaseModel):
    scan_id: int
    repository_id: int
    status: str
    security_score: Optional[float]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    detected_language: Optional[str]
    scan_time: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    error_message: Optional[str]


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
def initiate_scan(
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
            ScanReport.status == ScanStatus.RUNNING,
        )
        .first()
    )
    if running:
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
    response_model=ScanStatusResponse,
    summary="Get Latest Scan Results",
)
def get_scan_results(
    repo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanReport:
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
    return scan


@router.get(
    "/scans/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Poll Scan Status",
)
def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanReport:
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
    return scan


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
            "total_vulnerabilities": s.total_vulnerabilities,
            "scan_time": s.scan_time.isoformat() if s.scan_time else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": s.duration_seconds,
        }
        for s in scans
    ]
