"""
ARK GitHub Webhooks — Auto-scan on push/PR + PR Comment Bot.

Features:
  1. POST /webhooks/github — Receive push/PR events and auto-trigger scans
  2. PR Review Bot — inline review comments on PR-added lines + one summary comment
  3. Commit statuses — pending/success/failure on the PR head (usable as a required check)
  4. Webhook signature verification (HMAC-SHA256)
  5. /webhooks/pr-review/{repo_id} — one-click enable/disable/status of PR reviews
"""
from __future__ import annotations
import hashlib
import hmac
import json
from typing import Any, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session

from app.utils.config import settings
from app.utils.logger import get_logger
from app.database.db import get_db
from app.models.repository import Repository
from app.models.scan_report import ScanReport, ScanStatus
from app.models.user import User
from app.api.auth import get_current_user, get_decrypted_token
from app.services import pr_review_service

log = get_logger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

WEBHOOK_SECRET = settings.GITHUB_WEBHOOK_SECRET or settings.GITHUB_CLIENT_SECRET  # dedicated secret preferred


def _verify_signature(payload: bytes, signature: str | None) -> bool:
    """
    Verify GitHub webhook HMAC-SHA256 signature.

    Security policy:
    - If a GITHUB_WEBHOOK_SECRET is configured, the signature MUST be present and valid.
    - If no secret is configured AND we are not in production, we allow the request
      but emit a warning (useful for local dev without a tunnel).
    - In production with no secret: reject all webhook requests outright.
    """
    from app.utils.config import settings

    if not WEBHOOK_SECRET:
        if settings.APP_ENV == "production":
            log.error(
                "[Webhook] GITHUB_WEBHOOK_SECRET is not set in production — "
                "all webhook requests are being rejected for safety."
            )
            return False  # REJECT — never allow unsigned webhooks in production
        # Dev/test with no secret: warn and permit (developer convenience only)
        log.warning(
            "[Webhook] GITHUB_WEBHOOK_SECRET is not configured. "
            "Request accepted in non-production mode. Set the secret for security."
        )
        return True

    if not signature:
        log.warning("[Webhook] Received webhook without X-Hub-Signature-256 header — rejected.")
        return False

    if not signature.startswith("sha256="):
        log.warning("[Webhook] Webhook signature has unexpected format — rejected.")
        return False

    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    result = hmac.compare_digest(f"sha256={expected}", signature)
    if not result:
        log.warning("[Webhook] Webhook signature mismatch — possible spoofed request rejected.")
    return result


@router.post("/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    GitHub Webhook receiver.

    Handles:
    - `push` events → triggers auto-scan on default branch
    - `pull_request` events → triggers diff-aware PR scan
    - `ping` events → responds with OK

    Webhook must be configured at: https://github.com/<owner>/<repo>/settings/hooks
    """
    # 1. Verify signature
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not _verify_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 2. Parse event
    event_type = request.headers.get("X-GitHub-Event", "")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    log.info(f"[Webhook] Received {event_type} event")

    # 3. Handle event types
    if event_type == "ping":
        return {"status": "ok", "message": "ARK AI Guard webhook active 🛡️"}

    elif event_type == "push":
        return await _handle_push(payload, background_tasks, db)

    elif event_type == "pull_request":
        return await _handle_pull_request(payload, background_tasks, db)

    elif event_type == "installation":
        return {"status": "ok", "message": "GitHub App installation received"}

    else:
        return {"status": "ignored", "event": event_type}


async def _handle_push(
    payload: dict, background_tasks: BackgroundTasks, db: Session
) -> dict:
    """Handle push event — trigger auto-scan on default branch."""
    repo_data = payload.get("repository", {})
    full_name = repo_data.get("full_name", "")
    ref = payload.get("ref", "")
    default_branch = repo_data.get("default_branch", "main")

    # Only scan pushes to default branch
    if ref != f"refs/heads/{default_branch}":
        return {
            "status": "skipped",
            "reason": f"Push to {ref}, not default branch ({default_branch})",
        }

    # Find repository in our DB
    repo = db.query(Repository).filter(Repository.full_name == full_name).first()
    if not repo:
        return {"status": "skipped", "reason": f"Repository {full_name} not connected"}

    # Create scan report
    scan_report = ScanReport(
        repository_id=repo.id,
        status=ScanStatus.PENDING,
        trigger="webhook_push",
        branch=default_branch,
        commit_sha=payload.get("after", "")[:40],
        scan_phase_detail="Triggered by GitHub push webhook",
    )
    db.add(scan_report)
    db.commit()
    db.refresh(scan_report)

    # Trigger scan in background
    background_tasks.add_task(
        _run_webhook_scan, repo.id, scan_report.id, full_name
    )

    log.info(f"[Webhook] Auto-scan triggered for {full_name} (push to {default_branch})")
    return {
        "status": "scan_triggered",
        "scan_id": scan_report.id,
        "repository": full_name,
        "trigger": "push",
    }


async def _handle_pull_request(
    payload: dict, background_tasks: BackgroundTasks, db: Session
) -> dict:
    """Handle PR event — scan the PR head and post an inline review on the PR."""
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened", "ready_for_review"):
        return {"status": "skipped", "reason": f"PR action '{action}' not scanned"}

    pr = payload.get("pull_request", {})
    if pr.get("draft"):
        return {"status": "skipped", "reason": "Draft PR"}

    repo_data = payload.get("repository", {})
    full_name = repo_data.get("full_name", "")
    pr_number = payload.get("number", 0)
    head = pr.get("head", {}) or {}
    pr_branch = head.get("ref", "")
    pr_sha = head.get("sha", "")
    # Fork PRs: the head branch lives in the fork, so clone from there.
    head_clone_url = (head.get("repo") or {}).get("clone_url")

    # Find repository in our DB
    repo = db.query(Repository).filter(Repository.full_name == full_name).first()
    if not repo:
        return {"status": "skipped", "reason": f"Repository {full_name} not connected"}

    # Create scan report with PR metadata
    scan_report = ScanReport(
        repository_id=repo.id,
        status=ScanStatus.PENDING,
        trigger=f"webhook_pr_{pr_number}",
        branch=pr_branch,
        commit_sha=(pr_sha or "")[:40],
        scan_phase_detail=f"Triggered by PR #{pr_number}",
    )
    db.add(scan_report)
    db.commit()
    db.refresh(scan_report)

    # Trigger scan + PR review in background
    background_tasks.add_task(
        _run_webhook_scan, repo.id, scan_report.id, full_name,
        pr_number=pr_number, pr_sha=pr_sha,
        branch=pr_branch, clone_url=head_clone_url,
    )

    log.info(f"[Webhook] PR scan triggered for {full_name} PR#{pr_number}")
    return {
        "status": "scan_triggered",
        "scan_id": scan_report.id,
        "repository": full_name,
        "trigger": f"pr_{pr_number}",
    }


def _token_for_repo(repo: Repository) -> str:
    """Repo owner's GitHub OAuth token, falling back to the shared PAT."""
    token = ""
    if repo.user is not None:
        token = get_decrypted_token(repo.user)
    return token or settings.GITHUB_PAT


def _report_url(scan_id: int) -> str:
    return f"{settings.FRONTEND_URL.rstrip('/')}/dashboard/scans/{scan_id}/deep"


async def _run_webhook_scan(
    repo_id: int,
    scan_id: int,
    full_name: str,
    pr_number: int | None = None,
    pr_sha: str | None = None,
    branch: str | None = None,
    clone_url: str | None = None,
) -> None:
    """Background task: run scan and, for PRs, post an inline review."""
    from app.database.db import SessionLocal
    from app.services.scan_service import run_full_scan
    from app.models.vulnerability import Vulnerability

    db = SessionLocal()
    token = ""
    try:
        scan_report = db.query(ScanReport).filter(ScanReport.id == scan_id).first()
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not scan_report or not repo:
            return

        token = _token_for_repo(repo)
        report_url = _report_url(scan_id)

        if pr_number and pr_sha:
            await pr_review_service.set_commit_status(
                token, full_name, pr_sha, "pending", "Security scan in progress…", report_url
            )

        result = await run_full_scan(
            db, repo, scan_report,
            access_token=token or None,
            branch=branch,
            clone_url=clone_url,
        )

        if not (pr_number and pr_sha):
            return

        if result.status != ScanStatus.COMPLETED:
            await pr_review_service.set_commit_status(
                token, full_name, pr_sha, "error",
                f"Scan failed: {(result.error_message or 'unknown error')[:100]}", report_url,
            )
            return

        if not token:
            log.warning(f"[PR Bot] No GitHub token for {full_name} — cannot post review")
            return

        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        await pr_review_service.post_pr_review(
            token, full_name, pr_number, pr_sha, result, vulns, report_url
        )

    except Exception as exc:
        log.error(f"[Webhook] Background scan failed: {exc}", exc_info=True)
        if pr_number and pr_sha and token:
            await pr_review_service.set_commit_status(
                token, full_name, pr_sha, "error", "DevScops Guard hit an internal error"
            )
    finally:
        db.close()


# ── PR Review setup (one-click webhook install) ────────────────────────────────

def _hook_url(request: Request) -> str:
    base = settings.BACKEND_PUBLIC_URL.strip().rstrip("/")
    if not base:
        base = str(request.base_url).rstrip("/")
        # Behind Render/other proxies the request may look like plain http.
        if base.startswith("http://") and "localhost" not in base and "127.0.0.1" not in base:
            base = "https://" + base[len("http://"):]
    return f"{base}/api/v1/webhooks/github"


def _owned_repo(db: Session, repo_id: int, user: User) -> Repository:
    repo = db.query(Repository).filter(
        Repository.id == repo_id, Repository.user_id == user.id
    ).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


def _user_token_or_400(user: User) -> str:
    token = get_decrypted_token(user)
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Connect your GitHub account to enable PR reviews.",
        )
    return token


@router.get("/pr-review/{repo_id}")
async def pr_review_status(
    repo_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Is the PR-review webhook installed on this repository?"""
    repo = _owned_repo(db, repo_id, current_user)
    token = get_decrypted_token(current_user)
    if not token:
        return {"enabled": False, "reason": "github_not_connected"}
    hook = await pr_review_service.find_repo_webhook(token, repo.full_name, _hook_url(request))
    return {"enabled": bool(hook and hook.get("active")), "hook_id": hook.get("id") if hook else None}


@router.post("/pr-review/{repo_id}")
async def enable_pr_review(
    repo_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Install the push + pull_request webhook so every PR gets an automatic review."""
    repo = _owned_repo(db, repo_id, current_user)
    token = _user_token_or_400(current_user)
    if not settings.GITHUB_WEBHOOK_SECRET and settings.APP_ENV == "production":
        raise HTTPException(
            status_code=500,
            detail="Server is missing GITHUB_WEBHOOK_SECRET — webhooks would be rejected.",
        )
    try:
        hook = await pr_review_service.install_repo_webhook(
            token, repo.full_name, _hook_url(request), WEBHOOK_SECRET
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"enabled": True, "hook_id": hook.get("id")}


@router.delete("/pr-review/{repo_id}")
async def disable_pr_review(
    repo_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove the PR-review webhook from this repository."""
    repo = _owned_repo(db, repo_id, current_user)
    token = _user_token_or_400(current_user)
    removed = await pr_review_service.remove_repo_webhook(token, repo.full_name, _hook_url(request))
    return {"enabled": False, "removed": removed}


# ── Scan Comparison / Diff API ─────────────────────────────────────────────────

@router.get("/scans/compare/{scan_id_a}/{scan_id_b}")
async def compare_scans(
    scan_id_a: int,
    scan_id_b: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Compare two scan reports side-by-side.

    Returns:
    - New vulnerabilities (in B but not A)
    - Fixed vulnerabilities (in A but not B)
    - Score change
    - Severity breakdown diff
    """
    from app.models.vulnerability import Vulnerability

    # Ownership check: both scans must belong to the requesting user
    scan_a = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id_a, Repository.user_id == current_user.id)
        .first()
    )
    scan_b = (
        db.query(ScanReport)
        .join(Repository, ScanReport.repository_id == Repository.id)
        .filter(ScanReport.id == scan_id_b, Repository.user_id == current_user.id)
        .first()
    )

    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Get vulnerabilities for both scans
    vulns_a = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id_a).all()
    vulns_b = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id_b).all()

    # Build fingerprints (rule_id + file + line)
    def fingerprint(v):
        return f"{v.rule_id}:{v.file_path}:{v.line_number}"

    fps_a = {fingerprint(v): v for v in vulns_a}
    fps_b = {fingerprint(v): v for v in vulns_b}

    new_vulns = [
        {
            "rule_id": v.rule_id,
            "file": v.file_path,
            "line": v.line_number,
            "issue": v.issue,
            "severity": v.severity.value if v.severity else "medium",
        }
        for fp, v in fps_b.items() if fp not in fps_a
    ]

    fixed_vulns = [
        {
            "rule_id": v.rule_id,
            "file": v.file_path,
            "line": v.line_number,
            "issue": v.issue,
            "severity": v.severity.value if v.severity else "medium",
        }
        for fp, v in fps_a.items() if fp not in fps_b
    ]

    score_a = scan_a.nexus_score or scan_a.security_score or 0
    score_b = scan_b.nexus_score or scan_b.security_score or 0

    return {
        "scan_a": {"id": scan_id_a, "score": score_a, "total": len(vulns_a)},
        "scan_b": {"id": scan_id_b, "score": score_b, "total": len(vulns_b)},
        "score_change": round(score_b - score_a, 1),
        "score_trend": "improving" if score_b > score_a else "degrading" if score_b < score_a else "stable",
        "new_vulnerabilities": new_vulns,
        "fixed_vulnerabilities": fixed_vulns,
        "new_count": len(new_vulns),
        "fixed_count": len(fixed_vulns),
        "severity_diff": {
            "critical": (scan_b.critical_count or 0) - (scan_a.critical_count or 0),
            "high": (scan_b.high_count or 0) - (scan_a.high_count or 0),
            "medium": (scan_b.medium_count or 0) - (scan_a.medium_count or 0),
            "low": (scan_b.low_count or 0) - (scan_a.low_count or 0),
        },
    }
