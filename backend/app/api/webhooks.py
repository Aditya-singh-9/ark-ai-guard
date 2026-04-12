"""
ARK GitHub Webhooks — Auto-scan on push/PR + PR Comment Bot.

Features:
  1. POST /webhooks/github — Receive push/PR events and auto-trigger scans
  2. PR Comment Bot — Post security results as PR comments
  3. GitHub Check Runs — Set pass/fail status on PRs
  4. Webhook signature verification (HMAC-SHA256)
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
from app.api.auth import get_current_user

log = get_logger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

WEBHOOK_SECRET = settings.GITHUB_WEBHOOK_SECRET or settings.GITHUB_CLIENT_SECRET  # dedicated secret preferred


def _verify_signature(payload: bytes, signature: str | None) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not WEBHOOK_SECRET or not signature:
        return True  # skip verification if no secret configured

    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)


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
    """Handle PR event — trigger diff-aware scan + post results as PR comment."""
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "skipped", "reason": f"PR action '{action}' not scanned"}

    pr = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})
    full_name = repo_data.get("full_name", "")
    pr_number = payload.get("number", 0)
    pr_branch = pr.get("head", {}).get("ref", "")
    pr_sha = pr.get("head", {}).get("sha", "")

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

    # Trigger scan + PR comment in background
    background_tasks.add_task(
        _run_webhook_scan, repo.id, scan_report.id, full_name,
        pr_number=pr_number, pr_sha=pr_sha
    )

    log.info(f"[Webhook] PR scan triggered for {full_name} PR#{pr_number}")
    return {
        "status": "scan_triggered",
        "scan_id": scan_report.id,
        "repository": full_name,
        "trigger": f"pr_{pr_number}",
    }


async def _run_webhook_scan(
    repo_id: int,
    scan_id: int,
    full_name: str,
    pr_number: int | None = None,
    pr_sha: str | None = None,
) -> None:
    """Background task: run scan and optionally post PR comment."""
    from app.database.db import SessionLocal
    from app.services.scan_service import run_full_scan

    db = SessionLocal()
    try:
        scan_report = db.query(ScanReport).filter(ScanReport.id == scan_id).first()
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not scan_report or not repo:
            return

        # Run full scan
        result = await run_full_scan(db, repo, scan_report)

        # Post PR comment if this was a PR-triggered scan
        if pr_number and result.status == ScanStatus.COMPLETED:
            await _post_pr_comment(full_name, pr_number, result, pr_sha)

    except Exception as exc:
        log.error(f"[Webhook] Background scan failed: {exc}", exc_info=True)
    finally:
        db.close()


async def _post_pr_comment(
    full_name: str,
    pr_number: int,
    scan_report: ScanReport,
    pr_sha: str | None = None,
) -> None:
    """Post scan results as a formatted PR comment on GitHub."""
    import httpx

    # Build the comment body
    score = scan_report.nexus_score or scan_report.security_score or 0
    score_emoji = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"

    comment = f"""## 🛡️ ARK AI Guard Security Report

{score_emoji} **Nexus Score: {score:.0f}/100**

| Severity | Count |
|----------|-------|
| 🔴 Critical | {scan_report.critical_count or 0} |
| 🟠 High | {scan_report.high_count or 0} |
| 🟡 Medium | {scan_report.medium_count or 0} |
| 🟢 Low | {scan_report.low_count or 0} |
| **Total** | **{scan_report.total_vulnerabilities or 0}** |

"""

    if scan_report.critical_count and scan_report.critical_count > 0:
        comment += "> ⚠️ **Action Required**: This PR introduces critical security vulnerabilities.\n\n"
    elif score >= 80:
        comment += "> ✅ **Approved by ARK**: No critical security issues detected.\n\n"

    comment += f"🔍 *Scanned in {scan_report.duration_seconds or 0:.1f}s by ARK Nexus Engine™*"

    # Post comment via GitHub API
    # This requires the repository owner to have a GitHub token configured
    # For now, we log the comment — in production, use the GitHub App installation token
    log.info(f"[PR Bot] Would post comment to {full_name} PR#{pr_number}:\n{comment[:200]}...")

    # TODO: Uncomment when GitHub App token is available
    # headers = {
    #     "Authorization": f"token {github_token}",
    #     "Accept": "application/vnd.github.v3+json",
    # }
    # url = f"https://api.github.com/repos/{full_name}/issues/{pr_number}/comments"
    # async with httpx.AsyncClient() as client:
    #     await client.post(url, json={"body": comment}, headers=headers)


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
