"""
PR Review Bot — posts DevScops Guard findings directly on GitHub pull requests.

What it does for a PR-triggered scan:
  1. Reads the PR diff (GET /pulls/{n}/files) and works out which lines were
     ADDED/CHANGED by the PR.
  2. Posts ONE review containing inline comments on exactly those lines — only
     for findings the PR introduced (not pre-existing repo debt).
  3. Upserts ONE summary comment (edited on every push, never spammed).
  4. Sets a commit status (pending → success/failure) so it can be used as a
     required check in branch protection.

Works with a plain OAuth / PAT token (scopes: `repo`). No GitHub App needed.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

import httpx

from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

GITHUB_API = settings.GITHUB_API_BASE
STATUS_CONTEXT = "DevScops Guard / security"
SUMMARY_MARKER = "<!-- devscops-guard:summary -->"
INLINE_MARKER_PREFIX = "<!-- devscops-guard:finding:"

# Tuning knobs — keep PRs readable and avoid noisy bots.
MAX_INLINE_COMMENTS = 25
MIN_INLINE_SEVERITY = "medium"          # medium/high/critical get inline comments
MAX_FALSE_POSITIVE_PROBABILITY = 0.6    # skip findings the engine itself doubts
FAILING_SEVERITIES = {"critical", "high"}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def parse_added_lines(patch: Optional[str]) -> set[int]:
    """
    Return the set of NEW-file line numbers that were added in a unified diff
    patch (as returned by GitHub's /pulls/{n}/files endpoint).
    """
    added: set[int] = set()
    if not patch:
        return added
    new_line = 0
    for raw in patch.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added.add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue  # removed line — doesn't exist in the new file
        elif raw.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            new_line += 1  # context line
    return added


def _sev(v: Any) -> str:
    s = getattr(v, "severity", None)
    return (getattr(s, "value", s) or "medium").lower()


def _fingerprint(v: Any) -> str:
    return f"{v.rule_id or 'rule'}:{v.file_path}:{v.line_number}"


def _norm_path(p: Optional[str]) -> str:
    p = (p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _inline_body(v: Any) -> str:
    sev = _sev(v)
    parts = [
        f"{_SEV_ICON.get(sev, '⚪')} **{sev.upper()}** — {v.issue}",
    ]
    meta = " · ".join(x for x in [
        f"`{v.rule_id}`" if v.rule_id else "",
        v.cwe_id or "",
        v.cve_id or "",
        f"confidence {v.confidence:.0%}" if v.confidence is not None else "",
    ] if x)
    if meta:
        parts.append(f"<sub>{meta}</sub>")
    if v.ai_summary or v.description:
        parts.append("")
        parts.append((v.ai_summary or v.description)[:800])
    if v.suggested_fix:
        parts.append("")
        parts.append("**💡 Suggested fix**")
        parts.append(v.suggested_fix[:1200])
    parts.append("")
    parts.append(f"{INLINE_MARKER_PREFIX}{_fingerprint(v)} -->")
    return "\n".join(parts)


async def _paginate(client: httpx.AsyncClient, url: str, token: str, max_pages: int = 10) -> list[dict]:
    items: list[dict] = []
    for page in range(1, max_pages + 1):
        r = await client.get(url, headers=_headers(token), params={"per_page": 100, "page": page})
        if r.status_code != 200:
            log.warning(f"[PR Bot] GET {url} page {page} -> {r.status_code}")
            break
        batch = r.json()
        items.extend(batch)
        if len(batch) < 100:
            break
    return items


# ── Public API ───────────────────────────────────────────────────────────────

async def set_commit_status(
    token: str,
    full_name: str,
    sha: str,
    state: str,
    description: str,
    target_url: Optional[str] = None,
) -> None:
    """state: pending | success | failure | error"""
    if not (token and sha):
        return
    payload: dict[str, Any] = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    if target_url:
        payload["target_url"] = target_url
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{GITHUB_API}/repos/{full_name}/statuses/{sha}",
                headers=_headers(token), json=payload,
            )
            if r.status_code not in (200, 201):
                log.warning(f"[PR Bot] status {state} failed: {r.status_code} {r.text[:200]}")
    except httpx.HTTPError as exc:
        log.warning(f"[PR Bot] status {state} network error: {exc}")


def select_pr_findings(
    vulns: Iterable[Any], changed: dict[str, set[int]]
) -> tuple[list[Any], list[Any]]:
    """
    Split findings into:
      - introduced: on a line ADDED by this PR (eligible for inline comments)
      - touched:    elsewhere in a file the PR modified
    Low-confidence findings are dropped from both.
    """
    introduced, touched = [], []
    for v in vulns:
        path = _norm_path(v.file_path)
        if path not in changed:
            continue
        if (v.false_positive_probability or 0) > MAX_FALSE_POSITIVE_PROBABILITY:
            continue
        if v.line_number and v.line_number in changed[path]:
            introduced.append(v)
        else:
            touched.append(v)
    key = lambda v: (_SEV_RANK.get(_sev(v), 4), v.file_path or "", v.line_number or 0)
    return sorted(introduced, key=key), sorted(touched, key=key)


def _build_summary(
    scan_report: Any,
    introduced: list[Any],
    touched: list[Any],
    inline_posted: int,
    dashboard_url: Optional[str],
    passed: bool,
) -> str:
    score = scan_report.nexus_score or scan_report.security_score or 0
    score_icon = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
    counts = {s: 0 for s in _SEV_RANK}
    for v in introduced:
        counts[_sev(v)] += 1

    lines = [
        SUMMARY_MARKER,
        "## 🛡️ DevScops Guard — PR Security Review",
        "",
        ("✅ **No new high-risk issues introduced by this PR.**" if passed
         else "⛔ **This PR introduces high-risk security issues.** Please review the inline comments."),
        "",
        "| | This PR | Whole repo |",
        "|---|---|---|",
        f"| 🔴 Critical | **{counts['critical']}** | {scan_report.critical_count or 0} |",
        f"| 🟠 High | **{counts['high']}** | {scan_report.high_count or 0} |",
        f"| 🟡 Medium | **{counts['medium']}** | {scan_report.medium_count or 0} |",
        f"| 🟢 Low | **{counts['low']}** | {scan_report.low_count or 0} |",
        "",
        f"{score_icon} Repo Nexus Score: **{score:.0f}/100**",
        "",
    ]
    if introduced:
        lines.append(f"<details><summary><b>{len(introduced)} finding(s) on lines changed in this PR</b>"
                     f" ({inline_posted} commented inline)</summary>\n")
        for v in introduced[:50]:
            lines.append(f"- {_SEV_ICON.get(_sev(v), '⚪')} `{v.file_path}:{v.line_number}` — {v.issue}")
        lines.append("\n</details>\n")
    if touched:
        lines.append(f"<details><summary>{len(touched)} pre-existing finding(s) in files you touched</summary>\n")
        for v in touched[:30]:
            lines.append(f"- {_SEV_ICON.get(_sev(v), '⚪')} `{v.file_path}:{v.line_number or '-'}` — {v.issue}")
        lines.append("\n</details>\n")
    footer = f"<sub>Commit `{(scan_report.commit_sha or '')[:7]}` · scanned in {scan_report.duration_seconds or 0:.0f}s"
    if dashboard_url:
        footer += f" · [Full report]({dashboard_url})"
    footer += "</sub>"
    lines.append(footer)
    return "\n".join(lines)


async def post_pr_review(
    token: str,
    full_name: str,
    pr_number: int,
    head_sha: str,
    scan_report: Any,
    vulns: list[Any],
    dashboard_url: Optional[str] = None,
) -> dict[str, Any]:
    """
    Post inline review comments + upsert summary + set commit status.
    Returns a small result dict (useful for logs/tests). Never raises on
    GitHub API errors — a failing bot must not break the scan pipeline.
    """
    base = f"{GITHUB_API}/repos/{full_name}"
    result: dict[str, Any] = {"inline_posted": 0, "introduced": 0, "passed": True}

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Which lines did the PR add?
        files = await _paginate(client, f"{base}/pulls/{pr_number}/files", token, max_pages=30)
        changed = {_norm_path(f["filename"]): parse_added_lines(f.get("patch"))
                   for f in files if f.get("status") != "removed"}

        introduced, touched = select_pr_findings(vulns, changed)
        passed = not any(_sev(v) in FAILING_SEVERITIES for v in introduced)
        result.update(introduced=len(introduced), passed=passed)

        # 2. Inline comments (dedup against what we've already posted on earlier pushes)
        existing = await _paginate(client, f"{base}/pulls/{pr_number}/comments", token)
        already = {
            c["body"].split(INLINE_MARKER_PREFIX, 1)[1].split(" -->", 1)[0]
            for c in existing if INLINE_MARKER_PREFIX in (c.get("body") or "")
        }
        min_rank = _SEV_RANK[MIN_INLINE_SEVERITY]
        to_post = [
            v for v in introduced
            if _SEV_RANK.get(_sev(v), 4) <= min_rank and _fingerprint(v) not in already
        ][:MAX_INLINE_COMMENTS]

        comments = [{
            "path": _norm_path(v.file_path),
            "line": v.line_number,
            "side": "RIGHT",
            "body": _inline_body(v),
        } for v in to_post]

        if comments:
            r = await client.post(
                f"{base}/pulls/{pr_number}/reviews",
                headers=_headers(token),
                json={
                    "commit_id": head_sha,
                    # COMMENT (not REQUEST_CHANGES): GitHub rejects REQUEST_CHANGES
                    # when the token owner is also the PR author.
                    "event": "COMMENT",
                    "body": f"🛡️ DevScops Guard found **{len(comments)}** issue(s) on lines changed in this PR.",
                    "comments": comments,
                },
            )
            if r.status_code in (200, 201):
                result["inline_posted"] = len(comments)
            else:
                # A single bad line position fails the whole batch → fall back
                # to posting comments one-by-one and skip the ones GitHub rejects.
                log.warning(f"[PR Bot] batch review failed ({r.status_code}): {r.text[:300]} — retrying individually")
                for c in comments:
                    rr = await client.post(
                        f"{base}/pulls/{pr_number}/comments",
                        headers=_headers(token),
                        json={**c, "commit_id": head_sha},
                    )
                    if rr.status_code in (200, 201):
                        result["inline_posted"] += 1

        # 3. Upsert the single summary comment
        summary = _build_summary(scan_report, introduced, touched, result["inline_posted"], dashboard_url, passed)
        issue_comments = await _paginate(client, f"{base}/issues/{pr_number}/comments", token)
        mine = next((c for c in issue_comments if SUMMARY_MARKER in (c.get("body") or "")), None)
        if mine:
            await client.patch(f"{base}/issues/comments/{mine['id']}", headers=_headers(token), json={"body": summary})
        else:
            await client.post(f"{base}/issues/{pr_number}/comments", headers=_headers(token), json={"body": summary})

    # 4. Commit status
    if passed:
        desc = "No new high-risk issues" if not introduced else f"{len(introduced)} low/medium issue(s) to review"
    else:
        n = sum(1 for v in introduced if _sev(v) in FAILING_SEVERITIES)
        desc = f"{n} critical/high issue(s) introduced"
    await set_commit_status(token, full_name, head_sha, "success" if passed else "failure", desc, dashboard_url)

    log.info(f"[PR Bot] {full_name}#{pr_number}: {result}")
    return result


# ── Webhook installation ─────────────────────────────────────────────────────

async def find_repo_webhook(token: str, full_name: str, hook_url: str) -> Optional[dict]:
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(f"{GITHUB_API}/repos/{full_name}/hooks", headers=_headers(token))
        if r.status_code != 200:
            return None
        return next((h for h in r.json() if h.get("config", {}).get("url") == hook_url), None)


async def install_repo_webhook(token: str, full_name: str, hook_url: str, secret: str) -> dict:
    """Create (or update) the push + pull_request webhook on a repository."""
    config = {"url": hook_url, "content_type": "json", "insecure_ssl": "0"}
    if secret:
        config["secret"] = secret
    body = {"name": "web", "active": True, "events": ["push", "pull_request"], "config": config}

    existing = await find_repo_webhook(token, full_name, hook_url)
    async with httpx.AsyncClient(timeout=15.0) as client:
        if existing:
            r = await client.patch(f"{GITHUB_API}/repos/{full_name}/hooks/{existing['id']}",
                                   headers=_headers(token), json=body)
        else:
            r = await client.post(f"{GITHUB_API}/repos/{full_name}/hooks", headers=_headers(token), json=body)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"GitHub refused to create webhook ({r.status_code}): {r.json().get('message', r.text[:200])}")
    return r.json()


async def remove_repo_webhook(token: str, full_name: str, hook_url: str) -> bool:
    existing = await find_repo_webhook(token, full_name, hook_url)
    if not existing:
        return False
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.delete(f"{GITHUB_API}/repos/{full_name}/hooks/{existing['id']}", headers=_headers(token))
    return r.status_code == 204
