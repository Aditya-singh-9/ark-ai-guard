"""
GitHub OAuth and API service.
Handles token exchange, user info retrieval, and repository listing.
"""
import httpx
from typing import Any, Optional
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

GITHUB_API = settings.GITHUB_API_BASE

# ── Shared HTTP client ────────────────────────────────────────────────────────
# A single pooled AsyncClient is reused across all GitHub calls so we keep TLS
# connections alive instead of paying a fresh handshake on every request. This
# is the main latency win for the multi-step OAuth login flow.
_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    """Return a lazily-created, process-wide pooled httpx client."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            headers={"Accept": "application/vnd.github+json"},
        )
    return _client


async def close_client() -> None:
    """Close the shared client (call on application shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
        _client = None


async def exchange_code_for_token(code: str) -> Optional[str]:
    """
    Exchange a GitHub OAuth authorization code for an access token.

    Args:
        code: The authorization code from GitHub's OAuth callback.

    Returns:
        GitHub access token string, or None if the exchange fails.
    """
    client = get_client()
    response = await client.post(
        settings.GITHUB_TOKEN_URL,
        data={
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": settings.GITHUB_REDIRECT_URI,
        },
        headers={"Accept": "application/json"},
        timeout=15.0,
    )

    if response.status_code != 200:
        log.error(f"GitHub token exchange failed: {response.status_code} {response.text}")
        return None

    data = response.json()
    token = data.get("access_token")
    if not token:
        log.error(f"No access_token in GitHub response: {data}")
        return None

    log.info("GitHub token exchange successful")
    return token


async def get_github_user(access_token: str) -> Optional[dict[str, Any]]:
    """
    Fetch the authenticated user's profile from the GitHub API.

    Args:
        access_token: A valid GitHub personal access token.

    Returns:
        Dict with user fields, or None on error.
    """
    client = get_client()
    response = await client.get(
        f"{GITHUB_API}/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10.0,
    )

    if response.status_code != 200:
        log.error(f"GitHub /user request failed: {response.status_code}")
        return None

    user = response.json()
    log.info(f"Fetched GitHub user: {user.get('login')}")
    return user


async def get_github_user_emails(access_token: str) -> list[dict]:
    """Fetch user emails (needed when the profile email field is None/private)."""
    client = get_client()
    response = await client.get(
        f"{GITHUB_API}/user/emails",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10.0,
    )
    if response.status_code == 200:
        return response.json()
    return []


async def get_repository_info(
    owner: str, repo_name: str, access_token: str
) -> Optional[dict[str, Any]]:
    """
    Fetch repository metadata from the GitHub API.

    Args:
        owner: Repository owner (user or org).
        repo_name: Repository name.
        access_token: GitHub token with repo scope.

    Returns:
        Repo metadata dict or None.
    """
    client = get_client()
    response = await client.get(
        f"{GITHUB_API}/repos/{owner}/{repo_name}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10.0,
    )

    if response.status_code == 404:
        log.warning(f"Repository {owner}/{repo_name} not found or private")
        return None
    if response.status_code != 200:
        log.error(f"GitHub repo info failed: {response.status_code}")
        return None

    return response.json()


async def list_user_repositories(access_token: str, per_page: int = 50) -> list[dict]:
    """List all repositories accessible to the authenticated user."""
    client = get_client()
    response = await client.get(
        f"{GITHUB_API}/user/repos",
        params={"per_page": per_page, "sort": "updated", "type": "all"},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10.0,
    )
    if response.status_code == 200:
        return response.json()
    return []


def validate_github_url(url: str) -> tuple[str, str] | None:
    """
    Parse a GitHub repository URL and return (owner, repo_name).

    Accepts formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - git@github.com:owner/repo.git

    Returns:
        (owner, repo_name) tuple or None if not a valid GitHub URL.
    """
    url = url.strip().rstrip("/")
    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]

    # HTTPS format
    if url.startswith("https://github.com/"):
        parts = url.replace("https://github.com/", "").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]

    # SSH format
    if url.startswith("git@github.com:"):
        parts = url.replace("git@github.com:", "").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]

    return None

class GitHubAPIError(Exception):
    """Raised when GitHub API calls fail."""
    pass


def _normalize_fix(fix: dict) -> dict:
    """Accept both legacy and new key names for a stored auto-fix."""
    return {
        "file_path": fix.get("file_path") or fix.get("file") or "",
        "original_code": fix.get("original_code") or fix.get("original") or "",
        "fixed_code": fix.get("fixed_code") or fix.get("fixed") or "",
        "explanation": fix.get("explanation", "Security best practice"),
    }


def _apply_snippet_fix(
    file_content: str,
    original_snippet: str,
    fixed_snippet: str,
) -> Optional[str]:
    """
    Safely apply a fix to a file by replacing ONLY the matched snippet.

    Returns the full patched file content, or None if the fix cannot be
    applied safely (snippet not found, empty, or ambiguous). Returning None
    means "skip this fix" — we never overwrite a whole file with a fragment.
    """
    orig = (original_snippet or "").strip()
    fixed = fixed_snippet or ""

    # Guard rails — refuse to patch when we can't be confident.
    if not orig or not fixed:
        return None
    if orig == fixed.strip():
        return None  # no-op

    # Try exact match first.
    occurrences = file_content.count(orig)
    if occurrences == 1:
        return file_content.replace(orig, fixed.strip(), 1)

    # Try line-trimmed match (handles leading/trailing whitespace differences).
    lines = file_content.splitlines(keepends=True)
    match_indices = [i for i, ln in enumerate(lines) if ln.strip() == orig]
    if len(match_indices) == 1:
        idx = match_indices[0]
        # Preserve the original line's leading indentation.
        leading_ws = lines[idx][: len(lines[idx]) - len(lines[idx].lstrip())]
        newline = "\n" if lines[idx].endswith("\n") else ""
        lines[idx] = f"{leading_ws}{fixed.strip()}{newline}"
        return "".join(lines)

    # Ambiguous (0 or >1 matches) — refuse to guess.
    return None


async def create_autofix_pr(
    repo_full_name: str,
    base_branch: str,
    fixes: list[dict],
    access_token: Optional[str] = None,
) -> dict[str, Any]:
    """
    Creates an automated Pull Request with security patches using GitHub Data API.

    SAFETY: Each fix is applied by fetching the file's REAL current content and
    replacing only the matched vulnerable snippet. Fixes whose snippet cannot be
    matched unambiguously are skipped, so a file is never overwritten with a
    truncated fragment.

    Args:
        repo_full_name: e.g. "Aditya-singh-9/ark-ai-guard"
        base_branch: e.g. "main"
        fixes: List of stored auto-fix dicts.
        access_token: The authenticated user's GitHub OAuth token. The PR is
            created as that user. Falls back to the shared GITHUB_PAT only when
            no per-user token is available (e.g. email/password accounts).

    Returns:
        dict: The resulting PR data from GitHub (including 'html_url'),
              plus 'applied_count' and 'skipped' lists.
    """
    import uuid
    import base64
    token = access_token or settings.GITHUB_PAT
    if not token:
        raise ValueError(
            "No GitHub token available. Connect your GitHub account (or configure "
            "GITHUB_PAT) before creating an auto-fix pull request."
        )

    # If full name has a trailing slash or whitespace, clean it
    repo_full_name = repo_full_name.strip().strip("/")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    base_url = f"{GITHUB_API}/repos/{repo_full_name}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Get the ref of the base branch to get the latest commit SHA
        log.info(f"[GitHub] Fetching ref for heads/{base_branch}")
        ref_resp = await client.get(f"{base_url}/git/ref/heads/{base_branch}", headers=headers)
        if ref_resp.status_code != 200:
            raise GitHubAPIError(f"Failed to fetch base branch ref: {ref_resp.text}")
        
        base_commit_sha = ref_resp.json()["object"]["sha"]

        # 2. Get the base commit object to get its tree SHA
        commit_resp = await client.get(f"{base_url}/git/commits/{base_commit_sha}", headers=headers)
        if commit_resp.status_code != 200:
            raise GitHubAPIError("Failed to fetch base commit")
        
        base_tree_sha = commit_resp.json()["tree"]["sha"]

        # 3. For each fix, fetch the REAL file, patch only the matched snippet,
        #    and create a blob from the FULL corrected file content.
        tree_elements = []
        skipped: list[dict] = []
        for raw_fix in fixes:
            fix = _normalize_fix(raw_fix)
            file_path = fix["file_path"]
            if not file_path:
                skipped.append({"file": "", "reason": "missing file path"})
                continue

            # Fetch current file content from the base branch.
            content_resp = await client.get(
                f"{base_url}/contents/{file_path}",
                headers=headers,
                params={"ref": base_branch},
            )
            if content_resp.status_code != 200:
                log.warning(f"[GitHub] Could not fetch {file_path}: {content_resp.status_code}")
                skipped.append({"file": file_path, "reason": "file not found in repo"})
                continue

            try:
                current_content = base64.b64decode(
                    content_resp.json()["content"]
                ).decode("utf-8")
            except Exception:
                skipped.append({"file": file_path, "reason": "binary or undecodable file"})
                continue

            patched = _apply_snippet_fix(
                current_content, fix["original_code"], fix["fixed_code"]
            )
            if patched is None:
                log.info(f"[GitHub] Skipping {file_path}: snippet could not be matched safely")
                skipped.append({"file": file_path, "reason": "snippet not matched unambiguously"})
                continue

            encoded_content = base64.b64encode(patched.encode("utf-8")).decode("utf-8")
            blob_resp = await client.post(
                f"{base_url}/git/blobs",
                headers=headers,
                json={"content": encoded_content, "encoding": "base64"}
            )
            if blob_resp.status_code != 201:
                log.error(f"[GitHub] Blob creation failed for {file_path}: {blob_resp.text}")
                skipped.append({"file": file_path, "reason": "blob creation failed"})
                continue

            blob_sha = blob_resp.json()["sha"]
            tree_elements.append({
                "path": file_path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha
            })

        if not tree_elements:
            raise GitHubAPIError(
                "No fixes could be applied safely — every snippet failed to match "
                "its source file. No changes were pushed."
            )

        # 4. Create a new tree with the new blobs, using the base tree
        tree_resp = await client.post(
            f"{base_url}/git/trees",
            headers=headers,
            json={"base_tree": base_tree_sha, "tree": tree_elements}
        )
        if tree_resp.status_code != 201:
            raise GitHubAPIError(f"Failed to create new tree: {tree_resp.text}")
        
        new_tree_sha = tree_resp.json()["sha"]

        # 5. Create a new commit
        applied_count = len(tree_elements)
        commit_msg = f"🛡️ ARK Security: Auto-fix {applied_count} vulnerability/vulnerabilities"
        new_commit_resp = await client.post(
            f"{base_url}/git/commits",
            headers=headers,
            json={
                "message": commit_msg,
                "tree": new_tree_sha,
                "parents": [base_commit_sha]
            }
        )
        if new_commit_resp.status_code != 201:
            raise GitHubAPIError("Failed to create commit")
        
        new_commit_sha = new_commit_resp.json()["sha"]

        # 6. Create a new branch reference pointing to the new commit
        new_branch_name = f"ark-autofix-{uuid.uuid4().hex[:8]}"
        ref_create_resp = await client.post(
            f"{base_url}/git/refs",
            headers=headers,
            json={
                "ref": f"refs/heads/{new_branch_name}",
                "sha": new_commit_sha
            }
        )
        if ref_create_resp.status_code != 201:
            raise GitHubAPIError(f"Failed to create branch: {ref_create_resp.text}")

        # 7. Create the Pull Request
        pr_body = "## 🛡️ ARK AI Guard — Automated Security Patch\n\n"
        pr_body += "This PR was automatically generated by the **ARK Nexus Engine** to fix identified security vulnerabilities.\n\n"
        pr_body += f"### Vulnerabilities Addressed ({applied_count})\n"

        for idx, el in enumerate(tree_elements, 1):
            pr_body += f"{idx}. `{el['path']}`\n"

        if skipped:
            pr_body += f"\n### ⚠️ Skipped ({len(skipped)})\n"
            pr_body += "These fixes could not be applied automatically and need manual review:\n"
            for s in skipped:
                pr_body += f"- `{s['file']}` — {s['reason']}\n"

        pr_body += "\n---\n**🤖 Review carefully before merging!** Although fixes are generated by our high-confidence AI pipeline, always ensure it does not introduce breaking logic changes to your application."

        pr_resp = await client.post(
            f"{base_url}/pulls",
            headers=headers,
            json={
                "title": commit_msg,
                "head": new_branch_name,
                "base": base_branch,
                "body": pr_body
            }
        )

        if pr_resp.status_code != 201:
            raise GitHubAPIError(f"Failed to create Pull Request: {pr_resp.text}")

        pr_data = pr_resp.json()
        log.info(
            f"[GitHub] PR created successfully: {pr_data.get('html_url')} "
            f"({applied_count} applied, {len(skipped)} skipped)"
        )
        pr_data["applied_count"] = applied_count
        pr_data["skipped"] = skipped
        return pr_data
