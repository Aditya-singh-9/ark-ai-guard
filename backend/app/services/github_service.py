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


async def exchange_code_for_token(code: str) -> Optional[str]:
    """
    Exchange a GitHub OAuth authorization code for an access token.

    Args:
        code: The authorization code from GitHub's OAuth callback.

    Returns:
        GitHub access token string, or None if the exchange fails.
    """
    async with httpx.AsyncClient() as client:
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
    async with httpx.AsyncClient() as client:
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
    async with httpx.AsyncClient() as client:
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
    async with httpx.AsyncClient() as client:
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
    async with httpx.AsyncClient() as client:
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


async def create_autofix_pr(
    repo_full_name: str,
    base_branch: str,
    fixes: list[dict]
) -> dict[str, Any]:
    """
    Creates an automated Pull Request with security patches using GitHub Data API.

    Args:
        repo_full_name: e.g. "Aditya-singh-9/ark-ai-guard"
        base_branch: e.g. "main"
        fixes: List of dicts, each with keys 'file_path' and 'fixed_code'

    Returns:
        dict: The resulting PR data from GitHub (e.g. including 'html_url')
    """
    import uuid
    import base64
    token = settings.GITHUB_PAT
    if not token:
        raise ValueError("GITHUB_PAT is not configured in settings")

    # If full name has a trailing slash or whitespace, clean it
    repo_full_name = repo_full_name.strip().strip("/")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    base_url = f"{GITHUB_API}/repos/{repo_full_name}"

    async with httpx.AsyncClient() as client:
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

        # 3. Create a blob for each file that needs fixing
        tree_elements = []
        for fix in fixes:
            blob_content = fix["fixed_code"]
            file_path = fix["file_path"]

            encoded_content = base64.b64encode(blob_content.encode("utf-8")).decode("utf-8")
            blob_resp = await client.post(
                f"{base_url}/git/blobs",
                headers=headers,
                json={"content": encoded_content, "encoding": "base64"}
            )
            if blob_resp.status_code != 201:
                log.error(f"[GitHub] Blob creation failed for {file_path}: {blob_resp.text}")
                continue

            blob_sha = blob_resp.json()["sha"]
            tree_elements.append({
                "path": file_path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha
            })

        if not tree_elements:
            raise GitHubAPIError("No valid file fixes to apply")

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
        commit_msg = f"🛡️ ARK Security: Auto-fix {len(fixes)} vulnerability/vulnerabilities"
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
        pr_body += "### Vulnerabilities Addressed\n"
        
        for idx, fix in enumerate(fixes, 1):
            explanation = fix.get("explanation", "Security Best Practice")
            pr_body += f"{idx}. `{fix['file_path']}`: {explanation}\n"
            
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
        log.info(f"[GitHub] PR created successfully: {pr_data.get('html_url')}")
        return pr_data
