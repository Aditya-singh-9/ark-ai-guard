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
