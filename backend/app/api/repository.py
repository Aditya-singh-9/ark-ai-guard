"""
Repository management router.

Endpoints:
  POST   /connect-repository        Connect a GitHub repo to user account
  GET    /repositories              List user's connected repositories
  GET    /repositories/{repo_id}   Get a single repository
  DELETE /repositories/{repo_id}   Remove a repository connection
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_decrypted_token
from app.database.db import get_db
from app.models.repository import Repository
from app.models.user import User
from app.services import github_service
from app.utils.logger import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["Repositories"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class ConnectRepositoryRequest(BaseModel):
    repository_url: str

    @field_validator("repository_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        parsed = github_service.validate_github_url(v)
        if not parsed:
            raise ValueError(
                "Must be a valid GitHub repository URL "
                "(e.g. https://github.com/owner/repo)"
            )
        return v.strip()


class RepositoryResponse(BaseModel):
    id: int
    name: str
    owner: str
    full_name: str
    url: str
    language: Optional[str]
    description: Optional[str]
    is_private: bool
    total_scans: int
    last_scanned_at: Optional[str]

    class Config:
        from_attributes = True


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post(
    "/connect-repository",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Connect a GitHub Repository",
)
async def connect_repository(
    body: ConnectRepositoryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Repository:
    """
    Validate a GitHub repository URL and connect it to the user's account.
    Fetches metadata from the GitHub API and stores it in the database.
    """
    parsed = github_service.validate_github_url(body.repository_url)
    owner, repo_name = parsed  # type: ignore[misc]

    # Check if already connected
    existing = (
        db.query(Repository)
        .filter(
            Repository.owner == owner,
            Repository.name == repo_name,
            Repository.user_id == current_user.id,
        )
        .first()
    )
    if existing:
        log.info(f"Repository already connected: {owner}/{repo_name}")
        return existing

    # Fetch metadata from GitHub API
    gh_token = get_decrypted_token(current_user)
    repo_info: Optional[dict] = None

    if gh_token:
        repo_info = await github_service.get_repository_info(owner, repo_name, gh_token)

    if repo_info is None:
        # Try as public repo without auth
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo_name}",
                    headers={"Accept": "application/vnd.github+json"},
                    timeout=10.0,
                )
            if resp.status_code == 200:
                repo_info = resp.json()
            elif resp.status_code == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Repository '{owner}/{repo_name}' not found. "
                           "If it's private, make sure your GitHub token has the 'repo' scope.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    # Build repository record
    clone_url = (
        repo_info.get("clone_url")
        if repo_info
        else f"https://github.com/{owner}/{repo_name}.git"
    )

    repository = Repository(
        github_repo_id=repo_info.get("id") if repo_info else None,
        name=repo_name,
        owner=owner,
        full_name=f"{owner}/{repo_name}",
        url=body.repository_url.strip(),
        clone_url=clone_url,
        default_branch=(repo_info.get("default_branch", "main") if repo_info else "main"),
        language=repo_info.get("language") if repo_info else None,
        description=repo_info.get("description") if repo_info else None,
        is_private=repo_info.get("private", False) if repo_info else False,
        user_id=current_user.id,
    )
    db.add(repository)
    db.commit()
    db.refresh(repository)

    log.info(f"Repository connected: {repository.full_name} (id={repository.id})")
    return repository


@router.get(
    "/repositories",
    response_model=list[RepositoryResponse],
    summary="List Connected Repositories",
)
def list_repositories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Repository]:
    """Return all repositories connected by the authenticated user."""
    repos = (
        db.query(Repository)
        .filter(Repository.user_id == current_user.id)
        .order_by(Repository.id.desc())
        .all()
    )
    return repos


@router.get(
    "/repositories/{repo_id}",
    response_model=RepositoryResponse,
    summary="Get Repository",
)
def get_repository(
    repo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Repository:
    """Return a single repository owned by the current user."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


@router.delete(
    "/repositories/{repo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove Repository",
)
def delete_repository(
    repo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Remove a repository connection and all associated scans."""
    repo = (
        db.query(Repository)
        .filter(Repository.id == repo_id, Repository.user_id == current_user.id)
        .first()
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    db.delete(repo)
    db.commit()
    log.info(f"Repository deleted: {repo.full_name} (id={repo_id})")
