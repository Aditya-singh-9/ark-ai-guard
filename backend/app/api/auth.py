"""
Authentication router — GitHub OAuth + JWT issuance.

Endpoints:
  POST /auth/github        Exchange GitHub OAuth code for a JWT
  GET  /auth/me            Return current user profile
  POST /auth/logout        (Stateless: frontend discards token)
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User
from app.services import github_service
from app.utils.config import settings
from app.utils.logger import get_logger
from app.security.token_denylist import deny_token, is_denied

log = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
from app.api.limiter import limiter

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/github", auto_error=False)


# ── Schemas ────────────────────────────────────────────────────────────────────

class GitHubCodeRequest(BaseModel):
    code: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    user: dict


class UserResponse(BaseModel):
    id: int
    github_id: int
    username: str
    email: Optional[str]
    display_name: Optional[str]
    avatar_url: Optional[str]
    created_at: datetime


# ── JWT Helpers ────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    # jti (JWT ID) enables per-token revocation
    to_encode["exp"] = expire
    to_encode["jti"] = str(uuid.uuid4())
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        # Check denylist — revoked tokens are rejected even if signature is valid
        jti = payload.get("jti")
        if jti and is_denied(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _encrypt_token(raw_token: str) -> str:
    """Encrypt a GitHub access token before storing in DB."""
    if not settings.ENCRYPTION_KEY:
        return raw_token  # Return plaintext if no key configured
    try:
        from cryptography.fernet import Fernet
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_token.encode()).decode()
    except Exception:
        return raw_token


def _decrypt_token(encrypted: str) -> str:
    """Decrypt a stored GitHub access token."""
    if not settings.ENCRYPTION_KEY:
        return encrypted
    try:
        from cryptography.fernet import Fernet
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(encrypted.encode()).decode()
    except Exception:
        return encrypted


# ── Dependencies ───────────────────────────────────────────────────────────────

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency — validates JWT and returns the User model."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(token)
    user_id: Optional[int] = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_decrypted_token(user: User) -> str:
    """Return the decrypted GitHub access token for the user."""
    if not user.access_token_encrypted:
        return ""
    return _decrypt_token(user.access_token_encrypted)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/github", response_model=TokenResponse, summary="GitHub OAuth Login")
@limiter.limit("5/minute")
async def github_login(request: Request, body: GitHubCodeRequest, db: Session = Depends(get_db)) -> dict:
    """
    Exchange a GitHub OAuth authorization code for a JWT access token.

    The frontend should redirect to:
    https://github.com/login/oauth/authorize?client_id=CLIENT_ID&scope=repo,user:email

    After authorization, GitHub redirects to GITHUB_REDIRECT_URI with ?code=XXX.
    The frontend then calls this endpoint with the code.
    """
    # 1. Exchange code for GitHub token
    gh_token = await github_service.exchange_code_for_token(body.code)
    if not gh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange GitHub OAuth code for token. Code may be invalid or expired.",
        )

    # 2. Fetch GitHub user profile
    gh_user = await github_service.get_github_user(gh_token)
    if not gh_user:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not retrieve user profile from GitHub API.",
        )

    # 3. Resolve email (profile email may be private)
    email = gh_user.get("email")
    if not email:
        emails = await github_service.get_github_user_emails(gh_token)
        primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
        email = primary["email"] if primary else None

    # 4. Upsert user in DB
    existing = db.query(User).filter(User.github_id == gh_user["id"]).first()
    if existing:
        existing.username = gh_user.get("login", existing.username)
        existing.email = email or existing.email
        existing.avatar_url = gh_user.get("avatar_url")
        existing.display_name = gh_user.get("name")
        existing.access_token_encrypted = _encrypt_token(gh_token)
        existing.last_login_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        user = existing
    else:
        user = User(
            github_id=gh_user["id"],
            username=gh_user.get("login", ""),
            email=email,
            display_name=gh_user.get("name"),
            avatar_url=gh_user.get("avatar_url"),
            access_token_encrypted=_encrypt_token(gh_token),
            last_login_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    log.info(f"User authenticated: {user.username} (id={user.id})")

    # 5. Issue JWT
    jwt_token = create_access_token({"sub": str(user.id), "username": user.username})

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "github_id": user.github_id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
        },
    }


@router.get("/me", response_model=UserResponse, summary="Get Current User")
async def get_me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user's profile."""
    return current_user


@router.post("/logout", summary="Logout")
async def logout(
    token: Optional[str] = Depends(oauth2_scheme),
) -> dict:
    """
    Revoke the current JWT by adding its jti to the denylist.
    Even if the token is not provided, this still returns success (idempotent).
    """
    if token:
        try:
            # Decode without raising — we just want the jti and exp
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},  # might already be expired
            )
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti:
                ttl = max(0, int(exp - datetime.now(timezone.utc).timestamp())) if exp else 86400
                deny_token(jti, ttl)
                log.info(f"[Auth] Token {jti[:8]}... revoked on logout")
        except Exception:
            pass  # Malformed token — still return success
    return {"message": "Logged out successfully. Token has been revoked."}
