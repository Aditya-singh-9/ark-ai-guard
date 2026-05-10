"""
Authentication router — GitHub OAuth + JWT issuance + Email/Password auth.

Endpoints:
  POST /auth/github           Exchange GitHub OAuth code for a JWT
  POST /auth/register         Register with email + password (OTP sent, no JWT yet)
  POST /auth/verify-email     Verify OTP and receive JWT
  POST /auth/resend-otp       Resend verification OTP
  POST /auth/login            Login with email + password
  GET  /auth/me               Return current user profile
  POST /auth/logout           Revoke JWT (server-side denylist)
  POST /auth/forgot-password  Send a password-reset email
  POST /auth/reset-password   Validate reset token and set new password
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import re
import uuid
import secrets
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
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
    github_id: Optional[int] = None
    username: str
    email: Optional[str]
    display_name: Optional[str]
    avatar_url: Optional[str]
    auth_provider: str = "github"
    created_at: datetime


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    display_name: Optional[str] = None


_PASSWORD_RE = re.compile(
    r'^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>\/?]).{8,}$'
)


def _validate_password_strength(password: str) -> None:
    """Raise HTTPException 400 if password does not meet complexity requirements."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if not _PASSWORD_RE.match(password):
        raise HTTPException(
            status_code=400,
            detail=(
                "Password must contain at least one uppercase letter, "
                "one digit, and one special character (!@#$%^&* etc.)."
            ),
        )


class EmailLoginRequest(BaseModel):
    email: str
    password: str


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
        user = None
        # Check if email is already registered via Email/Password
        if email:
            existing_email = db.query(User).filter(User.email == email).first()
            if existing_email:
                existing_email.github_id = gh_user["id"]
                existing_email.avatar_url = gh_user.get("avatar_url")
                existing_email.access_token_encrypted = _encrypt_token(gh_token)
                existing_email.is_email_verified = 1
                db.commit()
                db.refresh(existing_email)
                user = existing_email

        if not user:
            base_username = gh_user.get("login", "")
            username = base_username
            suffix = 1
            # Ensure unique username
            while db.query(User).filter(User.username == username).first():
                username = f"{base_username}_{suffix}"
                suffix += 1

            user = User(
                github_id=gh_user["id"],
                username=username,
                email=email,
                display_name=gh_user.get("name"),
                avatar_url=gh_user.get("avatar_url"),
                access_token_encrypted=_encrypt_token(gh_token),
                last_login_at=datetime.now(timezone.utc),
                is_email_verified=1,  # GitHub already verifies emails
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


# ── Email / Password Auth ─────────────────────────────────────────────────────

class VerificationResponse(BaseModel):
    requires_verification: bool
    email: str
    message: str


class VerifyEmailRequest(BaseModel):
    email: str
    otp: str


class ResendOtpRequest(BaseModel):
    email: str


def _generate_otp() -> tuple[str, str, datetime]:
    """Generate a 6-digit OTP, its SHA-256 hash, and expiry (10 min)."""
    raw_otp = "{:06d}".format(secrets.randbelow(1_000_000))
    otp_hash = hashlib.sha256(raw_otp.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    return raw_otp, otp_hash, expires_at


@router.post("/register", summary="Register with Email/Password")
@limiter.limit("5/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Register a new account. Returns a verification prompt — no JWT until OTP confirmed."""
    import bcrypt
    from app.services.email_service import send_verification_otp_email

    # Password strength enforcement (email already validated by EmailStr)
    _validate_password_strength(body.password)
    if not re.match(r'^[\w.@+-]+$', body.username):
        raise HTTPException(status_code=400, detail="Username contains invalid characters.")

    # Check uniqueness
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username is already taken.")

    raw_otp, otp_hash, expires_at = _generate_otp()

    user = User(
        github_id=None,
        username=body.username,
        email=body.email,
        display_name=body.display_name or body.username,
        avatar_url=None,
        auth_provider="email",
        password_hash=bcrypt.hashpw(body.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        last_login_at=datetime.now(timezone.utc),
        is_email_verified=0,
        email_otp_hash=otp_hash,
        email_otp_expires_at=expires_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    send_verification_otp_email(
        to_email=user.email,
        username=user.display_name or user.username,
        otp=raw_otp,
    )
    log.info(f"New email user registered (unverified): {user.username} — OTP sent")

    return {
        "requires_verification": True,
        "email": user.email,
        "message": "Account created! Check your email for the 6-digit verification code.",
    }


@router.post("/verify-email", response_model=TokenResponse, summary="Verify Email with OTP")
@limiter.limit("10/minute")
async def verify_email(
    request: Request,
    body: VerifyEmailRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Verify 6-digit OTP sent after registration. Issues a JWT on success."""
    otp_hash = hashlib.sha256(body.otp.strip().encode()).hexdigest()

    user = db.query(User).filter(
        User.email == body.email,
        User.auth_provider == "email",
    ).first()

    if not user:
        raise HTTPException(status_code=400, detail="Account not found.")

    if bool(user.is_email_verified):
        # Already verified — just issue token
        jwt_token = create_access_token({"sub": str(user.id), "username": user.username})
        return {
            "access_token": jwt_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id,
                "github_id": None,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
                "avatar_url": None,
                "auth_provider": "email",
            },
        }

    if user.email_otp_hash != otp_hash:
        raise HTTPException(status_code=400, detail="Incorrect verification code. Please try again.")

    if user.email_otp_expires_at is None or \
       datetime.now(timezone.utc) > user.email_otp_expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new one.")

    # Mark verified and clear OTP
    user.is_email_verified = 1
    user.email_otp_hash = None
    user.email_otp_expires_at = None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    log.info(f"Email verified for user: {user.username}")
    jwt_token = create_access_token({"sub": str(user.id), "username": user.username})

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "github_id": None,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": None,
            "auth_provider": "email",
        },
    }


@router.post("/resend-otp", summary="Resend Email Verification OTP")
@limiter.limit("3/minute")
async def resend_otp(
    request: Request,
    body: ResendOtpRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Regenerate and resend the 6-digit verification OTP."""
    from app.services.email_service import send_verification_otp_email

    user = db.query(User).filter(
        User.email == body.email,
        User.auth_provider == "email",
    ).first()

    # Always return success to prevent email enumeration
    if not user or bool(user.is_email_verified):
        return {"message": "If a pending verification exists for that email, a new code has been sent."}

    raw_otp, otp_hash, expires_at = _generate_otp()
    user.email_otp_hash = otp_hash
    user.email_otp_expires_at = expires_at
    db.commit()

    send_verification_otp_email(
        to_email=user.email,
        username=user.display_name or user.username,
        otp=raw_otp,
    )
    log.info(f"OTP resent for: {user.email}")
    return {"message": "If a pending verification exists for that email, a new code has been sent."}


@router.post("/login", response_model=TokenResponse, summary="Login with Email/Password")
@limiter.limit("10/minute")
async def email_login(
    request: Request,
    body: EmailLoginRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Authenticate with email and password. Blocks unverified accounts."""
    import bcrypt

    user = db.query(User).filter(
        User.email == body.email,
        User.auth_provider == "email",
    ).first()

    if not user or not user.password_hash or not bcrypt.checkpw(body.password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # Block login until email is verified
    if not bool(user.is_email_verified):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="requires_verification",
            headers={"X-Verification-Email": user.email},
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    log.info(f"Email user logged in: {user.username}")
    jwt_token = create_access_token({"sub": str(user.id), "username": user.username})

    return {
        "access_token": jwt_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "github_id": None,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "auth_provider": "email",
        },
    }


# ── Password Reset ─────────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@router.post("/forgot-password", summary="Request Password Reset Email")
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    body: ForgotPasswordRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Send a password-reset email if the email belongs to an email/password account.
    Always returns 200 to avoid leaking account existence.
    """
    import secrets
    import hashlib
    from app.services.email_service import send_password_reset_email

    user = db.query(User).filter(
        User.email == body.email,
        User.auth_provider == "email",
    ).first()

    # Always return success to avoid email enumeration
    if not user:
        log.info(f"[ForgotPassword] No email account found for {body.email} — returning 200 silently")
        return {"message": "If that email exists, a reset link has been sent."}

    # Generate a cryptographically secure token
    raw_token = secrets.token_urlsafe(48)           # 64-char URL-safe string
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    # Persist the hash + expiry (we never store the raw token)
    user.reset_token_hash = token_hash
    user.reset_token_expires_at = expires_at
    db.commit()

    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={raw_token}"
    send_password_reset_email(
        to_email=user.email,
        username=user.display_name or user.username,
        reset_url=reset_url,
    )

    log.info(f"[ForgotPassword] Reset link issued for {user.email}")
    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/reset-password", summary="Reset Password with Token")
@limiter.limit("5/minute")
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Validate the reset token and update the user's password.
    The token is single-use and expires in 30 minutes.
    """
    import hashlib
    import bcrypt

    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    token_hash = hashlib.sha256(body.token.encode()).hexdigest()

    user = db.query(User).filter(
        User.reset_token_hash == token_hash,
        User.auth_provider == "email",
    ).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    # Check expiry
    if user.reset_token_expires_at is None or \
       datetime.now(timezone.utc) > user.reset_token_expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=400, detail="Reset token has expired. Please request a new one.")

    # Update password and invalidate token
    user.password_hash = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()

    log.info(f"[ResetPassword] Password updated for {user.email}")
    return {"message": "Password updated successfully. You can now log in with your new password."}
