"""
Rate limiting configuration for ARK AI Guard.

Strategy:
  - Authenticated routes  → keyed by user_id  (prevents VPN/proxy bypass)
  - Unauthenticated routes → keyed by IP        (standard IP-based throttling)

This makes the scan limit truly per-user, not per-IP.
"""
from typing import Optional
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _get_rate_limit_key(request: Request) -> str:
    """
    Smart rate limit key:
    - If the request carries a valid JWT, use the user's DB id.
    - Otherwise fall back to IP address.
    This prevents authenticated users from bypassing limits via VPN/proxies.
    """
    auth_header: Optional[str] = request.headers.get("Authorization", "")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from jose import jwt as _jwt
            from app.utils.config import settings
            payload = _jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},  # don't fail on expired during key extraction
            )
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except Exception:
            pass  # Fall through to IP-based key
    return get_remote_address(request)  # unauthenticated: use IP


# Shared SlowAPI Limiter instance — uses smart key function
limiter = Limiter(key_func=_get_rate_limit_key)
