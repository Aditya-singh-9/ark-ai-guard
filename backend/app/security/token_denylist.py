"""
Token Denylist — JWT revocation store.

Uses an in-memory set for single-process deployments.
When REDIS_URL is configured, uses Redis for multi-process/multi-node support.

Usage:
    from app.security.token_denylist import deny_token, is_denied

    deny_token(jti, expires_in_seconds)  # on logout
    is_denied(jti)                        # on each request
"""
from __future__ import annotations
import time
from threading import Lock
from app.utils.logger import get_logger

log = get_logger(__name__)

# ── In-memory fallback denylist ───────────────────────────────────────────────
# Stores {jti: expiry_unix_timestamp}
_memory_store: dict[str, float] = {}
_lock = Lock()


def _purge_expired() -> None:
    """Remove expired entries to prevent unbounded memory growth."""
    now = time.time()
    expired = [jti for jti, exp in _memory_store.items() if exp < now]
    for jti in expired:
        del _memory_store[jti]


# ── Redis client (lazy initialisation) ────────────────────────────────────────

_redis_client = None
_redis_checked = False


def _get_redis():
    """Try to get a Redis connection. Returns None if unavailable."""
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client
    _redis_checked = True
    try:
        import redis  # type: ignore
        from app.utils.config import settings
        if not getattr(settings, "REDIS_URL", ""):
            return None
        r = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=1)
        r.ping()
        _redis_client = r
        log.info("[TokenDenylist] Redis backend active — distributed revocation enabled.")
        return r
    except Exception as exc:
        log.info(f"[TokenDenylist] Redis unavailable ({exc}) — using in-memory denylist.")
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def deny_token(jti: str, expires_in_seconds: int) -> None:
    """
    Add a JWT ID to the denylist.
    Call this on logout with the token's `jti` claim and remaining TTL.
    """
    redis = _get_redis()
    if redis:
        try:
            redis.setex(f"ark:denied:{jti}", expires_in_seconds, "1")
            return
        except Exception as exc:
            log.warning(f"[TokenDenylist] Redis setex failed: {exc}. Falling back to memory.")

    with _lock:
        _purge_expired()
        _memory_store[jti] = time.time() + expires_in_seconds
    log.debug(f"[TokenDenylist] Token {jti[:8]}… denied (TTL={expires_in_seconds}s)")


def is_denied(jti: str) -> bool:
    """Return True if the token has been revoked."""
    if not jti:
        return False

    redis = _get_redis()
    if redis:
        try:
            return bool(redis.exists(f"ark:denied:{jti}"))
        except Exception:
            pass  # Fall through to memory check

    with _lock:
        expiry = _memory_store.get(jti)
        if expiry is None:
            return False
        if time.time() > expiry:
            del _memory_store[jti]
            return False
        return True


def denylist_size() -> int:
    """Return the number of active denied tokens (for health/monitoring)."""
    redis = _get_redis()
    if redis:
        try:
            keys = redis.keys("ark:denied:*")
            return len(keys)
        except Exception:
            pass
    with _lock:
        _purge_expired()
        return len(_memory_store)
