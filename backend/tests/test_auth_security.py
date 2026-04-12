"""
Tests — JWT Token Denylist + Auth Security

Tests:
  1. Token denylist: deny + is_denied
  2. Expired tokens auto-expire from denylist
  3. Unknown tokens are NOT in denylist
  4. Logout actually revokes the token
  5. Revoked token rejected on subsequent request
  6. New token creation includes jti claim
  7. Rate limiter key includes user_id for auth requests
"""
import time
import pytest
from app.security.token_denylist import deny_token, is_denied, denylist_size


# ── Token Denylist Unit Tests ─────────────────────────────────────────────────

class TestTokenDenylist:

    def test_unknown_token_not_denied(self):
        assert is_denied("completely-unknown-jti") is False

    def test_deny_token_marks_it_as_denied(self):
        jti = "test-jti-001"
        deny_token(jti, expires_in_seconds=300)
        assert is_denied(jti) is True

    def test_different_token_not_affected(self):
        deny_token("jti-only-this-one", expires_in_seconds=300)
        assert is_denied("jti-different-one") is False

    def test_expired_token_auto_clears(self):
        jti = "jti-short-lived"
        deny_token(jti, expires_in_seconds=1)
        assert is_denied(jti) is True

        # Wait for expiry
        time.sleep(1.5)
        assert is_denied(jti) is False

    def test_is_denied_with_empty_string(self):
        assert is_denied("") is False

    def test_multiple_tokens_tracked_independently(self):
        jti_a = "jti-user-a-session"
        jti_b = "jti-user-b-session"
        deny_token(jti_a, expires_in_seconds=300)

        assert is_denied(jti_a) is True
        assert is_denied(jti_b) is False

    def test_denylist_size_increases_on_deny(self):
        before = denylist_size()
        deny_token(f"unique-jti-{time.time()}", expires_in_seconds=300)
        after = denylist_size()
        assert after >= before + 1

    def test_deny_same_token_twice_is_idempotent(self):
        jti = "double-deny-jti"
        deny_token(jti, expires_in_seconds=300)
        deny_token(jti, expires_in_seconds=300)
        assert is_denied(jti) is True


# ── Auth Integration Tests ─────────────────────────────────────────────────────

class TestJWTRevocation:

    def test_create_token_includes_jti(self):
        from app.api.auth import create_access_token
        from jose import jwt
        from app.utils.config import settings

        token = create_access_token({"sub": "42", "username": "testuser"})
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert "jti" in payload
        assert len(payload["jti"]) == 36  # UUID4 format

    def test_create_two_tokens_have_unique_jtis(self):
        from app.api.auth import create_access_token

        token_a = create_access_token({"sub": "1", "username": "alice"})
        token_b = create_access_token({"sub": "1", "username": "alice"})

        from jose import jwt
        from app.utils.config import settings
        payload_a = jwt.decode(token_a, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        payload_b = jwt.decode(token_b, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload_a["jti"] != payload_b["jti"]

    def test_logout_revokes_token_in_api(self, client, auth_headers_a, token_a):
        """After logout, the same token should be rejected on the next request."""
        # Verify token works before logout
        r_check = client.get("/api/v1/auth/me", headers=auth_headers_a)
        assert r_check.status_code == 200

        # Logout
        r_logout = client.post(
            "/api/v1/auth/logout",
            headers=auth_headers_a,
        )
        assert r_logout.status_code == 200
        assert "revoked" in r_logout.json()["message"].lower()

        # Same token must now be rejected
        r_after = client.get("/api/v1/auth/me", headers=auth_headers_a)
        assert r_after.status_code == 401

    def test_logout_without_token_returns_200(self, client):
        """Logout is idempotent — works even without a token."""
        r = client.post("/api/v1/auth/logout")
        assert r.status_code == 200

    def test_logout_response_contains_message(self, client, auth_headers_a):
        r = client.post("/api/v1/auth/logout", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert "message" in data
        assert len(data["message"]) > 0


# ── Rate Limiter Key Tests ─────────────────────────────────────────────────────

class TestRateLimiterKey:

    def test_authenticated_key_uses_user_prefix(self):
        """Rate limit key for a user-bearing token must start with 'user:'."""
        from app.api.limiter import _get_rate_limit_key
        from app.api.auth import create_access_token
        from unittest.mock import MagicMock

        token = create_access_token({"sub": "99", "username": "testrate"})
        mock_request = MagicMock()
        mock_request.headers.get.return_value = f"Bearer {token}"
        mock_request.client.host = "1.2.3.4"

        key = _get_rate_limit_key(mock_request)
        assert key.startswith("user:"), f"Expected 'user:...' but got: {key!r}"

    def test_unauthenticated_key_uses_ip(self):
        """Rate limit key for a request without a token must be an IP address."""
        from app.api.limiter import _get_rate_limit_key
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.headers.get.return_value = ""  # No auth header
        mock_request.client.host = "5.6.7.8"

        key = _get_rate_limit_key(mock_request)
        # Should return an IP-like string, not user:...
        assert not key.startswith("user:"), f"Expected IP key but got: {key!r}"

    def test_invalid_token_falls_back_to_ip(self):
        """A malformed Bearer token must fall back to IP-based rate limiting."""
        from app.api.limiter import _get_rate_limit_key
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer invalid.token.here"
        mock_request.client.host = "9.10.11.12"

        key = _get_rate_limit_key(mock_request)
        # Invalid token → should fall back to IP
        assert not key.startswith("user:")
