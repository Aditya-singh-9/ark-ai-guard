"""
API Integration Tests — Auth, Ownership, IDOR, Security Headers.

Tests every critical path identified in the organizational audit:
  1. Auth endpoint guarding
  2. IDOR on scan sub-endpoints (compliance, owasp, autofixes, policy, threat)
  3. Cross-user scan isolation
  4. Security headers present on all responses
  5. Rate limiting response format
  6. Unauthenticated access rejection
"""
import pytest
from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

API = "/api/v1"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Authentication Guard Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthGuard:
    """All protected endpoints must return 401/403 without a valid JWT."""

    def test_get_me_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_list_repos_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/repositories/")
        assert r.status_code == 401

    def test_scan_repo_unauthenticated(self, client: TestClient):
        r = client.post(f"{API}/scan-repository", json={"repository_id": 1})
        assert r.status_code == 401

    def test_get_scan_status_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/status")
        assert r.status_code == 401

    def test_compliance_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/compliance")
        assert r.status_code == 401

    def test_owasp_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/owasp")
        assert r.status_code == 401

    def test_autofixes_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/autofixes")
        assert r.status_code == 401

    def test_policy_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/policy")
        assert r.status_code == 401

    def test_threat_analysis_unauthenticated(self, client: TestClient):
        r = client.get(f"{API}/scans/1/threat-analysis")
        assert r.status_code == 401

    def test_get_me_authenticated(self, client: TestClient, auth_headers_a, user_a):
        r = client.get(f"{API}/auth/me", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == user_a.username
        assert data["id"] == user_a.id

    def test_invalid_token_rejected(self, client: TestClient):
        r = client.get(f"{API}/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"})
        assert r.status_code == 401

    def test_malformed_auth_header_rejected(self, client: TestClient):
        r = client.get(f"{API}/auth/me", headers={"Authorization": "NotBearer xyz"})
        assert r.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 2. IDOR Prevention Tests — the audit's critical blocker
# ─────────────────────────────────────────────────────────────────────────────

class TestIDORPrevention:
    """
    User B must NOT be able to access User A's scan data via any endpoint.
    These tests verify the ownership check we added to all Mythos endpoints.
    """

    def test_user_b_cannot_read_user_a_compliance(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/compliance", headers=auth_headers_b)
        # Must be 404 (not 200, not 500, not 403 leaking id existence)
        assert r.status_code == 404, (
            f"IDOR: user_b got {r.status_code} on user_a's compliance scan"
        )

    def test_user_b_cannot_read_user_a_owasp(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/owasp", headers=auth_headers_b)
        assert r.status_code == 404

    def test_user_b_cannot_read_user_a_autofixes(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/autofixes", headers=auth_headers_b)
        assert r.status_code == 404

    def test_user_b_cannot_read_user_a_policy(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/policy", headers=auth_headers_b)
        assert r.status_code == 404

    def test_user_b_cannot_read_user_a_threat(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/threat-analysis", headers=auth_headers_b)
        assert r.status_code == 404

    def test_user_b_cannot_compare_user_a_scans(
        self, client: TestClient, scan_a, scan_b, auth_headers_b
    ):
        r = client.get(
            f"{API}/webhooks/scans/compare/{scan_a.id}/{scan_b.id}",
            headers=auth_headers_b,
        )
        # scan_a belongs to user_a, so user_b comparison should fail
        assert r.status_code in (404, 401)

    def test_user_a_can_read_own_compliance(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/compliance", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert "compliance" in data
        assert data["scan_id"] == scan_a.id

    def test_user_a_can_read_own_owasp(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/owasp", headers=auth_headers_a)
        assert r.status_code == 200
        assert "owasp_top_10" in r.json()

    def test_user_a_can_read_own_autofixes(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/autofixes", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert "fixes" in data
        assert isinstance(data["fixes"], list)

    def test_user_a_can_read_own_policy(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/policy", headers=auth_headers_a)
        assert r.status_code == 200
        assert "gate_status" in r.json()

    def test_user_a_can_read_own_threat(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/threat-analysis", headers=auth_headers_a)
        assert r.status_code == 200
        assert "risk_level" in r.json()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Repository Isolation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRepositoryIsolation:
    """User B cannot access, scan, or see User A's repositories."""

    def test_user_b_cannot_scan_user_a_repo(
        self, client: TestClient, repo_a, auth_headers_b
    ):
        r = client.post(
            f"{API}/scan-repository",
            json={"repository_id": repo_a.id},
            headers=auth_headers_b,
        )
        assert r.status_code == 404

    def test_user_b_cannot_get_user_a_scan_results(
        self, client: TestClient, repo_a, auth_headers_b
    ):
        r = client.get(f"{API}/scan-results/{repo_a.id}", headers=auth_headers_b)
        assert r.status_code == 404

    def test_user_b_cannot_list_user_a_repo_scans(
        self, client: TestClient, repo_a, auth_headers_b
    ):
        r = client.get(f"{API}/repositories/{repo_a.id}/scans", headers=auth_headers_b)
        assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 4. Security Headers Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Every response must include our security hardening headers."""

    def _check_security_headers(self, response):
        headers = response.headers
        assert "x-content-type-options" in headers, "Missing X-Content-Type-Options"
        assert headers["x-content-type-options"] == "nosniff"
        assert "x-frame-options" in headers, "Missing X-Frame-Options"
        assert headers["x-frame-options"] == "DENY"
        assert "referrer-policy" in headers, "Missing Referrer-Policy"
        assert "x-ark-version" in headers, "Missing X-ARK-Version"

    def test_health_endpoint_has_security_headers(self, client: TestClient):
        r = client.get("/health")
        assert r.status_code == 200
        self._check_security_headers(r)

    def test_root_endpoint_has_security_headers(self, client: TestClient):
        r = client.get("/")
        assert r.status_code == 200
        self._check_security_headers(r)

    def test_auth_me_has_security_headers(self, client: TestClient):
        r = client.get(f"{API}/auth/me")
        # Even error responses must have security headers
        assert r.status_code == 401
        self._check_security_headers(r)

    def test_process_time_header_present(self, client: TestClient):
        r = client.get("/health")
        assert "x-process-time-ms" in r.headers


# ─────────────────────────────────────────────────────────────────────────────
# 5. Scan Status & Results Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanStatus:
    """Test the scan status polling endpoints."""

    def test_get_scan_status_own_scan(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/status", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert data["scan_id"] == scan_a.id
        assert data["status"] == "completed"
        assert data["nexus_score"] == pytest.approx(72.5, abs=0.1)

    def test_get_nonexistent_scan_returns_404(
        self, client: TestClient, auth_headers_a
    ):
        r = client.get(f"{API}/scans/99999999/status", headers=auth_headers_a)
        assert r.status_code == 404

    def test_get_live_scan_status(
        self, client: TestClient, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/live-status", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert data["is_complete"] is True
        assert "layers_completed" in data

    def test_user_b_cannot_get_user_a_scan_status(
        self, client: TestClient, scan_a, auth_headers_b
    ):
        r = client.get(f"{API}/scans/{scan_a.id}/status", headers=auth_headers_b)
        assert r.status_code == 404

    def test_list_repo_scans(
        self, client: TestClient, repo_a, scan_a, auth_headers_a
    ):
        r = client.get(f"{API}/repositories/{repo_a.id}/scans", headers=auth_headers_a)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["scan_id"] == scan_a.id


# ─────────────────────────────────────────────────────────────────────────────
# 6. Health & System Endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestSystemEndpoints:
    def test_health_check_returns_healthy(self, client: TestClient):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("healthy", "degraded")
        assert data["service"] is not None

    def test_root_returns_feature_list(self, client: TestClient):
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert "features" in data
        assert len(data["features"]) > 5
        assert data["layers"] == 7

    def test_docs_accessible(self, client: TestClient):
        r = client.get("/docs")
        assert r.status_code == 200

    def test_openapi_schema_accessible(self, client: TestClient):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert schema["info"]["title"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 7. Logout Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_returns_message(self, client: TestClient):
        r = client.post(f"{API}/auth/logout")
        assert r.status_code == 200
        assert "message" in r.json()

    def test_logout_unauthenticated_still_works(self, client: TestClient):
        """Stateless logout should work without any token."""
        r = client.post(f"{API}/auth/logout")
        assert r.status_code == 200
