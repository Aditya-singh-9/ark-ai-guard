"""
Tests for GitHub URL validation, config, and model enums.
"""
import pytest


class TestGitHubURLValidation:
    """Test github_service.validate_github_url with various formats."""

    def test_https_url(self):
        from app.services.github_service import validate_github_url
        result = validate_github_url("https://github.com/octocat/Hello-World")
        assert result == ("octocat", "Hello-World")

    def test_https_url_with_git_suffix(self):
        from app.services.github_service import validate_github_url
        result = validate_github_url("https://github.com/octocat/Hello-World.git")
        assert result == ("octocat", "Hello-World")

    def test_https_url_trailing_slash(self):
        from app.services.github_service import validate_github_url
        result = validate_github_url("https://github.com/octocat/Hello-World/")
        assert result == ("octocat", "Hello-World")

    def test_ssh_url(self):
        from app.services.github_service import validate_github_url
        result = validate_github_url("git@github.com:octocat/Hello-World.git")
        assert result == ("octocat", "Hello-World")

    def test_invalid_url_returns_none(self):
        from app.services.github_service import validate_github_url
        assert validate_github_url("https://gitlab.com/owner/repo") is None
        assert validate_github_url("not-a-url") is None
        assert validate_github_url("") is None

    def test_org_repo(self):
        from app.services.github_service import validate_github_url
        result = validate_github_url("https://github.com/myorg/my-service")
        assert result == ("myorg", "my-service")


class TestConfig:
    """Test configuration defaults."""

    def test_config_loads(self):
        from app.utils.config import settings
        assert settings.APP_NAME == "ARK DevSecOps AI"
        assert settings.ALGORITHM == "HS256"
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0

    def test_allowed_origins_has_frontend(self):
        from app.utils.config import settings
        assert any("localhost" in o for o in settings.ALLOWED_ORIGINS)


class TestVulnerabilityModel:
    """Test Vulnerability model enums and to_dict."""

    def test_severity_enum_values(self):
        from app.models.vulnerability import Severity
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_scanner_enum_values(self):
        from app.models.vulnerability import ScannerType
        assert ScannerType.SEMGREP.value == "semgrep"
        assert ScannerType.BANDIT.value == "bandit"
        assert ScannerType.TRIVY.value == "trivy"
