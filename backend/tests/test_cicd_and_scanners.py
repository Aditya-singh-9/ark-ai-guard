"""
Tests for CI/CD generator template fallback logic and scanner output parsing.
"""
import pytest


class TestCICDGeneratorTemplates:
    """Test template selection and YAML validity."""

    @pytest.mark.asyncio
    async def test_python_template_returned(self):
        from app.services.cicd_generator import generate_cicd_pipeline

        structure = {
            "language": "python",
            "frameworks": ["FastAPI"],
            "has_docker": False,
            "package_manifests": ["requirements.txt"],
        }
        yaml = await generate_cicd_pipeline("myorg/myrepo", structure)
        assert "name:" in yaml
        assert "jobs:" in yaml
        assert "security-scan" in yaml or "security" in yaml.lower()

    @pytest.mark.asyncio
    async def test_javascript_template_returned(self):
        from app.services.cicd_generator import generate_cicd_pipeline

        structure = {
            "language": "javascript",
            "frameworks": ["React"],
            "has_docker": False,
            "package_manifests": ["package.json"],
        }
        yaml = await generate_cicd_pipeline("myorg/frontend", structure)
        assert "Node" in yaml or "node" in yaml.lower()

    @pytest.mark.asyncio
    async def test_unknown_language_returns_python_default(self):
        from app.services.cicd_generator import generate_cicd_pipeline

        structure = {
            "language": "cobol",
            "frameworks": [],
            "has_docker": False,
            "package_manifests": [],
        }
        yaml = await generate_cicd_pipeline("myorg/legacy", structure)
        assert "name:" in yaml
        assert len(yaml) > 100  # Should be a real pipeline


class TestSemgrepParser:
    """Test semgrep_runner severity mapping."""

    def test_severity_mapping_error_to_critical(self):
        from app.security.semgrep_runner import _map_severity
        assert _map_severity("ERROR") == "critical"

    def test_severity_mapping_warning_to_high(self):
        from app.security.semgrep_runner import _map_severity
        assert _map_severity("WARNING") == "high"

    def test_severity_mapping_info_to_medium(self):
        from app.security.semgrep_runner import _map_severity
        assert _map_severity("INFO") == "medium"

    def test_severity_mapping_unknown_to_medium(self):
        from app.security.semgrep_runner import _map_severity
        assert _map_severity("UNKNOWN") == "medium"

    def test_case_insensitive(self):
        from app.security.semgrep_runner import _map_severity
        assert _map_severity("error") == "critical"
        assert _map_severity("Warning") == "high"


class TestBanditParser:
    """Test bandit_runner severity mapping and Python detection."""

    def test_high_maps_correctly(self):
        from app.security.bandit_runner import _map_severity
        assert _map_severity("HIGH") == "high"

    def test_medium_maps_correctly(self):
        from app.security.bandit_runner import _map_severity
        assert _map_severity("MEDIUM") == "medium"

    def test_low_maps_correctly(self):
        from app.security.bandit_runner import _map_severity
        assert _map_severity("LOW") == "low"

    def test_empty_maps_to_low(self):
        from app.security.bandit_runner import _map_severity
        assert _map_severity("") == "low"

    def test_no_python_files_detected(self, tmp_path):
        from app.security.bandit_runner import _has_python_files
        # Empty directory
        assert _has_python_files(str(tmp_path)) is False

    def test_python_files_detected(self, tmp_path):
        from app.security.bandit_runner import _has_python_files
        (tmp_path / "main.py").write_text("print('hello')")
        assert _has_python_files(str(tmp_path)) is True
