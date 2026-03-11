"""
Repository cloning and structure analysis service.
Clones repos to a temp dir, detects language/frameworks, and summarises structure.
"""
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

# File patterns for tech stack detection
TECH_INDICATORS: dict[str, dict] = {
    "python": {
        "files": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
        "extensions": [".py"],
    },
    "javascript": {
        "files": ["package.json"],
        "extensions": [".js", ".jsx", ".ts", ".tsx"],
    },
    "java": {
        "files": ["pom.xml", "build.gradle"],
        "extensions": [".java"],
    },
    "go": {
        "files": ["go.mod"],
        "extensions": [".go"],
    },
    "rust": {
        "files": ["Cargo.toml"],
        "extensions": [".rs"],
    },
    "ruby": {
        "files": ["Gemfile"],
        "extensions": [".rb"],
    },
}

FRAMEWORK_INDICATORS: dict[str, list[str]] = {
    "FastAPI": ["fastapi"],
    "Django": ["django"],
    "Flask": ["flask"],
    "React": ["react", "\"react\""],
    "Vue": ["vue"],
    "Next.js": ["next"],
    "Spring Boot": ["spring-boot"],
    "Express": ["express"],
}

PACKAGE_MANIFESTS = [
    "requirements.txt",
    "package.json",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Cargo.toml",
    "go.mod",
    "Pipfile",
    "pyproject.toml",
]


class RepoClonerService:
    """Handles cloning and static analysis of GitHub repositories."""

    def __init__(self) -> None:
        os.makedirs(settings.SCAN_TEMP_DIR, exist_ok=True)

    def get_clone_path(self, scan_id: int) -> str:
        return os.path.join(settings.SCAN_TEMP_DIR, f"scan-{scan_id}")

    def clone_repository(self, clone_url: str, scan_id: int, access_token: str | None = None) -> str:
        """
        Clone repository to a local temp directory.

        Injects access_token into the clone URL for private repos.
        Returns the local path to the cloned repo.
        Raises RuntimeError on failure.
        """
        dest_path = self.get_clone_path(scan_id)

        if os.path.exists(dest_path):
            log.info(f"Removing existing clone at {dest_path}")
            shutil.rmtree(dest_path, ignore_errors=True)

        # Build authenticated clone URL for private repos
        auth_url = clone_url
        if access_token and "github.com" in clone_url:
            auth_url = clone_url.replace(
                "https://",
                f"https://x-access-token:{access_token}@",
            )

        log.info(f"Cloning repository to {dest_path}")
        cmd = [
            "git",
            "clone",
            "--depth", "1",       # Shallow clone — only latest commit
            "--single-branch",
            "--no-tags",
            auth_url,
            dest_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out after 120 seconds")
        except Exception as exc:
            raise RuntimeError(f"Git clone failed: {exc}") from exc

        if result.returncode != 0:
            stderr = result.stderr.replace(access_token or "", "***") if access_token else result.stderr
            raise RuntimeError(f"Git clone error: {stderr[:500]}")

        log.info(f"Repository cloned successfully: {dest_path}")
        return dest_path

    def analyse_structure(self, repo_path: str) -> dict[str, Any]:
        """
        Walk the repository and extract structural metadata.

        Returns a dict with:
        - language: primary language
        - frameworks: detected frameworks
        - file_count: total source files
        - directory_tree: top-level structure (truncated)
        - package_manifests: found manifest files
        - has_docker: bool
        - has_cicd: bool
        - total_size_kb: estimated size
        """
        if not os.path.isdir(repo_path):
            return {}

        file_count = 0
        extension_counts: dict[str, int] = {}
        found_files: set[str] = set()
        top_level: list[str] = []
        total_size = 0

        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "vendor", "dist", "build", ".next", "target",
        }

        for root, dirs, files in os.walk(repo_path):
            # Skip non-source dirs
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            rel_root = os.path.relpath(root, repo_path)
            if rel_root == ".":
                top_level = sorted(dirs[:30] + files[:30])

            for fname in files:
                fpath = os.path.join(root, fname)
                file_count += 1
                try:
                    total_size += os.path.getsize(fpath)
                except OSError:
                    pass

                ext = Path(fname).suffix.lower()
                if ext:
                    extension_counts[ext] = extension_counts.get(ext, 0) + 1

                # Track manifest files
                if fname in PACKAGE_MANIFESTS:
                    found_files.add(fname)

        # Determine primary language
        language = _detect_language(extension_counts, found_files)

        # Detect frameworks by scanning manifest content
        frameworks = _detect_frameworks(repo_path, found_files)

        has_docker = any(
            f in found_files or os.path.exists(os.path.join(repo_path, f))
            for f in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
        )
        has_cicd = os.path.isdir(os.path.join(repo_path, ".github", "workflows"))

        return {
            "language": language,
            "frameworks": frameworks,
            "file_count": file_count,
            "directory_tree": top_level[:50],
            "package_manifests": sorted(found_files),
            "has_docker": has_docker,
            "has_cicd": has_cicd,
            "total_size_kb": round(total_size / 1024, 1),
            "extension_counts": dict(
                sorted(extension_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }

    def cleanup(self, scan_id: int) -> None:
        """Remove the cloned repository from disk."""
        clone_path = self.get_clone_path(scan_id)
        if os.path.exists(clone_path):
            shutil.rmtree(clone_path, ignore_errors=True)
            log.info(f"Cleaned up clone at {clone_path}")


def _detect_language(
    extension_counts: dict[str, int], found_files: set[str]
) -> str:
    """Pick the primary language based on extension frequency and manifest files."""
    for lang, info in TECH_INDICATORS.items():
        for mf in info["files"]:
            if mf in found_files:
                return lang

    if not extension_counts:
        return "unknown"

    # Fallback: most common extension
    top_ext = max(extension_counts, key=extension_counts.get)  # type: ignore
    for lang, info in TECH_INDICATORS.items():
        if top_ext in info["extensions"]:
            return lang
    return "unknown"


def _detect_frameworks(repo_path: str, found_files: set[str]) -> list[str]:
    """Detect frameworks by scanning known manifest files for keyword matches."""
    frameworks: list[str] = []
    manifest_contents = ""

    for mf in found_files:
        fpath = os.path.join(repo_path, mf)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                manifest_contents += f.read(4096).lower()
        except Exception:
            continue

    for fw, keywords in FRAMEWORK_INDICATORS.items():
        if any(kw.lower() in manifest_contents for kw in keywords):
            frameworks.append(fw)

    return frameworks


# Module-level singleton
repo_cloner = RepoClonerService()
