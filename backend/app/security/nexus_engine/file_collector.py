"""
ARK Nexus Engine — Shared File Collector

Walks the repository ONCE and pre-loads all file contents into memory.
Each layer receives the pre-loaded file map instead of doing its own os.walk().

Benefits:
  - Eliminates 6x redundant filesystem I/O
  - Uses ThreadPoolExecutor for parallel file reads (I/O-bound)
  - File content is shared across all 6 layers via read-only dict
  - For a 5000-file repo, this takes ~1s instead of 6x ~1s = ~6s
"""
from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.utils.logger import get_logger

log = get_logger(__name__)

SKIP_DIRS = frozenset({
    "node_modules", "__pycache__", ".git", "venv", ".venv",
    "dist", "build", "vendor", ".tox", "coverage", ".next",
    "target", ".terraform", ".serverless", ".mypy_cache",
    ".pytest_cache", ".eggs", "bower_components",
})

# All extensions that ANY layer cares about
CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
    ".go", ".rb", ".cs", ".cpp", ".c", ".h", ".swift", ".kt",
    ".scala", ".rs", ".sh", ".bash", ".ps1",
})

CONFIG_EXTENSIONS = frozenset({
    ".env", ".yml", ".yaml", ".json", ".conf", ".cfg",
    ".ini", ".toml", ".tf", ".hcl",
})

MANIFEST_FILES = frozenset({
    "requirements.txt", "Pipfile", "pyproject.toml",
    "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "go.mod", "Cargo.toml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
})

ALL_EXTENSIONS = CODE_EXTENSIONS | CONFIG_EXTENSIONS


@dataclass(frozen=True)
class FileInfo:
    """Pre-loaded file data shared across all layers."""
    rel_path: str       # Relative to repo root (forward slashes)
    abs_path: str       # Absolute path on disk
    extension: str      # Lowercase extension including dot
    filename: str       # Just the filename
    content: str        # Full file content (UTF-8, errors ignored)
    line_count: int     # Number of lines
    size_bytes: int     # File size


@dataclass
class RepoFileMap:
    """
    Complete pre-loaded file map for a repository.
    Layers can filter by extension or filename without re-reading disk.
    """
    repo_path: str
    files: dict[str, FileInfo] = field(default_factory=dict)  # rel_path → FileInfo
    total_files: int = 0
    total_bytes: int = 0

    def code_files(self) -> dict[str, FileInfo]:
        """Return only code source files."""
        return {k: v for k, v in self.files.items() if v.extension in CODE_EXTENSIONS}

    def config_files(self) -> dict[str, FileInfo]:
        """Return only config/IaC files."""
        return {k: v for k, v in self.files.items() if v.extension in CONFIG_EXTENSIONS}

    def by_extension(self, *exts: str) -> dict[str, FileInfo]:
        """Filter files by one or more extensions."""
        ext_set = set(exts)
        return {k: v for k, v in self.files.items() if v.extension in ext_set}

    def by_filename(self, *names: str) -> dict[str, FileInfo]:
        """Filter files by exact filename."""
        name_set = set(names)
        return {k: v for k, v in self.files.items() if v.filename in name_set}

    def manifests(self) -> dict[str, FileInfo]:
        """Return dependency manifest files."""
        return {k: v for k, v in self.files.items() if v.filename in MANIFEST_FILES}

    def dockerfiles(self) -> dict[str, FileInfo]:
        """Return Dockerfiles and compose files."""
        return {
            k: v for k, v in self.files.items()
            if v.filename.startswith("Dockerfile") or
               v.filename.startswith("docker-compose")
        }


def collect_repo_files(
    repo_path: str,
    max_file_size_bytes: int = 2 * 1024 * 1024,  # 2MB per file max
    max_workers: int = 8,
) -> RepoFileMap:
    """
    Walk the repository once and pre-load all relevant file contents.

    Uses ThreadPoolExecutor for parallel I/O reads.
    Skips binary files, oversized files, and non-relevant extensions.

    Args:
        repo_path: Absolute path to cloned repository.
        max_file_size_bytes: Skip files larger than this (default 2MB).
        max_workers: Thread pool size for parallel reads.

    Returns:
        RepoFileMap with all pre-loaded file data.
    """
    result = RepoFileMap(repo_path=repo_path)
    file_paths: list[tuple[str, str, str, str]] = []  # (abs, rel, ext, filename)

    # Phase 1: Walk filesystem to discover files (fast, no I/O reads)
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            ext = Path(fname).suffix.lower()
            is_manifest = fname in MANIFEST_FILES
            is_dockerfile = fname.startswith("Dockerfile") or fname.startswith("docker-compose")

            if ext not in ALL_EXTENSIONS and not is_manifest and not is_dockerfile:
                continue

            abs_path = os.path.join(root, fname)
            try:
                size = os.path.getsize(abs_path)
                if size > max_file_size_bytes:
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(abs_path, repo_path).replace("\\", "/")
            file_paths.append((abs_path, rel_path, ext, fname))

    # Phase 2: Read file contents in parallel (I/O-bound)
    def _read_file(item: tuple[str, str, str, str]) -> Optional[FileInfo]:
        abs_path, rel_path, ext, fname = item
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            return FileInfo(
                rel_path=rel_path,
                abs_path=abs_path,
                extension=ext,
                filename=fname,
                content=content,
                line_count=content.count("\n") + 1,
                size_bytes=len(content.encode("utf-8", errors="ignore")),
            )
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_read_file, item): item for item in file_paths}
        for future in as_completed(futures):
            fi = future.result()
            if fi:
                result.files[fi.rel_path] = fi
                result.total_bytes += fi.size_bytes

    result.total_files = len(result.files)
    log.info(
        f"[FileCollector] Pre-loaded {result.total_files} files "
        f"({result.total_bytes / 1024:.0f} KB) from {repo_path}"
    )
    return result
