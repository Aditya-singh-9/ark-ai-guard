"""
CI/CD Pipeline Generator — ARK DevSecOps AI
============================================
Produces a *deeply customised* GitHub Actions YAML tailored to the actual
detected tech stack (language + frameworks + Docker + package manager).

Generation strategy:
1. Ask Gemini for a bespoke pipeline (includes all context).
2. Fallback: build the YAML procedurally from stack-aware building blocks
   so the result is ALWAYS specific to the repo — never a generic template.
"""
from __future__ import annotations

import re
import textwrap
from typing import Any

from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Gemini bootstrap
# ---------------------------------------------------------------------------
try:
    import google.generativeai as genai
    _model = genai.GenerativeModel(settings.GEMINI_MODEL)
    GEMINI_AVAILABLE = bool(settings.GEMINI_API_KEY)
except Exception:
    _model = None
    GEMINI_AVAILABLE = False

# ---------------------------------------------------------------------------
# Rich Gemini prompt — passes ALL relevant context
# ---------------------------------------------------------------------------
_CICD_PROMPT = """\
You are a senior DevSecOps engineer at a top-tier security firm.
Generate a production-ready GitHub Actions CI/CD pipeline for the repository
described below. The pipeline MUST be tailored to the exact tech stack — do
NOT produce a generic template.

=== REPOSITORY CONTEXT ===
Repository : {repo_name}
Language   : {language}
Frameworks : {frameworks}
Has Docker : {has_docker}
Manifests  : {manifests}
Package Mgr: {package_manager}
Lang Version: {lang_version}
Test Runner: {test_runner}
Lint Tool  : {lint_tool}
Build Tool : {build_tool}

=== MANDATORY SECURITY STEPS (ALL must be present) ===
1. Semgrep SAST (semgrep/semgrep-action@v1, config: auto, auditOn: push)
2. TruffleHog secret scan (trufflesecurity/trufflehog@main)
3. Language-appropriate dependency audit:
   - Python  → pip-audit --vulnerability-service osv
   - Node.js → npm audit --audit-level=high  (or pnpm/yarn equivalent)
   - Java    → OWASP Dependency-Check action
   - Go      → govulncheck ./...
   - Rust    → cargo audit
   - Ruby    → bundler-audit
4. Trivy filesystem scan (if Docker present: also image scan after build)
5. Pipeline FAILS on CRITICAL severity findings

=== PIPELINE STAGES (in order) ===
1. security-scan   — SAST, secrets, dependency audit
2. build-and-test  — install, {build_tool} build, {test_runner} tests, coverage
3. docker-build    — only if has_docker=true → build & push to GHCR
4. deploy          — runs on main branch only, environment: production

=== FRAMEWORK-SPECIFIC REQUIREMENTS ===
{framework_hints}

=== OUTPUT RULES ===
- Return RAW YAML only. No markdown fences, no explanations.
- The pipeline name must start with: "ARK Secure CI/CD —"
- All secrets must use ${{{{ secrets.SECRET_NAME }}}} notation.
- Use pinned action versions (v4 for checkout, v5 for setup-python etc.).
"""

# ---------------------------------------------------------------------------
# Stack fingerprinting helpers
# ---------------------------------------------------------------------------

def _detect_package_manager(language: str, frameworks: list[str], manifests: list[str]) -> str:
    if language == "python":
        if "Pipfile" in manifests:
            return "pipenv"
        if "pyproject.toml" in manifests:
            return "poetry"
        return "pip"
    if language == "javascript":
        if "pnpm-lock.yaml" in manifests or "pnpm-workspace.yaml" in manifests:
            return "pnpm"
        if "yarn.lock" in manifests:
            return "yarn"
        return "npm"
    if language == "java":
        if "build.gradle" in manifests or "build.gradle.kts" in manifests:
            return "gradle"
        return "maven"
    if language == "rust":
        return "cargo"
    if language == "go":
        return "go"
    if language == "ruby":
        return "bundler"
    return "unknown"


def _detect_test_runner(language: str, frameworks: list[str]) -> str:
    if language == "python":
        return "pytest"
    if language == "javascript":
        if "Vitest" in frameworks or "Vite" in frameworks:
            return "vitest"
        if "Jest" in frameworks or "React" in frameworks or "Next.js" in frameworks:
            return "jest"
        return "jest"
    if language == "java":
        return "JUnit (via maven/gradle)"
    if language == "go":
        return "go test"
    if language == "rust":
        return "cargo test"
    if language == "ruby":
        return "rspec"
    return "language default"


def _detect_lint_tool(language: str, frameworks: list[str]) -> str:
    if language == "python":
        return "ruff"
    if language == "javascript":
        if "Next.js" in frameworks:
            return "next lint"
        return "eslint"
    if language == "java":
        return "checkstyle (via maven/gradle)"
    if language == "go":
        return "golangci-lint"
    if language == "rust":
        return "clippy"
    if language == "ruby":
        return "rubocop"
    return "none"


def _detect_build_tool(language: str, frameworks: list[str], pkg_mgr: str) -> str:
    if language == "python":
        return pkg_mgr
    if language == "javascript":
        if "Next.js" in frameworks:
            return "next build"
        if "Vite" in frameworks:
            return "vite build"
        return "npm run build"
    if language == "java":
        return "gradle" if pkg_mgr == "gradle" else "maven"
    if language == "go":
        return "go build"
    if language == "rust":
        return "cargo build --release"
    if language == "ruby":
        return "bundler"
    return "make"


def _detect_lang_version(language: str) -> str:
    defaults = {
        "python": "3.12",
        "javascript": "20",
        "java": "21",
        "go": "1.22",
        "rust": "stable",
        "ruby": "3.3",
    }
    return defaults.get(language, "latest")


def _build_framework_hints(language: str, frameworks: list[str], has_docker: bool) -> str:
    hints: list[str] = []

    # Python
    if "FastAPI" in frameworks:
        hints.append("- FastAPI: run uvicorn in test mode; check for async route coverage.")
    if "Django" in frameworks:
        hints.append("- Django: run 'python manage.py test'; include collectstatic step.")
    if "Flask" in frameworks:
        hints.append("- Flask: run 'flask test' or pytest with FLASK_ENV=testing.")

    # JavaScript
    if "Next.js" in frameworks:
        hints.append("- Next.js: 'next build' must succeed; run 'next lint' before build.")
    if "React" in frameworks and "Next.js" not in frameworks:
        hints.append("- React (CRA/Vite): 'CI=true npm test -- --coverage'; 'npm run build'.")
    if "Vue" in frameworks:
        hints.append("- Vue: 'npm run build'; 'vue-cli-service test:unit' or vitest.")
    if "Express" in frameworks:
        hints.append("- Express.js: run unit + integration tests; check PORT binding.")

    # Java
    if "Spring Boot" in frameworks:
        hints.append("- Spring Boot: 'mvn -B verify' or './gradlew build'; check actuator health.")

    # Docker
    if has_docker:
        hints.append(
            "- Docker: Build image, tag as ghcr.io/${{ github.repository }}:${{ github.sha }}, "
            "push to GHCR. Trivy must also scan the built image."
        )

    if not hints:
        hints.append("- No additional framework-specific hints; follow language best practices.")

    return "\n".join(hints)


# ---------------------------------------------------------------------------
# Procedural YAML builder — guaranteed customised fallback
# ---------------------------------------------------------------------------

def _install_step(language: str, pkg_mgr: str, has_docker: bool) -> str:
    if language == "python":
        if pkg_mgr == "poetry":
            return textwrap.dedent("""\
      - name: Install Poetry
        run: pip install poetry
      - name: Install dependencies
        run: poetry install --no-interaction --no-root""")
        if pkg_mgr == "pipenv":
            return textwrap.dedent("""\
      - name: Install Pipenv
        run: pip install pipenv
      - name: Install dependencies
        run: pipenv install --dev --system""")
        # pip / default
        return textwrap.dedent("""\
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt""")

    if language == "javascript":
        if pkg_mgr == "pnpm":
            return textwrap.dedent("""\
      - name: Setup pnpm
        uses: pnpm/action-setup@v3
        with:
          version: 9
      - name: Install dependencies
        run: pnpm install --frozen-lockfile""")
        if pkg_mgr == "yarn":
            return textwrap.dedent("""\
      - name: Install dependencies
        run: yarn install --frozen-lockfile""")
        return textwrap.dedent("""\
      - name: Install dependencies
        run: npm ci""")

    if language == "java":
        if pkg_mgr == "gradle":
            return textwrap.dedent("""\
      - name: Grant execute permission for gradlew
        run: chmod +x gradlew
      - name: Build with Gradle
        run: ./gradlew build""")
        return textwrap.dedent("""\
      - name: Build with Maven
        run: mvn -B verify --file pom.xml""")

    if language == "go":
        return textwrap.dedent("""\
      - name: Download Go modules
        run: go mod download""")

    if language == "rust":
        return textwrap.dedent("""\
      - name: Cache Cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      - name: Build
        run: cargo build --release""")

    if language == "ruby":
        return textwrap.dedent("""\
      - name: Install gems
        run: bundle install --jobs 4 --retry 3""")

    return "      - name: Install dependencies\n        run: echo 'No standard install step detected'"


def _dep_audit_step(language: str, pkg_mgr: str) -> str:
    if language == "python":
        base = "      - name: Dependency Audit\n        run: "
        if pkg_mgr == "poetry":
            return base + "pip install pip-audit && poetry export -f requirements.txt --output /tmp/req.txt && pip-audit -r /tmp/req.txt"
        return base + "pip install pip-audit && pip-audit --vulnerability-service osv"

    if language == "javascript":
        if pkg_mgr == "pnpm":
            return "      - name: Dependency Audit\n        run: pnpm audit --audit-level=high"
        if pkg_mgr == "yarn":
            return "      - name: Dependency Audit\n        run: yarn audit --level high"
        return "      - name: Dependency Audit\n        run: npm audit --audit-level=high"

    if language == "java":
        return textwrap.dedent("""\
      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: ${{ github.repository }}
          path: .
          format: HTML
          failBuildOnCVSS: 7""")

    if language == "go":
        return textwrap.dedent("""\
      - name: Go Vulnerability Check
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...""")

    if language == "rust":
        return textwrap.dedent("""\
      - name: Cargo Audit
        run: |
          cargo install cargo-audit
          cargo audit""")

    if language == "ruby":
        return textwrap.dedent("""\
      - name: Bundler Audit
        run: |
          gem install bundler-audit
          bundle-audit check --update""")

    return "      - name: Dependency Audit\n        run: echo 'No audit tool configured'"


def _lint_step(language: str, pkg_mgr: str, frameworks: list[str]) -> str:
    if language == "python":
        return textwrap.dedent("""\
      - name: Lint (Ruff)
        run: |
          pip install ruff
          ruff check .
      - name: Type Check (mypy)
        run: |
          pip install mypy
          mypy . --ignore-missing-imports || true""")

    if language == "javascript":
        if "Next.js" in frameworks:
            return "      - name: Lint\n        run: npx next lint"
        return "      - name: Lint\n        run: npm run lint --if-present"

    if language == "go":
        return textwrap.dedent("""\
      - name: Lint (golangci-lint)
        uses: golangci/golangci-lint-action@v4
        with:
          version: latest""")

    if language == "rust":
        return textwrap.dedent("""\
      - name: Clippy Check
        run: cargo clippy -- -D warnings""")

    if language == "ruby":
        return textwrap.dedent("""\
      - name: RuboCop Lint
        run: bundle exec rubocop --parallel""")

    return ""


def _test_step(language: str, pkg_mgr: str, frameworks: list[str]) -> str:
    if language == "python":
        runner = "poetry run pytest" if pkg_mgr == "poetry" else "pytest"
        return textwrap.dedent(f"""\
      - name: Run Tests
        run: |
          pip install pytest pytest-cov
          {runner} --cov=. --cov-report=xml
      - name: Upload Coverage
        uses: codecov/codecov-action@v4
        with:
          files: coverage.xml""")

    if language == "javascript":
        if pkg_mgr == "pnpm":
            cmd = "pnpm test --coverage"
        elif pkg_mgr == "yarn":
            cmd = "yarn test --coverage --watchAll=false"
        elif "Vitest" in frameworks or "Vite" in frameworks:
            cmd = "npm run test -- --coverage"
        else:
            cmd = "npm test -- --coverage --watchAll=false"
        return f"      - name: Run Tests\n        run: |\n          CI=true {cmd}"

    if language == "java":
        if pkg_mgr == "gradle":
            return "      - name: Run Tests\n        run: ./gradlew test"
        return "      - name: Run Tests\n        run: mvn -B test"

    if language == "go":
        return textwrap.dedent("""\
      - name: Run Tests
        run: go test -race -coverprofile=coverage.out ./...
      - name: Generate Coverage Report
        run: go tool cover -html=coverage.out -o coverage.html""")

    if language == "rust":
        return "      - name: Run Tests\n        run: cargo test --all-features"

    if language == "ruby":
        return "      - name: Run Tests\n        run: bundle exec rspec --format progress"

    return "      - name: Run Tests\n        run: echo 'No test command configured'"


def _setup_step(language: str, lang_version: str, pkg_mgr: str) -> str:
    if language == "python":
        cache = "pip" if pkg_mgr in ("pip", "pipenv") else "pip"
        return textwrap.dedent(f"""\
      - name: Set up Python {lang_version}
        uses: actions/setup-python@v5
        with:
          python-version: '{lang_version}'
          cache: '{cache}'""")

    if language == "javascript":
        cache = pkg_mgr if pkg_mgr in ("npm", "yarn") else "npm"
        return textwrap.dedent(f"""\
      - name: Setup Node.js {lang_version}
        uses: actions/setup-node@v4
        with:
          node-version: '{lang_version}'
          cache: '{cache}'""")

    if language == "java":
        cache = "gradle" if pkg_mgr == "gradle" else "maven"
        return textwrap.dedent(f"""\
      - name: Set up JDK {lang_version}
        uses: actions/setup-java@v4
        with:
          java-version: '{lang_version}'
          distribution: temurin
          cache: {cache}""")

    if language == "go":
        return textwrap.dedent(f"""\
      - name: Set up Go {lang_version}
        uses: actions/setup-go@v5
        with:
          go-version: '{lang_version}'
          cache: true""")

    if language == "rust":
        return textwrap.dedent(f"""\
      - name: Set up Rust (stable)
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy""")

    if language == "ruby":
        return textwrap.dedent(f"""\
      - name: Set up Ruby {lang_version}
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: '{lang_version}'
          bundler-cache: true""")

    return ""


def _build_step(language: str, frameworks: list[str], pkg_mgr: str) -> str:
    if language == "python":
        return ""   # build happens as part of test for Python
    if language == "javascript":
        if "Next.js" in frameworks:
            return "      - name: Build (Next.js)\n        run: npx next build"
        cmd = f"{'p' if pkg_mgr == 'pnpm' else 'yarn ' if pkg_mgr == 'yarn' else 'npm '}{'run ' if pkg_mgr in ('npm', 'pnpm') else ''}build"
        return f"      - name: Build\n        run: {cmd}"
    if language == "go":
        return "      - name: Build binary\n        run: go build -v ./..."
    if language == "rust":
        return "      - name: Build release binary\n        run: cargo build --release"
    return ""


def _docker_job(repo_name: str) -> str:
    return textwrap.dedent(f"""\
  docker-build:
    name: 🐳 Docker Build & Push
    needs: build-and-test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}

      - name: Extract Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{{{ github.repository }}}}
          tags: |
            type=sha,prefix=,suffix=,format=short
            type=ref,event=branch
            type=semver,pattern={{{{version}}}}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: ${{{{ github.event_name != 'pull_request' }}}}
          tags: ${{{{ steps.meta.outputs.tags }}}}
          labels: ${{{{ steps.meta.outputs.labels }}}}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Trivy Image Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/${{{{ github.repository }}}}:${{{{ github.sha }}}}
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
""")


def _deploy_job(language: str, frameworks: list[str], depends_on: str) -> str:
    # Add framework-specific deploy hints as comments
    hints: list[str] = []
    if "FastAPI" in frameworks or "Flask" in frameworks:
        hints.append("# Example: fly deploy --remote-only")
        hints.append("# For Railway: railway up")
    if "Django" in frameworks:
        hints.append("# python manage.py migrate")
        hints.append("# Example: fly deploy --remote-only")
    if "Next.js" in frameworks:
        hints.append("# Example: npx vercel --prod --token ${{ secrets.VERCEL_TOKEN }}")
    if "Spring Boot" in frameworks:
        hints.append("# Example: java -jar target/*.jar")

    hint_block = "\n          ".join(hints) if hints else "# Add your deployment commands here"

    return textwrap.dedent(f"""\
  deploy:
    name: 🚀 Deploy to Production
    needs: {depends_on}
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Deploy
        run: |
          {hint_block}
        env:
          DEPLOY_KEY: ${{{{ secrets.DEPLOY_KEY }}}}
""")


def _build_procedural_yaml(
    repo_name: str,
    language: str,
    frameworks: list[str],
    has_docker: bool,
    manifests: list[str],
) -> str:
    """
    Build a fully customised GitHub Actions YAML from detected stack metadata.
    This is the fallback when Gemini is unavailable — but it's still specific.
    """
    pkg_mgr = _detect_package_manager(language, frameworks, manifests)
    lang_version = _detect_lang_version(language)
    upper_lang = language.title() if language else "App"

    fw_label = f" / {', '.join(frameworks)}" if frameworks else ""
    name_line = f"name: ARK Secure CI/CD — {repo_name} ({upper_lang}{fw_label})"

    setup = _setup_step(language, lang_version, pkg_mgr)
    install = _install_step(language, pkg_mgr, has_docker)
    dep_audit = _dep_audit_step(language, pkg_mgr)
    lint = _lint_step(language, pkg_mgr, frameworks)
    test = _test_step(language, pkg_mgr, frameworks)
    build = _build_step(language, frameworks, pkg_mgr)

    # Compose security-scan job
    sec_steps = textwrap.dedent("""\
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: auto
          auditOn: push
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified

      - name: Trivy Filesystem Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: CRITICAL,HIGH
          exit-code: '1'""")

    # Build-and-test job
    build_test_steps_parts = [
        "      - uses: actions/checkout@v4",
        setup,
        install,
        dep_audit,
        lint,
        build,
        test,
    ]
    build_test_steps = "\n\n".join(p for p in build_test_steps_parts if p.strip())

    depends_on = "build-and-test"

    lines = [
        name_line,
        f"# Generated by ARK DevSecOps AI — {upper_lang}{fw_label} pipeline",
        f"# Repo: {repo_name}  |  Package manager: {pkg_mgr}",
        "",
        "on:",
        "  push:",
        "    branches: [main, develop]",
        "  pull_request:",
        "    branches: [main]",
        "",
        "concurrency:",
        "  group: ${{ github.workflow }}-${{ github.ref }}",
        "  cancel-in-progress: true",
        "",
        "jobs:",
        "  security-scan:",
        "    name: 🔒 Security Scan",
        "    runs-on: ubuntu-latest",
        "    steps:",
        textwrap.indent(sec_steps, "      "),
        "",
        "  build-and-test:",
        f"    name: 🔨 Build & Test ({upper_lang}{fw_label})",
        "    needs: security-scan",
        "    runs-on: ubuntu-latest",
        "    steps:",
        build_test_steps,
    ]

    if has_docker:
        lines += ["", _docker_job(repo_name)]
        depends_on = "docker-build"

    lines += ["", _deploy_job(language, frameworks, depends_on)]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def generate_cicd_pipeline(
    repo_name: str,
    structure: dict[str, Any],
) -> str:
    """
    Generate a GitHub Actions CI/CD YAML pipeline customised for this repo.

    Tries Gemini first (rich contextual prompt) then falls back to the
    procedural stack-aware builder — never produces a generic template.

    Args:
        repo_name: Full repository name (owner/repo).
        structure:  Output of RepoClonerService.analyse_structure() or an
                    equivalent dict with keys: language, frameworks,
                    has_docker, package_manifests.

    Returns:
        YAML string ready to commit to .github/workflows/ark-pipeline.yml
    """
    language  = structure.get("language", "python") or "python"
    frameworks = structure.get("frameworks", []) or []
    has_docker = structure.get("has_docker", False)
    manifests  = structure.get("package_manifests", []) or []

    # Derived context
    pkg_mgr    = _detect_package_manager(language, frameworks, manifests)
    lang_version = _detect_lang_version(language)
    test_runner  = _detect_test_runner(language, frameworks)
    lint_tool    = _detect_lint_tool(language, frameworks)
    build_tool   = _detect_build_tool(language, frameworks, pkg_mgr)
    fw_hints     = _build_framework_hints(language, frameworks, has_docker)

    # ── Gemini path ──────────────────────────────────────────────────────────
    if GEMINI_AVAILABLE and _model:
        framework_info = f" using {', '.join(frameworks)}" if frameworks else ""
        prompt = _CICD_PROMPT.format(
            repo_name=repo_name,
            language=language,
            frameworks=", ".join(frameworks) or "none",
            has_docker=has_docker,
            manifests=", ".join(manifests) or "none",
            package_manager=pkg_mgr,
            lang_version=lang_version,
            test_runner=test_runner,
            lint_tool=lint_tool,
            build_tool=build_tool,
            framework_hints=fw_hints,
        )
        log.info("Generating customised CI/CD pipeline via Gemini…")
        try:
            response = _model.generate_content(prompt)
            raw = response.text.strip()
            # Strip markdown fences if present
            raw = re.sub(r"^```(?:yaml|yml)?\s*", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
            raw = raw.strip()
            if raw.startswith("name:") or "jobs:" in raw:
                log.info("Gemini returned a valid customised CI/CD YAML")
                return raw
            log.warning("Gemini response did not look like valid YAML — using procedural builder")
        except Exception as exc:
            log.error(f"Gemini CI/CD generation error: {exc}")

    # ── Procedural builder fallback ──────────────────────────────────────────
    log.info(
        f"Building procedural CI/CD pipeline: lang={language}, "
        f"frameworks={frameworks}, pkg_mgr={pkg_mgr}, has_docker={has_docker}"
    )
    return _build_procedural_yaml(repo_name, language, frameworks, has_docker, manifests)
