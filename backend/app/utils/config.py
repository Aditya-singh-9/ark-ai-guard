"""
Central configuration management using Pydantic Settings.
All values can be overridden via environment variables or a .env file.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "ARK DevSecOps AI"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"  # development | production | testing
    DEBUG: bool = True

    # ── Security / JWT ───────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Fernet encryption key for storing GitHub access tokens in DB
    # Generate with: from cryptography.fernet import Fernet; Fernet.generate_key()
    ENCRYPTION_KEY: str = ""

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://ark_user:ark_pass@localhost:5432/ark_db"

    # ── GitHub OAuth ─────────────────────────────────────────────────────────
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:8080/auth/callback"
    GITHUB_API_BASE: str = "https://api.github.com"
    GITHUB_TOKEN_URL: str = "https://github.com/login/oauth/access_token"

    # ── AI / Multi-Model ───────────────────────────────────────────────────
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-pro"
    ANTHROPIC_API_KEY: str = ""        # Claude API key (optional, for enhanced AI fusion)
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"

    # ── GitHub Webhooks & Data API ───────────────────────────────────────
    GITHUB_WEBHOOK_SECRET: str = ""    # HMAC-SHA256 secret for webhook verification
    GITHUB_PAT: str = ""               # Personal Access Token for creating Auto-Fix PRs

    # ── Scanning ─────────────────────────────────────────────────────────────
    SCAN_TEMP_DIR: str = "/tmp/ark-scans"
    SCAN_TIMEOUT_SECONDS: int = 300  # 5 minutes max per scan
    MAX_REPO_SIZE_MB: int = 500

    # ── CORS / Frontend ───────────────────────────────────────────────────────
    FRONTEND_URL: str = "http://localhost:8080"
    ALLOWED_ORIGINS: str = (
        "http://localhost:8080,"
        "http://localhost:5173,"
        "http://127.0.0.1:8080"
    )

    @property
    def allowed_origins_list(self) -> list[str]:
        """Parse ALLOWED_ORIGINS from either comma-separated or JSON array string."""
        import json
        val = self.ALLOWED_ORIGINS.strip()
        if val.startswith("["):
            try:
                return json.loads(val)
            except json.JSONDecodeError:
                pass
        return [o.strip() for o in val.split(",") if o.strip()]

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_SCAN_PER_HOUR: int = 10

    # ── Redis (Token Denylist + Future Caching/Queuing) ───────────────────────
    # Set to redis://localhost:6379/0 to enable distributed JWT revocation
    REDIS_URL: str = ""  # Empty = use in-memory denylist (single-process only)


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton — reads .env once and caches."""
    return Settings()


# Module-level singleton for convenience import
settings: Settings = get_settings()
