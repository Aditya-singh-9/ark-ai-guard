"""
DevScops Guard — FastAPI Application Entry Point

Registers all routers, configures middleware, and handles application lifecycle.
"""
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.api.limiter import limiter

from app.api import auth, repository, scan, reports, webhooks
from app.database.db import init_db, check_db_connection
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger("ark.main")


# ── Rate Limiter ──────────────────────────────────────────────────────────────

# Removed local limiter instantiation


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown logic."""
    log.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.APP_ENV})")

    # Startup security checks
    if "CHANGE_ME" in settings.SECRET_KEY and settings.APP_ENV != "development":
        log.error("FATAL: SECRET_KEY is insecure default value! Set a real key via .env")
    if not settings.ENCRYPTION_KEY:
        log.warning("SECURITY WARNING: ENCRYPTION_KEY is not set — GitHub tokens stored in plaintext!")
    if not settings.GITHUB_WEBHOOK_SECRET:
        log.warning("SECURITY WARNING: GITHUB_WEBHOOK_SECRET is not set — webhook verification disabled!")

    # Initialise database tables + Auto-patch schemas
    try:
        init_db()
    except Exception as exc:
        log.error(f"Database initialisation or migration failed: {exc}")
        # Don't crash immediately — DB might not be ready yet in Docker Compose
        log.warning("Continuing startup without DB — some endpoints will fail")

    log.info("Application startup complete ✓")
    yield
    log.info("Application shutdown complete")


# ── Application Factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Production-ready DevSecOps AI backend. "
            "Scans GitHub repositories for vulnerabilities, "
            "analyses dependencies, and generates secure CI/CD pipelines."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── State ─────────────────────────────────────────────────────────────────
    app.state.limiter = limiter

    # ── Exception Handlers ────────────────────────────────────────────────────
    from slowapi import _rate_limit_exceeded_handler
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        log.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal server error occurred.",
                "path": str(request.url),
            },
        )

    # ── Middleware ────────────────────────────────────────────────────────────

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list + [settings.FRONTEND_URL],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Request timing + Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        # Performance
        response.headers["X-Process-Time-MS"] = str(elapsed_ms)
        response.headers["X-ARK-Version"] = settings.APP_VERSION
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response

    # ── Routers ───────────────────────────────────────────────────────────────
    PREFIX = "/api/v1"

    app.include_router(auth.router, prefix=PREFIX)
    app.include_router(repository.router, prefix=PREFIX)
    app.include_router(scan.router, prefix=PREFIX)
    app.include_router(reports.router, prefix=PREFIX)
    app.include_router(webhooks.router, prefix=PREFIX)

    # ── Health & Info Endpoints ───────────────────────────────────────────────

    @app.get("/health", tags=["System"], summary="Health Check")
    async def health_check() -> dict:
        """Returns service health status and DB connectivity."""
        db_ok = check_db_connection()
        return {
            "status": "healthy" if db_ok else "degraded",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "database": "connected" if db_ok else "disconnected",
        }

    @app.get("/", tags=["System"], summary="API Root")
    async def root() -> dict:
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "engine": "DevScops Nexus Engine + Mythos AI",
            "models": ["Mythos (offline)", "Gemini (online)"],
            "layers": 7,
            "features": [
                "7-Layer Deep Security Scanning",
                "Multi-Model AI Fusion",
                "OWASP/CWE/MITRE ATT&CK Mapping",
                "Compliance Frameworks (SOC2, PCI, HIPAA, ISO 27001)",
                "AI Auto-Fix Generation",
                "Policy-as-Code Security Gates",
                "GitHub Webhook Auto-Scan",
                "PR Security Comment Bot",
                "STRIDE Threat Modeling",
                "Attack Chain Detection",
            ],
            "docs": "/docs",
            "health": "/health",
        }

    return app


app = create_app()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.APP_ENV == "development",
        log_level="debug" if settings.DEBUG else "info",
    )
