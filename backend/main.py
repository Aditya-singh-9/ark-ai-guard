"""
ARK DevSecOps AI — FastAPI Application Entry Point

Registers all routers, configures middleware, and handles application lifecycle.
"""
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api import auth, repository, scan, reports
from app.database.db import init_db, check_db_connection
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger("ark.main")


# ── Rate Limiter ──────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown logic."""
    log.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.APP_ENV})")

    # Initialise database tables
    try:
        init_db()
    except Exception as exc:
        log.error(f"Database initialisation failed: {exc}")
        # Don't crash — DB might not be ready yet in Docker Compose
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
        allow_origins=settings.ALLOWED_ORIGINS + [settings.FRONTEND_URL],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        response.headers["X-Process-Time-MS"] = str(elapsed_ms)
        response.headers["X-ARK-Version"] = settings.APP_VERSION
        return response

    # ── Routers ───────────────────────────────────────────────────────────────
    PREFIX = "/api/v1"

    app.include_router(auth.router, prefix=PREFIX)
    app.include_router(repository.router, prefix=PREFIX)
    app.include_router(scan.router, prefix=PREFIX)
    app.include_router(reports.router, prefix=PREFIX)

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
