"""
Database engine, session factory, and dependency injection helper.
"""
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session
from typing import Generator
from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)


# ── Declarative Base ──────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """All SQLAlchemy models inherit from this base."""
    pass


# ── Engine ────────────────────────────────────────────────────────────────────

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,       # Test connections before using from pool
    pool_size=10,             # Maintained open connections
    max_overflow=20,          # Extra connections beyond pool_size
    pool_timeout=30,          # Seconds to wait for a connection
    echo=settings.DEBUG,      # Log SQL in dev
)


# ── Session Factory ───────────────────────────────────────────────────────────

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ── FastAPI Dependency ────────────────────────────────────────────────────────

def get_db() -> Generator[Session, None, None]:
    """
    Yield a database session and ensure it is closed after request.

    Usage in FastAPI route:
        db: Session = Depends(get_db)
    """
    db: Session = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Init ──────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """
    Create all tables defined via SQLAlchemy models.
    Called once at application startup.
    """
    # Import models to register them with Base.metadata
    import app.models  # noqa: F401

    log.info("Initialising database tables…")
    Base.metadata.create_all(bind=engine)
    log.info("Database ready ✓")


def check_db_connection() -> bool:
    """Health-check: returns True if the DB is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        log.error(f"Database health check failed: {exc}")
        return False
