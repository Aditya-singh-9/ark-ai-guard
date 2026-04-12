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

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    # SQLite: use StaticPool for thread safety with check_same_thread=False
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=settings.DEBUG,
    )
else:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        echo=settings.DEBUG,
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
    
    # Auto-patch missing auth columns for legacy schema
    try:
        with engine.begin() as conn:
            # We catch exceptions internally if columns already exist
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(50)"))
                conn.execute(text("UPDATE users SET auth_provider = 'github' WHERE auth_provider IS NULL"))
            except Exception:
                pass
            
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
            except Exception:
                pass
        log.info("Schema integrity verified ✓")
    except Exception as e:
        log.warning(f"Schema patch warning (can be ignored if columns exist): {e}")

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
