"""
Shared pytest fixtures for ARK AI Guard test suite.
Uses an in-memory SQLite database and FastAPI TestClient.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.db import Base, get_db
from app.models.user import User
from app.models.repository import Repository
from app.models.scan_report import ScanReport, ScanStatus
from app.api.auth import create_access_token

# ── In-memory test database ───────────────────────────────────────────────────

TEST_DB_URL = "sqlite:///:memory:"

_test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSession = sessionmaker(bind=_test_engine, autocommit=False, autoflush=False)


def _override_get_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


# ── App fixture ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    """Create the FastAPI app with tables initialized."""
    # Import all models so they register with metadata
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=_test_engine)

    from main import create_app
    _app = create_app()
    _app.dependency_overrides[get_db] = _override_get_db
    yield _app
    Base.metadata.drop_all(bind=_test_engine)


@pytest.fixture(scope="session")
def client(app):
    """Reusable TestClient bound to the test app."""
    return TestClient(app)


# ── Database fixture ──────────────────────────────────────────────────────────

@pytest.fixture()
def db():
    """Fresh DB session per test, with rollback after each test."""
    connection = _test_engine.connect()
    transaction = connection.begin()
    session = _TestSession(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


# ── User fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture()
def user_a(db) -> User:
    """First test user (owner of repos/scans)."""
    u = User(
        github_id=100001,
        username="user_alice",
        email="alice@test.com",
        display_name="Alice",
        avatar_url=None,
        access_token_encrypted="test_token_alice",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def user_b(db) -> User:
    """Second test user (attacker in IDOR tests)."""
    u = User(
        github_id=100002,
        username="user_bob",
        email="bob@test.com",
        display_name="Bob",
        avatar_url=None,
        access_token_encrypted="test_token_bob",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


# ── JWT token helpers ─────────────────────────────────────────────────────────

def _make_token(user: User) -> str:
    return create_access_token({"sub": str(user.id), "username": user.username})


@pytest.fixture()
def token_a(user_a) -> str:
    return _make_token(user_a)


@pytest.fixture()
def token_b(user_b) -> str:
    return _make_token(user_b)


@pytest.fixture()
def auth_headers_a(token_a) -> dict:
    return {"Authorization": f"Bearer {token_a}"}


@pytest.fixture()
def auth_headers_b(token_b) -> dict:
    return {"Authorization": f"Bearer {token_b}"}


# ── Repository fixtures ───────────────────────────────────────────────────────

@pytest.fixture()
def repo_a(db, user_a) -> Repository:
    """Repository owned by user_a."""
    r = Repository(
        user_id=user_a.id,
        github_repo_id=9990001,
        name="alice-app",
        owner="user_alice",
        full_name="user_alice/alice-app",
        url="https://github.com/user_alice/alice-app",
        default_branch="main",
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@pytest.fixture()
def repo_b(db, user_b) -> Repository:
    """Repository owned by user_b."""
    r = Repository(
        user_id=user_b.id,
        github_repo_id=9990002,
        name="bob-app",
        owner="user_bob",
        full_name="user_bob/bob-app",
        url="https://github.com/user_bob/bob-app",
        default_branch="main",
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


# ── Scan fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture()
def scan_a(db, repo_a) -> ScanReport:
    """Completed scan for repo_a."""
    s = ScanReport(
        repository_id=repo_a.id,
        status=ScanStatus.COMPLETED,
        nexus_score=72.5,
        security_score=70.0,
        total_vulnerabilities=10,
        critical_count=1,
        high_count=3,
        medium_count=4,
        low_count=2,
        compliance_summary='{"SOC2": {"status": "WARN", "compliance_percentage": 80.0}}',
        owasp_coverage='{"A03: Injection": 2}',
        autofix_suggestions='[{"file": "app.py", "fix": "sanitize input"}]',
        policy_gate_status="warn",
        policy_violations='[]',
        mythos_risk_level="HIGH",
        mythos_attack_surface=45.0,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@pytest.fixture()
def scan_b(db, repo_b) -> ScanReport:
    """Completed scan for repo_b (another user's scan)."""
    s = ScanReport(
        repository_id=repo_b.id,
        status=ScanStatus.COMPLETED,
        nexus_score=55.0,
        total_vulnerabilities=20,
        critical_count=3,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s
