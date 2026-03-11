# Import all models to ensure they are registered with SQLAlchemy Base
from app.models.user import User  # noqa: F401
from app.models.repository import Repository  # noqa: F401
from app.models.scan_report import ScanReport  # noqa: F401
from app.models.vulnerability import Vulnerability  # noqa: F401
