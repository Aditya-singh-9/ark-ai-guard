"""
ScanReport model — represents one complete security scan of a repository.
SQLite-compatible: uses Integer instead of BigInteger.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text, Float, ForeignKey, func, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum
from app.database.db import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Foreign key to repository
    repository_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    # Scan metadata
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    scan_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime, server_default=func.now(), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Vulnerability counts
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Security scoring (0–100)
    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Detected tech stack
    detected_language: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    detected_frameworks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # AI analysis output
    ai_recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    architecture_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Generated CI/CD pipeline YAML
    cicd_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Error details (if scan failed)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    repository: Mapped["Repository"] = relationship("Repository", back_populates="scan_reports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="scan_report", cascade="all, delete-orphan"
    )

    def compute_security_score(self) -> float:
        """
        Calculate security score 0–100.
        Deduct: critical*15, high*7, medium*3, low*1. Floor at 0.
        """
        deduction = (
            self.critical_count * 15
            + self.high_count * 7
            + self.medium_count * 3
            + self.low_count * 1
        )
        return max(0.0, 100.0 - deduction)

    def __repr__(self) -> str:
        return f"<ScanReport id={self.id} repo_id={self.repository_id} score={self.security_score}>"
