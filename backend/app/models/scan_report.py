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
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYSING = "analysing"
    FINALISING = "finalising"
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

    # Legacy security score (0–100) — kept for backward compatibility
    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Nexus Score™ (0–100) — multiplicative risk model from Nexus Engine
    nexus_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Which Nexus Engine layers completed (JSON list e.g. [1,2,3,4,5,6,7])
    scan_layers_completed: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Real-time phase detail for live UI progress
    scan_phase_detail: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Detected tech stack
    detected_language: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    detected_frameworks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # AI analysis output
    ai_recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    architecture_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Nexus executive summary (JSON)
    nexus_executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Generated CI/CD pipeline YAML
    cicd_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── ARK Mythos™ AI Analysis ───────────────────────────────────────────
    mythos_risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # CRITICAL/HIGH/MEDIUM/LOW
    mythos_attack_surface: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0-100
    compliance_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: SOC2, PCI, HIPAA, ISO
    owasp_coverage: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON: OWASP Top 10 mapping
    threat_model: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # STRIDE threat model
    executive_brief: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Mythos executive summary

    # ── Policy-as-Code Engine ─────────────────────────────────────────────
    policy_gate_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # pass/warn/block
    policy_violations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # ── AI Auto-Fix Suggestions ───────────────────────────────────────────
    autofix_suggestions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array

    # ── Webhook/Trigger Metadata ──────────────────────────────────────────
    trigger: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # manual/webhook_push/webhook_pr_N
    branch: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)

    # Error details (if scan failed)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    repository: Mapped["Repository"] = relationship("Repository", back_populates="scan_reports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="scan_report", cascade="all, delete-orphan"
    )

    def compute_security_score(self) -> float:
        """
        Legacy security score 0–100.
        Deduct: critical*15, high*7, medium*3, low*1. Floor at 0.
        Kept for backward compatibility alongside Nexus Score.
        """
        deduction = (
            self.critical_count * 15
            + self.high_count * 7
            + self.medium_count * 3
            + self.low_count * 1
        )
        return max(0.0, 100.0 - deduction)

    def __repr__(self) -> str:
        return f"<ScanReport id={self.id} repo_id={self.repository_id} nexus_score={self.nexus_score}>"
