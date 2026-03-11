"""
Tests for score computation, deduplication, and scan service utilities.
"""
import pytest
from app.models.scan_report import ScanReport, ScanStatus


class TestSecurityScoreComputation:
    """Test the security score formula on ScanReport model."""

    def _make_report(self, critical=0, high=0, medium=0, low=0) -> ScanReport:
        r = ScanReport()
        r.critical_count = critical
        r.high_count = high
        r.medium_count = medium
        r.low_count = low
        return r

    def test_perfect_score(self):
        r = self._make_report()
        assert r.compute_security_score() == 100.0

    def test_single_critical_deducts_15(self):
        r = self._make_report(critical=1)
        assert r.compute_security_score() == 85.0

    def test_single_high_deducts_7(self):
        r = self._make_report(high=1)
        assert r.compute_security_score() == 93.0

    def test_single_medium_deducts_3(self):
        r = self._make_report(medium=1)
        assert r.compute_security_score() == 97.0

    def test_single_low_deducts_1(self):
        r = self._make_report(low=1)
        assert r.compute_security_score() == 99.0

    def test_score_floors_at_zero(self):
        r = self._make_report(critical=10, high=10, medium=10, low=10)
        assert r.compute_security_score() == 0.0

    def test_mixed_findings(self):
        # 1 critical (15) + 2 high (14) + 3 medium (9) + 4 low (4) = deduction 42
        r = self._make_report(critical=1, high=2, medium=3, low=4)
        assert r.compute_security_score() == 58.0

    def test_status_enum_values(self):
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"


class TestScanServiceDeduplication:
    """Test the deduplication logic in scan_service."""

    def test_dedup_removes_exact_duplicates(self):
        from app.services.scan_service import _deduplicate_findings

        findings = [
            {"file": "a.py", "line": 10, "rule_id": "B001", "severity": "high", "issue": "x"},
            {"file": "a.py", "line": 10, "rule_id": "B001", "severity": "high", "issue": "x"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 1

    def test_dedup_keeps_higher_severity(self):
        from app.services.scan_service import _deduplicate_findings

        findings = [
            {"file": "a.py", "line": 5, "rule_id": "X1", "severity": "low", "issue": "q"},
            {"file": "a.py", "line": 5, "rule_id": "X1", "severity": "critical", "issue": "q"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_dedup_preserves_different_files(self):
        from app.services.scan_service import _deduplicate_findings

        findings = [
            {"file": "a.py", "line": 1, "rule_id": "R1", "severity": "high", "issue": "i"},
            {"file": "b.py", "line": 1, "rule_id": "R1", "severity": "high", "issue": "i"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 2

    def test_dedup_sorts_critical_first(self):
        from app.services.scan_service import _deduplicate_findings

        findings = [
            {"file": "z.py", "line": 1, "rule_id": "Lo", "severity": "low", "issue": "l"},
            {"file": "a.py", "line": 1, "rule_id": "Cr", "severity": "critical", "issue": "c"},
            {"file": "m.py", "line": 1, "rule_id": "Me", "severity": "medium", "issue": "m"},
        ]
        result = _deduplicate_findings(findings)
        assert result[0]["severity"] == "critical"
        assert result[-1]["severity"] == "low"
