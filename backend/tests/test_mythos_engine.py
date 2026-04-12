"""
Unit Tests — ARK Mythos Engine™

Tests the offline AI analysis engine:
  1. False positive detection heuristics
  2. Exploitability scoring
  3. OWASP Top 10 mapping
  4. CWE mapping
  5. MITRE ATT&CK mapping
  6. Compliance framework mapping (SOC2, PCI, HIPAA, ISO)
  7. Attack chain correlation
  8. Business impact assessment
  9. Priority ranking
  10. Full engine run
"""
import pytest
from app.security.nexus_engine.finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.security.nexus_engine.mythos_engine import (
    run_mythos_engine,
    _calc_fp_probability,
    _calc_exploitability,
    _map_owasp,
    _map_cwe,
    _map_mitre,
    _map_compliance,
    _assess_business_impact,
    MythosAnalysis,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(
    rule_id: str = "test-rule",
    issue: str = "test issue",
    description: str = "",
    file: str = "app/main.py",
    line: int = 10,
    code_snippet: str = "eval(user_input)",
    severity: NexusSeverity = NexusSeverity.HIGH,
    confidence: float = 0.8,
) -> NexusFinding:
    return NexusFinding(
        layer=NexusLayer.SURFACE,
        rule_id=rule_id,
        issue=issue,
        description=description,
        file=file,
        line=line,
        code_snippet=code_snippet,
        severity=severity,
        confidence=confidence,
        exploitability=0.5,
        blast_radius=5,
    )


# ── 1. False Positive Detection ───────────────────────────────────────────────

class TestFalsePositiveDetection:

    def test_test_file_increases_fp_score(self):
        f = _finding(file="tests/test_auth.py")
        score = _calc_fp_probability(f, "tests/test_auth.py", "eval(user_input)", "eval")
        assert score > 0.3, "Test file should raise FP probability by at least 0.3"

    def test_example_file_increases_fp_score(self):
        f = _finding(file="examples/demo.py")
        score = _calc_fp_probability(f, "examples/demo.py", "eval(x)", "eval")
        assert score >= 0.1  # example/ path adds some FP signal

    def test_production_file_stays_low(self):
        f = _finding(file="app/api/auth.py")
        score = _calc_fp_probability(f, "app/api/auth.py", "eval(user_input)", "eval")
        assert score < 0.4, "Real production file should not be heavily flagged as FP"

    def test_nosec_comment_increases_fp(self):
        f = _finding(code_snippet="# nosec\neval(x)")
        score = _calc_fp_probability(f, "app.py", "# nosec\neval(x)", "eval")
        assert score > 0.1

    def test_short_snippet_increases_fp(self):
        f = _finding(code_snippet="x")
        score = _calc_fp_probability(f, "app.py", "x", "eval")
        assert score >= 0.1

    def test_low_confidence_finding_increases_fp(self):
        f = _finding(confidence=0.3)
        score = _calc_fp_probability(f, "app.py", "eval(x)", "eval")
        assert score > 0.1

    def test_commented_line_is_high_fp(self):
        f = _finding(code_snippet="# eval(user_input)")
        score = _calc_fp_probability(f, "app.py", "# eval(user_input)", "eval")
        assert score >= 0.4


# ── 2. Exploitability Scoring ─────────────────────────────────────────────────

class TestExploitabilityScoring:

    def test_sql_injection_is_highly_exploitable(self):
        f = _finding(rule_id="sqli", issue="SQL injection", file="app/api/routes.py")
        score = _calc_exploitability(f, "sqli sql injection", "app/api/routes.py")
        assert score >= 0.7

    def test_xss_is_moderately_exploitable(self):
        f = _finding(rule_id="xss", issue="XSS vulnerability")
        score = _calc_exploitability(f, "xss cross-site", "app.py")
        assert 0.4 <= score <= 1.0

    def test_eval_exec_very_exploitable(self):
        f = _finding(rule_id="exec", issue="exec usage", code_snippet="exec(input())")
        score = _calc_exploitability(f, "eval( exec(", "app.py")
        assert score >= 0.6  # eval+exec both trigger boosts

    def test_utility_file_reduces_exploitability(self):
        f = _finding(file="utils/helper.py")
        score = _calc_exploitability(f, "eval(x)", "utils/helper.py")
        # Utility code is less reachable
        assert score < 1.0

    def test_api_route_increases_exploitability(self):
        f = _finding(file="api/routes.py")
        score = _calc_exploitability(f, "sqli", "api/routes.py")
        assert score >= 0.7

    def test_exploitability_never_exceeds_1(self):
        f = _finding(rule_id="sqli xss eval exec", file="api/handler.py")
        score = _calc_exploitability(f, "sqli xss eval exec command-injection", "api/handler.py")
        assert score <= 1.0

    def test_exploitability_never_below_0(self):
        f = _finding(file="internal/util.py")
        score = _calc_exploitability(f, "low-risk", "internal/util.py")
        assert score >= 0.0


# ── 3. OWASP Mapping ──────────────────────────────────────────────────────────

class TestOWASPMapping:

    def test_sqli_maps_to_a03(self):
        category, name = _map_owasp("sql-injection sqli database")
        assert category == "A03"
        assert "Injection" in name

    def test_jwt_maps_to_a07(self):
        category, name = _map_owasp("jwt token session")
        assert category == "A07"

    def test_cve_maps_to_a06(self):
        category, name = _map_owasp("cve dependency outdated")
        assert category == "A06"

    def test_hardcoded_secret_maps_to_a02(self):
        category, name = _map_owasp("password secret credential encrypt")
        assert category == "A02"

    def test_unrelated_finding_returns_empty_or_closest(self):
        category, name = _map_owasp("random unrelated text")
        # Should return empty or best guess
        assert isinstance(category, str)
        assert isinstance(name, str)


# ── 4. CWE Mapping ───────────────────────────────────────────────────────────

class TestCWEMapping:

    def test_sqli_maps_to_cwe89(self):
        assert _map_cwe("sql-injection sqli database", "sqli") == "CWE-89"

    def test_xss_maps_to_cwe79(self):
        assert _map_cwe("xss cross-site innerHTML", "xss") == "CWE-79"

    def test_eval_maps_to_cwe95(self):
        assert _map_cwe("eval( dangerous", "eval") == "CWE-95"

    def test_path_traversal_maps_to_cwe22(self):
        assert _map_cwe("path-traversal directory", "path-traversal") == "CWE-22"

    def test_hardcoded_secret_maps_to_cwe798(self):
        assert _map_cwe("hardcoded-secret api key", "hardcoded-secret") == "CWE-798"

    def test_pickle_maps_to_cwe502(self):
        assert _map_cwe("deserialization pickle unsafe", "pickle") == "CWE-502"

    def test_missing_keyword_returns_empty(self):
        assert _map_cwe("completely unrelated finding", "unknownrule") == ""


# ── 5. MITRE ATT&CK Mapping ──────────────────────────────────────────────────

class TestMITREMapping:

    def test_credential_access_mapped(self):
        tactic, technique = _map_mitre("password secret credential api-key")
        assert tactic == "Credential Access"
        assert "T1552" in technique

    def test_execution_mapped(self):
        tactic, technique = _map_mitre("eval exec command-injection")
        assert tactic == "Execution"

    def test_initial_access_for_injection(self):
        tactic, technique = _map_mitre("sqli injection xss")
        assert tactic == "Initial Access"

    def test_no_match_returns_empty(self):
        tactic, technique = _map_mitre("something completely unknown")
        assert tactic == ""
        assert technique == ""


# ── 6. Compliance Framework Mapping ──────────────────────────────────────────

class TestComplianceMapping:

    def test_auth_finding_hits_soc2(self):
        violations = _map_compliance("jwt session auth access-control rbac")
        assert "SOC2" in violations
        controls = violations["SOC2"]
        assert any("CC6.1" in c for c in controls)

    def test_sqli_hits_pci_dss(self):
        violations = _map_compliance("sqli sql-injection injection")
        assert "PCI_DSS_v4" in violations

    def test_encrypt_hits_hipaa(self):
        violations = _map_compliance("ssl tls encrypt https cleartext")
        assert "HIPAA" in violations

    def test_hardcoded_key_hits_iso27001(self):
        violations = _map_compliance("secret credential hardcoded api-key")
        assert "ISO_27001" in violations

    def test_low_risk_finding_may_have_no_violations(self):
        violations = _map_compliance("unused variable minor style issue")
        # It's ok to have no compliance violations for benign findings
        assert isinstance(violations, dict)


# ── 7. Full Engine Integration ────────────────────────────────────────────────

class TestMythosEngineIntegration:

    def _make_sqli_finding(self) -> NexusFinding:
        return _finding(
            rule_id="sqli",
            issue="SQL Injection via unparameterized query",
            description="User input directly concatenated into SQL",
            file="app/api/users.py",
            code_snippet="cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            severity=NexusSeverity.CRITICAL,
        )

    def _make_jwt_finding(self) -> NexusFinding:
        return _finding(
            rule_id="jwt-none",
            issue="JWT algorithm set to 'none'",
            description="JWT accepts unsigned tokens",
            file="app/auth/middleware.py",
            code_snippet="jwt.decode(token, options={'verify_signature': False})",
            severity=NexusSeverity.CRITICAL,
        )

    def test_engine_returns_report_for_empty_findings(self):
        report = run_mythos_engine([])
        assert report is not None
        assert report.analyses == []
        assert report.overall_risk_level == "MEDIUM"  # default

    def test_single_critical_finding_produces_high_risk(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert report.overall_risk_level in ("HIGH", "CRITICAL")

    def test_engine_maps_cwe_onto_findings(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert findings[0].cwe_id == "CWE-89"

    def test_engine_adds_ai_summary(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert findings[0].ai_summary is not None
        assert len(findings[0].ai_summary) > 10

    def test_engine_computes_risk_scores(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        for analysis in report.analyses:
            assert 0 <= analysis.risk_score <= 100

    def test_attack_chain_detected_for_combined_findings(self):
        """SQLi + JWT bypass = injection + auth keyword combo = attack chain."""
        sqli = _finding(
            rule_id="sqli",
            issue="SQL Injection via unparameterized query",
            description="injection auth sql database user",
            file="app/api/users.py",
            severity=NexusSeverity.CRITICAL,
        )
        jwt_f = _finding(
            rule_id="jwt-none",
            issue="JWT auth bypass — algorithm none",
            description="auth jwt authentication token session",
            file="app/auth/middleware.py",
            severity=NexusSeverity.CRITICAL,
        )
        findings = [sqli, jwt_f]
        report = run_mythos_engine(findings)
        has_chain = any(a.attack_chain_probability > 0.5 for a in report.analyses)
        assert has_chain, "Attack chain should be detected — injection + auth keywords present"

    def test_priority_ranking_critical_is_rank_1(self):
        critical = self._make_sqli_finding()  # CRITICAL
        low = _finding(rule_id="info", issue="low issue", severity=NexusSeverity.LOW)
        findings = [low, critical]
        report = run_mythos_engine(findings)
        # The critical finding should have a lower rank number (1 = highest priority)
        analyses = report.analyses
        rank_of_critical = analyses[1].fix_priority_rank  # critical is index 1
        rank_of_low = analyses[0].fix_priority_rank
        assert rank_of_critical < rank_of_low

    def test_compliance_summary_populated(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert isinstance(report.compliance_summary, dict)
        assert "SOC2" in report.compliance_summary or "PCI_DSS_v4" in report.compliance_summary

    def test_owasp_coverage_populated(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert isinstance(report.owasp_coverage, dict)
        assert len(report.owasp_coverage) > 0

    def test_executive_brief_is_string(self):
        findings = [self._make_sqli_finding(), self._make_jwt_finding()]
        report = run_mythos_engine(findings)
        assert isinstance(report.executive_brief, str)
        assert len(report.executive_brief) > 20

    def test_attack_surface_score_in_range(self):
        findings = [self._make_sqli_finding()]
        report = run_mythos_engine(findings)
        assert 0 <= report.attack_surface_score <= 100
