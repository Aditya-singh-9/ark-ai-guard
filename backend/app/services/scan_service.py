"""
Scan orchestration service — powered by ARK Nexus Engine™ + Mythos™.

Pipeline:
  1. Clone repository
  2. Analyse project structure
  3. Run Nexus Engine (7 layers in parallel + Mythos AI)
  4. Persist findings to DB with Nexus + Mythos metadata
  5. AI analysis + CI/CD generation
  6. Run Policy Engine (security gates)
  7. Generate Auto-Fix suggestions
  8. Compute Nexus Score
  9. Cleanup
"""
import json
import time
import asyncio
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session

from app.models.scan_report import ScanReport, ScanStatus
from app.models.vulnerability import Vulnerability, Severity, ScannerType
from app.models.repository import Repository
from app.services.repo_cloner import repo_cloner
from app.services.ai_analysis_service import analyse_repository
from app.services.cicd_generator import generate_cicd_pipeline
from app.services.policy_engine import evaluate_policies, build_scan_policy_data
from app.services.autofix_service import generate_ai_fixes
from app.security.nexus_engine import run_nexus_engine, NexusResult
from app.security.nexus_engine.finding_types import NexusFinding, NexusSeverity
from app.utils.logger import get_logger

log = get_logger(__name__)

# Cap max findings stored in DB per scan
MAX_FINDINGS_STORED = 500


def _nexus_severity_to_db(sev: NexusSeverity) -> Severity:
    mapping = {
        NexusSeverity.CRITICAL: Severity.CRITICAL,
        NexusSeverity.HIGH:     Severity.HIGH,
        NexusSeverity.MEDIUM:   Severity.MEDIUM,
        NexusSeverity.LOW:      Severity.LOW,
        NexusSeverity.INFO:     Severity.INFO,
    }
    return mapping.get(sev, Severity.MEDIUM)


def _scanner_type(scanner_str: str) -> ScannerType:
    if "nexus+ai" in scanner_str:
        return ScannerType.NEXUS
    if "nexus" in scanner_str:
        return ScannerType.NEXUS
    mapping = {
        "semgrep": ScannerType.SEMGREP,
        "bandit":  ScannerType.BANDIT,
        "trivy":   ScannerType.TRIVY,
    }
    return mapping.get(scanner_str.lower(), ScannerType.NEXUS)


async def run_full_scan(
    db: Session,
    repository: Repository,
    scan_report: ScanReport,
    access_token: str | None = None,
) -> ScanReport:
    """
    Execute the full Nexus Engine security scanning pipeline.

    Steps:
    1. Clone the repository
    2. Analyse project structure
    3. Run Nexus Engine (7 layers)
    4. Persist vulnerabilities to DB
    5. AI analysis & CI/CD generation
    6. Compute Nexus Score + legacy security score
    7. Cleanup

    Returns:
        Updated ScanReport with status=COMPLETED or FAILED
    """
    scan_id = scan_report.id
    start_time = time.time()

    log.info(f"[Scan {scan_id}] Starting Nexus Engine for {repository.full_name}")

    scan_report.status = ScanStatus.CLONING
    scan_report.scan_phase_detail = "Cloning repository…"
    db.commit()

    clone_path: str | None = None

    def _update_phase(label: str) -> None:
        """Update phase detail in DB for live UI polling."""
        try:
            scan_report.scan_phase_detail = label[:490]
            db.commit()
        except Exception:
            pass

    try:
        # ── Step 1: Clone ────────────────────────────────────────────────
        log.info(f"[Scan {scan_id}] Cloning {repository.clone_url or repository.url}")
        clone_path = repo_cloner.clone_repository(
            clone_url=repository.clone_url or repository.url,
            scan_id=scan_id,
            access_token=access_token,
        )

        # ── Step 2: Structure Analysis ───────────────────────────────────
        _update_phase("Analysing project structure…")
        log.info(f"[Scan {scan_id}] Analysing structure…")
        structure = repo_cloner.analyse_structure(clone_path)

        scan_report.detected_language   = structure.get("language")
        scan_report.detected_frameworks = json.dumps(structure.get("frameworks", []))
        db.commit()

        # ── Step 3: Run Nexus Engine ─────────────────────────────────────
        scan_report.status = ScanStatus.SCANNING
        _update_phase("Nexus Engine starting — Layer 1: Surface Scan…")
        db.commit()

        def _progress_callback(label: str, layer: int, count: int = 0) -> None:
            layer_label = f"L{layer}: " if layer > 0 else ""
            _update_phase(f"Nexus Engine — {layer_label}{label}")

        log.info(f"[Scan {scan_id}] Running Nexus Engine…")
        nexus_result: NexusResult = await run_nexus_engine(
            repo_path=clone_path,
            progress_callback=_progress_callback,
            enable_ai_fusion=True,
        )

        # ── Step 4: Process findings ─────────────────────────────────────
        _update_phase(f"Processing {len(nexus_result.findings)} findings…")
        log.info(f"[Scan {scan_id}] Nexus Engine complete — {len(nexus_result.findings)} findings")

        all_findings = nexus_result.findings[:MAX_FINDINGS_STORED]

        # Count by severity
        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for f in all_findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        scan_report.total_vulnerabilities = len(all_findings)
        scan_report.critical_count = severity_counts["critical"]
        scan_report.high_count     = severity_counts["high"]
        scan_report.medium_count   = severity_counts["medium"]
        scan_report.low_count      = severity_counts["low"]

        # Store Nexus Engine metadata
        scan_report.nexus_score              = nexus_result.nexus_score
        scan_report.scan_layers_completed    = json.dumps(nexus_result.layers_completed)
        scan_report.nexus_executive_summary  = json.dumps(nexus_result.executive_summary)

        # ── Step 5: Persist Vulnerabilities ─────────────────────────────
        log.info(f"[Scan {scan_id}] Persisting {len(all_findings)} findings…")
        for f in all_findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                layer_id=f.layer.value,
                file_path=_safe_str(f.file, 500),
                line_number=f.line if f.line else None,
                column_number=f.column if f.column else None,
                issue=_safe_str(f.issue, 1000),
                description=_safe_str(f.description, 2000),
                severity=_nexus_severity_to_db(f.severity),
                scanner=_scanner_type(f.scanner),
                rule_id=_safe_str(f.rule_id, 200),
                cve_id=_safe_str(f.cve_id, 50) if f.cve_id else None,
                cwe_id=_safe_str(f.cwe_id, 50) if f.cwe_id else None,
                code_snippet=_safe_str(f.code_snippet, 2000),
                suggested_fix=_safe_str(f.suggested_fix, 2000),
                package_name=_safe_str(f.package_name, 200) if f.package_name else None,
                package_version=_safe_str(f.package_version, 100) if f.package_version else None,
                fixed_version=_safe_str(f.fixed_version, 100) if f.fixed_version else None,
                confidence=round(f.confidence, 3),
                exploitability=round(f.exploitability, 3),
                blast_radius=f.blast_radius,
                false_positive_probability=round(f.false_positive_probability, 3),
                ai_summary=_safe_str(f.ai_summary, 1000) if f.ai_summary else None,
            )
            db.add(vuln)
        db.flush()

        # ── Step 6: AI Analysis & CI/CD Generation ───────────────────────
        _update_phase("AI vulnerability analysis & CI/CD generation…")
        scan_report.status = ScanStatus.ANALYSING
        db.commit()

        # Convert Nexus findings to legacy dict format for AI analysis
        legacy_findings = [f.to_dict() for f in all_findings[:50]]  # top 50 for AI prompt

        ai_task   = analyse_repository(structure, legacy_findings)
        cicd_task = generate_cicd_pipeline(repository.full_name, structure)

        ai_result, cicd_yaml = await asyncio.gather(ai_task, cicd_task)

        scan_report.ai_recommendations   = json.dumps(ai_result)
        scan_report.architecture_summary = ai_result.get("security_assessment", "")
        scan_report.cicd_yaml            = cicd_yaml

        # ── Step 7: Finalise ─────────────────────────────────────────────
        scan_report.status = ScanStatus.FINALISING
        _update_phase("Finalising report…")
        db.commit()

        # Use Nexus Score as the primary security score (it's more accurate)
        # Fall back to legacy deduction formula if Nexus Score is somehow unavailable
        scan_report.security_score = (
            scan_report.nexus_score
            if scan_report.nexus_score is not None
            else scan_report.compute_security_score()
        )

        elapsed = time.time() - start_time
        scan_report.status              = ScanStatus.COMPLETED
        scan_report.completed_at        = datetime.now(timezone.utc)
        scan_report.duration_seconds    = round(elapsed, 2)
        scan_report.scan_phase_detail   = "Completed"

        repository.last_scanned_at = datetime.now(timezone.utc)
        repository.total_scans     = (repository.total_scans or 0) + 1

        db.commit()
        log.info(
            f"[Scan {scan_id}] ✓ Complete in {elapsed:.1f}s — "
            f"Nexus Score: {scan_report.nexus_score:.1f} — "
            f"{len(all_findings)} findings"
        )

        # ── Step 8: Mythos Report Persistence ────────────────────────────
        mythos_report = nexus_result.mythos_report
        if mythos_report:
            try:
                scan_report.mythos_risk_level    = mythos_report.overall_risk_level
                scan_report.mythos_attack_surface = round(mythos_report.attack_surface_score, 1)
                scan_report.compliance_summary   = json.dumps(mythos_report.compliance_summary)
                scan_report.owasp_coverage       = json.dumps(mythos_report.owasp_coverage)
                scan_report.threat_model         = mythos_report.threat_model_summary
                scan_report.executive_brief      = mythos_report.executive_brief
                db.commit()
            except Exception as exc:
                log.debug(f"[Scan {scan_id}] Mythos persistence error (non-critical): {exc}")

        # ── Step 9: Policy Engine ────────────────────────────────────────
        try:
            policy_data = build_scan_policy_data(scan_report, mythos_report)
            policy_result = evaluate_policies(policy_data)
            scan_report.policy_gate_status = policy_result.gate_status
            scan_report.policy_violations  = json.dumps([
                {"rule": v.rule_name, "action": v.action.value, "message": v.message}
                for v in policy_result.violations + policy_result.warnings
            ])
            db.commit()
            log.info(f"[Scan {scan_id}] Policy gate: {policy_result.gate_status}")
        except Exception as exc:
            log.debug(f"[Scan {scan_id}] Policy engine error (non-critical): {exc}")

        # ── Step 10: Auto-Fix Generation ──────────────────────────────────
        try:
            _update_phase("Generating auto-fix suggestions…")
            fix_findings = [f.to_dict() for f in all_findings[:30]]
            fixes = await generate_ai_fixes(fix_findings)
            if fixes:
                scan_report.autofix_suggestions = json.dumps([
                    {
                        "finding_id": fix.finding_id,
                        "file": fix.file_path,
                        "line": fix.line_number,
                        "original": fix.original_code[:200],
                        "fixed": fix.fixed_code[:500],
                        "explanation": fix.explanation,
                        "confidence": fix.confidence,
                        "model": fix.model,
                        "breaking_risk": fix.breaking_risk,
                    }
                    for fix in fixes[:20]  # Store top 20 fixes
                ])
                db.commit()
                log.info(f"[Scan {scan_id}] Generated {len(fixes)} auto-fix suggestions")
        except Exception as exc:
            log.debug(f"[Scan {scan_id}] Auto-fix error (non-critical): {exc}")

    except Exception as exc:
        log.error(f"[Scan {scan_id}] ✗ Failed: {exc}", exc_info=True)
        scan_report.status          = ScanStatus.FAILED
        scan_report.error_message   = str(exc)[:2000]
        scan_report.completed_at    = datetime.now(timezone.utc)
        scan_report.scan_phase_detail = f"Failed: {str(exc)[:200]}"
        db.commit()

    finally:
        if clone_path:
            repo_cloner.cleanup(clone_path)

    return scan_report


def _safe_str(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    return str(value)[:max_len]


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Deduplicate raw findings dicts by (file, line, rule_id) fingerprint.
    When duplicates exist, keeps the one with the highest severity.
    Sorts result: critical → high → medium → low → info.
    """
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best: dict[str, dict] = {}
    for f in findings:
        key = f"{f.get('file')}:{f.get('line')}:{f.get('rule_id')}"
        existing = best.get(key)
        if existing is None:
            best[key] = f
        else:
            # Keep the higher-severity duplicate
            if _SEV_ORDER.get(f.get("severity", "info"), 4) < _SEV_ORDER.get(
                existing.get("severity", "info"), 4
            ):
                best[key] = f
    return sorted(best.values(), key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 4))
