"""
ARK Nexus Engine — Orchestrator

Runs all 7 layers in parallel, merges and deduplicates findings,
computes the Nexus Score using the multiplicative risk model, and
returns a complete NexusResult.

Nexus Score™ formula:
    S = 100 × Π(1 - Pᵢ × wᵢ × Cᵢ)

Where:
    Pᵢ  = normalized exploitability (0–1)
    wᵢ  = severity weight (critical=1.0, high=0.7, medium=0.4, low=0.15)
    Cᵢ  = confidence factor (0–1), reduced by AI FP probability
    Π   = product over all findings
    Floor at 0.0
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from .finding_types import NexusFinding, NexusSeverity, SEVERITY_WEIGHT
from .file_collector import collect_repo_files, RepoFileMap
from .layer1_surface   import run_layer1_surface
from .layer2_semantic  import run_layer2_semantic
from .layer3_crypto    import run_layer3_crypto
from .layer4_deps      import run_layer4_deps
from .layer5_dataflow  import run_layer5_dataflow
from .layer6_iac       import run_layer6_iac
from .layer7_ai_fusion import run_layer7_ai_fusion, generate_executive_summary
from app.utils.logger  import get_logger

log = get_logger(__name__)


@dataclass
class NexusResult:
    """Complete result from a Nexus Engine scan."""
    findings: list[NexusFinding] = field(default_factory=list)
    nexus_score: float = 100.0
    layer_durations: dict[int, float] = field(default_factory=dict)
    layer_finding_counts: dict[int, int] = field(default_factory=dict)
    layers_completed: list[int] = field(default_factory=list)
    executive_summary: dict[str, Any] = field(default_factory=dict)
    total_duration_seconds: float = 0.0
    error: str | None = None
    mythos_report: Any = None  # MythosReport from offline AI

    def to_dict(self) -> dict:
        return {
            "nexus_score": round(self.nexus_score, 2),
            "total_findings": len(self.findings),
            "layers_completed": self.layers_completed,
            "layer_finding_counts": self.layer_finding_counts,
            "layer_durations": {str(k): round(v, 2) for k, v in self.layer_durations.items()},
            "executive_summary": self.executive_summary,
            "total_duration_seconds": round(self.total_duration_seconds, 2),
        }


# ── Progress callback type ─────────────────────────────────────────────────────
ProgressCallback = Callable[[str, int, int], None]
# Called as: callback(phase_label, layer_number, finding_count)


async def run_nexus_engine(
    repo_path: str,
    progress_callback: ProgressCallback | None = None,
    enable_ai_fusion: bool = True,
    max_repo_size_mb: float = 500.0,
) -> NexusResult:
    """
    Run the complete ARK Nexus Engine on a cloned repository.

    Args:
        repo_path: Absolute path to the cloned repository.
        progress_callback: Optional async callback for real-time progress updates.
        enable_ai_fusion: Whether to run Layer 7 (Gemini AI). Default True.
        max_repo_size_mb: Skip Layer 5 (cross-file dataflow) if repo exceeds this.

    Returns:
        NexusResult with all findings, Nexus Score, and per-layer metadata.
    """
    overall_start = time.perf_counter()
    result = NexusResult()

    def _notify(label: str, layer: int, count: int = 0) -> None:
        if progress_callback:
            try:
                progress_callback(label, layer, count)
            except Exception:
                pass

    # ── Pre-load all files ONCE (shared across all layers) ────────────────────
    _notify("Pre-loading repository files…", 0)
    t_collect = time.perf_counter()
    file_map: RepoFileMap = await asyncio.to_thread(collect_repo_files, repo_path)
    log.info(f"[Nexus] File collector: {file_map.total_files} files in {time.perf_counter() - t_collect:.1f}s")

    # ── Layers 1–6: run in parallel threads ───────────────────────────────────
    layer_runners = [
        (1, "Surface Pattern Scan",       run_layer1_surface),
        (2, "Semantic AST Analysis",      run_layer2_semantic),
        (3, "Cryptographic Audit",        run_layer3_crypto),
        (4, "Dependency DNA Analysis",    run_layer4_deps),
        (5, "Cross-File Data Flow",       run_layer5_dataflow),
        (6, "IaC Blast-Radius Analysis",  run_layer6_iac),
    ]

    async def _run_layer(layer_id: int, label: str, runner) -> tuple[int, list[NexusFinding], float]:
        _notify(f"Starting {label}…", layer_id)
        t0 = time.perf_counter()
        try:
            # Pass file_map to layers that support it
            findings = await asyncio.to_thread(runner, repo_path, file_map)
        except TypeError:
            # Fallback: layer doesn't accept file_map yet
            try:
                findings = await asyncio.to_thread(runner, repo_path)
            except Exception as exc:
                log.warning(f"[Nexus] Layer {layer_id} ({label}) error: {exc}")
                findings = []
        except Exception as exc:
            log.warning(f"[Nexus] Layer {layer_id} ({label}) error: {exc}")
            findings = []
        elapsed = time.perf_counter() - t0
        _notify(f"{label} complete ({len(findings)} findings)", layer_id, len(findings))
        log.info(f"[Nexus] Layer {layer_id} done in {elapsed:.1f}s — {len(findings)} findings")
        return layer_id, findings, elapsed

    # Run all 6 base layers concurrently
    tasks = [asyncio.create_task(_run_layer(lid, lbl, runner))
             for lid, lbl, runner in layer_runners]
    layer_results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[NexusFinding] = []

    for res in layer_results:
        if isinstance(res, Exception):
            log.error(f"[Nexus] Layer task exception: {res}")
            continue
        layer_id, findings, elapsed = res
        all_findings.extend(findings)
        result.layer_durations[layer_id] = elapsed
        result.layer_finding_counts[layer_id] = len(findings)
        result.layers_completed.append(layer_id)

    log.info(f"[Nexus] Layers 1–6 complete. Total raw findings: {len(all_findings)}")

    # ── Deduplicate ────────────────────────────────────────────────────────────
    _notify("Deduplicating findings…", 0)
    all_findings = _deduplicate(all_findings)
    log.info(f"[Nexus] After dedup: {len(all_findings)} findings")

    # ── Layer 7: Multi-Model AI Fusion (Mythos + Gemini) ────────────────────────
    if enable_ai_fusion:
        _notify("AI Fusion — Mythos™ + Gemini analysis…", 7)
        t7 = time.perf_counter()
        try:
            all_findings, mythos_report = await run_layer7_ai_fusion(all_findings)
            result.mythos_report = mythos_report
            result.layer_durations[7] = time.perf_counter() - t7
            result.layer_finding_counts[7] = len(all_findings)
            result.layers_completed.append(7)
        except Exception as exc:
            log.warning(f"[Nexus] Layer 7 skipped: {exc}")
            result.layer_durations[7] = 0.0

    # ── Cap findings ───────────────────────────────────────────────────────────
    all_findings = _sort_by_risk(all_findings)[:500]

    # ── Compute Nexus Score ────────────────────────────────────────────────────
    _notify("Computing Nexus Score…", 0)
    result.nexus_score = _compute_nexus_score(all_findings)

    # ── Executive Summary ─────────────────────────────────────────────────────
    result.executive_summary = generate_executive_summary(all_findings)

    result.findings = all_findings
    result.total_duration_seconds = time.perf_counter() - overall_start

    log.info(
        f"[Nexus] ✓ Complete in {result.total_duration_seconds:.1f}s — "
        f"Nexus Score: {result.nexus_score:.1f} — "
        f"{len(all_findings)} findings"
    )
    return result


def _compute_nexus_score(findings: list[NexusFinding]) -> float:
    """
    Nexus Score™ — multiplicative risk model.

    S = 100 × Π(1 - Pᵢ × wᵢ × Cᵢ)

    Each finding reduces the score multiplicatively.
    One critical/high-confidence finding drives the score toward 0.
    Theoretical low-confidence findings barely move it.
    """
    score = 100.0
    for f in findings:
        exploitability = max(0.0, min(1.0, f.exploitability))
        weight         = SEVERITY_WEIGHT.get(f.severity.value, 0.40)
        confidence     = max(0.0, min(1.0, f.confidence * (1.0 - f.false_positive_probability)))

        # Risk factor for this finding
        risk = exploitability * weight * confidence

        # Multiplicative reduction
        reduction_factor = 1.0 - risk * 0.30   # scale so single finding can't zero out
        score *= max(0.05, reduction_factor)   # floor each step at 0.05

        if score < 0.1:
            break  # Already effectively 0

    return max(0.0, round(score, 2))


def _deduplicate(findings: list[NexusFinding]) -> list[NexusFinding]:
    """
    Remove duplicate findings.
    Key: (file, line, rule_id_prefix).
    When duplicates exist, keep highest confidence × exploitability score.
    """
    seen: dict[tuple, NexusFinding] = {}

    for f in findings:
        # Normalize rule_id to first 2 segments (e.g. "nexus/l1")
        rule_prefix = "/".join(f.rule_id.split("/")[:3])
        key = (f.file, f.line, rule_prefix)
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        else:
            # Keep finding with higher risk score
            if (f.confidence * f.exploitability) > (existing.confidence * existing.exploitability):
                seen[key] = f

    return list(seen.values())


def _sort_by_risk(findings: list[NexusFinding]) -> list[NexusFinding]:
    """Sort findings by composite risk score (exploitability × blast_radius × confidence)."""
    severity_rank = {
        NexusSeverity.CRITICAL: 5,
        NexusSeverity.HIGH:     4,
        NexusSeverity.MEDIUM:   3,
        NexusSeverity.LOW:      2,
        NexusSeverity.INFO:     1,
    }
    return sorted(
        findings,
        key=lambda f: (
            severity_rank.get(f.severity, 1),
            f.exploitability * f.blast_radius * f.confidence,
        ),
        reverse=True,
    )
