"""
ARK Nexus Engine — Layer 7: Multi-Model AI Fusion

Dual-model architecture:
  1. ARK Mythos™ (offline) — Always available, zero API cost
     - False-positive reduction via contextual heuristics
     - OWASP/CWE/MITRE ATT&CK mapping
     - Compliance framework analysis (SOC2, PCI, HIPAA, ISO 27001)
     - Attack chain correlation
     - STRIDE threat modeling
     - Business impact assessment

  2. Gemini (online) — Enhanced accuracy when API key is available
     - AI-powered false positive classification
     - Context-aware exploitability scoring
     - Human-readable impact summaries

Both models' outputs are fused for the best possible results.
Falls back gracefully: Mythos alone → Mythos + Gemini → Mythos only on failure.
"""
from __future__ import annotations
import json
import os
from typing import Any

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from .mythos_engine import run_mythos_engine, MythosReport
from app.utils.logger import get_logger

log = get_logger(__name__)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
MAX_BATCH      = 12   # findings per Gemini call


async def run_layer7_ai_fusion(
    findings: list[NexusFinding],
) -> tuple[list[NexusFinding], MythosReport]:
    """
    Multi-Model AI Fusion:
      Step 1: Run ARK Mythos (offline, always available)
      Step 2: Run Gemini if API key available (online, enhanced)
      Step 3: Fuse results for maximum accuracy

    Returns:
        (augmented_findings, mythos_report)
    """
    if not findings:
        return findings, MythosReport()

    # ── Step 1: Mythos Engine (always runs) ──────────────────────────────
    log.info(f"[Layer 7] Running ARK Mythos™ on {len(findings)} findings...")
    mythos_report = run_mythos_engine(findings)
    # Mythos already augments findings in-place (CWE, summaries, FP scores)

    # ── Step 2: Gemini Enhancement (if available) ────────────────────────
    if GEMINI_API_KEY:
        log.info("[Layer 7] Enhancing with Gemini online model...")
        # Only augment medium+ severity with Gemini (save API quota)
        to_augment = [f for f in findings if f.severity not in (NexusSeverity.INFO,)]
        skip = [f for f in findings if f.severity == NexusSeverity.INFO]

        try:
            gemini_augmented = await _batch_augment_gemini(to_augment)
            findings = gemini_augmented + skip
            log.info(f"[Layer 7] Gemini augmented {len(gemini_augmented)} findings")
        except Exception as exc:
            log.warning(f"[Layer 7] Gemini failed — Mythos results used: {exc}")
    else:
        log.info("[Layer 7] No Gemini API key — using Mythos results only")

    log.info(
        f"[Layer 7] AI Fusion complete — "
        f"Risk Level: {mythos_report.overall_risk_level}, "
        f"Attack Surface: {mythos_report.attack_surface_score:.0f}/100"
    )
    return findings, mythos_report


async def _batch_augment_gemini(findings: list[NexusFinding]) -> list[NexusFinding]:
    """Process findings in batches for Gemini augmentation."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
    except ImportError:
        log.warning("[Layer 7] google-generativeai not installed — skipping Gemini")
        return findings

    results: list[NexusFinding] = []
    batches = [findings[i:i+MAX_BATCH] for i in range(0, len(findings), MAX_BATCH)]

    for batch_idx, batch in enumerate(batches):
        try:
            augmented_batch = await _call_gemini(model, batch)
            results.extend(augmented_batch)
        except Exception as exc:
            log.debug(f"[Layer 7] Gemini batch {batch_idx} failed: {exc}")
            results.extend(batch)

    return results


async def _call_gemini(model: Any, batch: list[NexusFinding]) -> list[NexusFinding]:
    """Make a single Gemini API call to augment a batch of findings."""
    import asyncio

    finding_list = []
    for i, f in enumerate(batch):
        finding_list.append({
            "idx": i,
            "rule_id": f.rule_id,
            "issue": f.issue,
            "severity": f.severity.value,
            "file": f.file,
            "line": f.line,
            "snippet": f.code_snippet[:150],
            "confidence": f.confidence,
            "cwe": f.cwe_id or "",
        })

    prompt = f"""You are an expert AppSec engineer reviewing security findings.
Analyze these {len(batch)} security findings and return a JSON array.

For each finding, provide:
- idx: same as input
- false_positive_probability: 0.0–1.0 (how likely is this a false positive)
- exploitability: 0.0–1.0 (how easy to exploit in a real attack)
- ai_summary: 1-sentence human-readable explanation of real-world impact

Return ONLY valid JSON array, no markdown, no explanation.
Format: [{{"idx": 0, "false_positive_probability": 0.1, "exploitability": 0.8, "ai_summary": "..."}}]

Findings to analyze:
{json.dumps(finding_list, indent=2)}
"""

    try:
        response = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config={"temperature": 0.1, "max_output_tokens": 1024},
            )
        )
        raw_text = response.text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        ai_results: list[dict] = json.loads(raw_text)
        ai_map = {r["idx"]: r for r in ai_results}

    except Exception as exc:
        log.debug(f"[Layer 7] Gemini parse error: {exc}")
        return batch

    augmented: list[NexusFinding] = []
    
    # Self-training parameters
    training_data_path = os.path.join("ark_ml", "mythos_training.jsonl")
    os.makedirs(os.path.dirname(training_data_path), exist_ok=True)
    training_entries = []

    for i, finding in enumerate(batch):
        ai = ai_map.get(i, {})
        fp_prob = float(ai.get("false_positive_probability", 0.0))
        exploit = float(ai.get("exploitability", finding.exploitability))
        ai_sum = str(ai.get("ai_summary", ""))

        # Fuse Gemini + Mythos: prefer Gemini summary but keep Mythos CWE/OWASP
        updated = NexusFinding(
            layer=finding.layer,
            rule_id=finding.rule_id,
            issue=finding.issue,
            description=finding.description,
            file=finding.file,
            line=finding.line,
            column=finding.column,
            code_snippet=finding.code_snippet,
            severity=finding.severity,
            cwe_id=finding.cwe_id,  # Mythos already mapped this
            cve_id=finding.cve_id,
            # Fuse confidence: reduce if both models agree it's FP
            confidence=finding.confidence * (1.0 - fp_prob * 0.5),
            exploitability=min(1.0, (finding.exploitability + exploit) / 2),
            blast_radius=finding.blast_radius,
            suggested_fix=finding.suggested_fix,
            package_name=finding.package_name,
            package_version=finding.package_version,
            fixed_version=finding.fixed_version,
            # Gemini summary takes priority, Mythos as fallback
            ai_summary=ai_sum if ai_sum else (finding.ai_summary or ""),
            false_positive_probability=round(
                (finding.false_positive_probability + fp_prob) / 2, 2
            ),
            scanner="nexus+mythos+gemini",
        )
        augmented.append(updated)

        # ── Self-Training Pipeline: Log high-quality Gemini insights ──
        if ai_sum and fp_prob < 0.5:
            # We ONLY train on high-confidence, non-false positive findings to teach Mythos actual exploit analysis
            training_prompt = (
                "<|system|> You are the ARK Mythos Security AI. Provide a deep security analysis.\n"
                "<|user|> Analyze this vulnerability:\n"
                f"Issue: {finding.issue}\n"
                "Code:\n<|vuln|>\n"
                f"{finding.code_snippet[:600]}\n<|vuln|>\n"
                "<|assistant|>"
            )
            training_entries.append(json.dumps({
                "text": f"{training_prompt}{ai_sum}<|eos|>"
            }))

    # Async append to training dataset file gracefully
    if training_entries:
        try:
            with open(training_data_path, "a", encoding="utf-8") as f:
                for entry in training_entries:
                    f.write(entry + "\n")
        except Exception as e:
            log.warning(f"[Layer 7] Failed to write self-training logs: {e}")

    return augmented


def generate_executive_summary(findings: list[NexusFinding]) -> dict[str, Any]:
    """
    Generate a high-level executive summary from all findings.
    This is a local (non-AI) summarization, always available.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    layer_counts: dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0}
    affected_files: set[str] = set()
    cves: list[str] = []
    max_blast = 0

    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        layer_counts[f.layer.value] = layer_counts.get(f.layer.value, 0) + 1
        if f.file:
            affected_files.add(f.file)
        if f.cve_id:
            cves.append(f.cve_id)
        max_blast = max(max_blast, f.blast_radius)

    top_findings = sorted(
        [f for f in findings if f.severity in (NexusSeverity.CRITICAL, NexusSeverity.HIGH)],
        key=lambda x: x.exploitability * x.blast_radius,
        reverse=True,
    )[:5]

    return {
        "severity_breakdown": severity_counts,
        "layer_breakdown": {
            f"layer_{k}": v for k, v in layer_counts.items() if v > 0
        },
        "total_findings": len(findings),
        "affected_files": len(affected_files),
        "unique_cves": list(set(cves))[:10],
        "max_blast_radius": max_blast,
        "top_priority_findings": [
            {
                "issue": f.issue,
                "file": f.file,
                "severity": f.severity.value,
                "exploitability": f.exploitability,
                "blast_radius": f.blast_radius,
                "fix": f.suggested_fix,
                "cwe": f.cwe_id or "",
            }
            for f in top_findings
        ],
    }
