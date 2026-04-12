"""
ARK Nexus Engine — Layer 6: IaC & Configuration Blast-Radius Analysis

Scans Infrastructure-as-Code (Dockerfile, docker-compose, Kubernetes manifests,
Terraform, GitHub Actions) and estimates the blast-radius of each misconfiguration
— how many services, users, or systems could be compromised if exploited.

Unique "blast-radius" scoring: each finding gets an estimate of downstream impact.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from .file_collector import RepoFileMap

log = get_logger(__name__)

SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv",
             "dist", "build", "vendor"}

# ── Dockerfile patterns ────────────────────────────────────────────────────────
_DOCKERFILE_PATTERNS = [
    (
        re.compile(r'^FROM\s+.+:latest\b', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/docker-latest-tag",
        "Docker Image Pinned to ':latest' — Non-Deterministic Build",
        "Using ':latest' tag means the image may change unexpectedly, creating supply-chain risk.",
        NexusSeverity.MEDIUM, 0.92, 0.45, 6,
        "Pin to a specific digest or version: FROM python:3.11.9-slim@sha256:...",
    ),
    (
        re.compile(r'^USER\s+root\b|^USER\s+0\b', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/docker-root-user",
        "Docker Container Running as root",
        "Running containers as root maximizes blast radius if the container is compromised.",
        NexusSeverity.HIGH, 0.95, 0.70, 9,
        "Add: USER 1001 (non-root) as the last USER instruction before CMD/ENTRYPOINT.",
    ),
    (
        re.compile(r'--privileged|--cap-add\s+SYS_ADMIN|--cap-add=SYS_ADMIN', re.IGNORECASE),
        "nexus/l6/docker-privileged",
        "Docker Container With Dangerous Capabilities",
        "--privileged or SYS_ADMIN gives nearly root-host access. Full container escape vector.",
        NexusSeverity.CRITICAL, 0.98, 0.90, 10,
        "Remove --privileged. Use specific minimal capabilities with --cap-add.",
    ),
    (
        re.compile(r'^(ENV|ARG)\s+(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL)\s*=\s*\S+', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/docker-secret-in-env",
        "Secret/Credential in Dockerfile ENV or ARG",
        "Secrets set via ENV/ARG are embedded in the image layer and visible in 'docker inspect'.",
        NexusSeverity.CRITICAL, 0.92, 0.80, 8,
        "Use Docker secrets, or pass at runtime via -e. Never bake secrets into image layers.",
    ),
    (
        re.compile(r'^ADD\s+https?://', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/docker-add-url",
        "Dockerfile ADD From Remote URL — No Integrity Check",
        "ADD with a URL downloads at build time without verifying integrity (no hash check).",
        NexusSeverity.HIGH, 0.90, 0.65, 7,
        "Use curl with --fail and verify with sha256sum, or use COPY with pre-downloaded + verified files.",
    ),
    (
        re.compile(r'curl\s+[^|]*\|\s*(sh|bash|python|perl|ruby)', re.IGNORECASE),
        "nexus/l6/docker-curl-pipe-shell",
        "curl | sh — Remote Code Execution in Build",
        "Piping curl output to a shell is a critical supply-chain attack vector in Dockerfiles.",
        NexusSeverity.CRITICAL, 0.95, 0.85, 10,
        "Download, verify SHA256, then execute. Never pipe curl to shell.",
    ),
    (
        re.compile(r'--no-check-certificate|wget\s+[^>]*--no-check-certificate', re.IGNORECASE),
        "nexus/l6/docker-no-tls-verify",
        "wget/curl Without TLS Verification in Dockerfile",
        "Skipping TLS verification in Dockerfile enables MITM attacks during build time.",
        NexusSeverity.HIGH, 0.90, 0.65, 7,
        "Remove --no-check-certificate. Fix CA bundle issues instead.",
    ),
    (
        re.compile(r'^EXPOSE\s+(22|23|3389|5900)\b', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/docker-dangerous-port",
        "Dangerous Management Port Exposed in Dockerfile",
        "Exposing SSH (22), Telnet (23), RDP (3389), or VNC (5900) via EXPOSE increases attack surface.",
        NexusSeverity.HIGH, 0.90, 0.70, 8,
        "Remove EXPOSE for sensitive ports. Use jump hosts or bastion servers for remote access.",
    ),
    (
        re.compile(r'apt-get install\s+[^\\n]*--no-install-recommends', re.IGNORECASE),
        "nexus/l6/docker-no-install-recommends-good",  # This is GOOD but let's check the negative
        # Actually, let's flag the MISSING of --no-install-recommends differently
        # Skip this — hard to detect absence
        "NOT USED", NexusSeverity.INFO, 0.0, 0.0, 0, "",
    ),
    (
        re.compile(r'HEALTHCHECK\s+NONE', re.IGNORECASE),
        "nexus/l6/docker-no-healthcheck",
        "Docker Container Has No Health Check",
        "Without a HEALTHCHECK, orchestrators cannot detect when containers are unhealthy.",
        NexusSeverity.LOW, 0.85, 0.20, 3,
        "Add: HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1",
    ),
]

# ── docker-compose patterns ────────────────────────────────────────────────────
_COMPOSE_PATTERNS = [
    (
        re.compile(r'network_mode\s*:\s*host', re.IGNORECASE),
        "nexus/l6/compose-host-network",
        "Docker Compose Service Using Host Network Mode",
        "host network mode removes container network isolation — service can reach any host port.",
        NexusSeverity.HIGH, 0.95, 0.80, 9,
        "Use bridge networking with explicit port mappings instead of host mode.",
    ),
    (
        re.compile(r'privileged\s*:\s*true', re.IGNORECASE),
        "nexus/l6/compose-privileged",
        "Compose Service Running in Privileged Mode",
        "Privileged containers have nearly root-host access. Full container escape vector.",
        NexusSeverity.CRITICAL, 0.98, 0.90, 10,
        "Remove 'privileged: true'. Use specific capabilities only.",
    ),
    (
        re.compile(r'volumes:\s*\n\s*-\s*/:/[^:]*:rw', re.IGNORECASE | re.DOTALL),
        "nexus/l6/compose-host-root-mount",
        "Host Root '/' Mounted Into Container (Read-Write)",
        "Mounting the host root filesystem read-write allows container to modify the entire host.",
        NexusSeverity.CRITICAL, 0.98, 0.95, 10,
        "Never mount '/' into containers. Use specific paths with minimal permissions.",
    ),
    (
        re.compile(r'-\s*/var/run/docker\.sock:/var/run/docker\.sock', re.IGNORECASE),
        "nexus/l6/compose-docker-sock",
        "Docker Socket Mounted Into Container",
        "Mounting docker.sock gives the container full control of the Docker daemon — trivial host escape.",
        NexusSeverity.CRITICAL, 0.98, 0.95, 10,
        "Remove docker.sock mount. Use Docker-in-Docker or a docker-proxy with restricted permissions.",
    ),
    (
        re.compile(r'(PASSWORD|SECRET|API_KEY|TOKEN)\s*:\s*[^\s\n]{3,}', re.IGNORECASE | re.MULTILINE),
        "nexus/l6/compose-hardcoded-secret",
        "Hardcoded Secret in docker-compose Configuration",
        "Secrets hardcoded in docker-compose.yml are committed to version control.",
        NexusSeverity.CRITICAL, 0.85, 0.80, 8,
        "Use Docker secrets or environment variable references (${MY_SECRET}).",
    ),
    (
        re.compile(r'restart\s*:\s*always', re.IGNORECASE),
        "nexus/l6/compose-restart-always",
        "Container Set to Restart Always — Review for Crash Loops",
        "'restart: always' can mask crash loops and make debugging harder. Use 'on-failure' with limit.",
        NexusSeverity.INFO, 0.90, 0.10, 2,
        "Use 'restart: on-failure:5' to limit restart attempts and surface failures.",
    ),
]

# ── Kubernetes manifest patterns ───────────────────────────────────────────────
_K8S_PATTERNS = [
    (
        re.compile(r'allowPrivilegeEscalation\s*:\s*true', re.IGNORECASE),
        "nexus/l6/k8s-privilege-escalation",
        "K8s Container Allows Privilege Escalation",
        "allowPrivilegeEscalation: true breaks container isolation.",
        NexusSeverity.HIGH, 0.97, 0.80, 9,
        "Set allowPrivilegeEscalation: false in securityContext.",
    ),
    (
        re.compile(r'runAsRoot\s*:\s*true|runAsUser\s*:\s*0\b', re.IGNORECASE),
        "nexus/l6/k8s-run-as-root",
        "K8s Pod Running as Root",
        "Running Kubernetes pods as root violates least-privilege.",
        NexusSeverity.HIGH, 0.95, 0.75, 9,
        "Set runAsNonRoot: true and runAsUser: 1001 in securityContext.",
    ),
    (
        re.compile(r'privileged\s*:\s*true', re.IGNORECASE),
        "nexus/l6/k8s-privileged-container",
        "K8s Privileged Container",
        "Privileged K8s containers have full host access. Severe container escape risk.",
        NexusSeverity.CRITICAL, 0.98, 0.90, 10,
        "Remove 'privileged: true'. Use specific securityContext capabilities.",
    ),
    (
        re.compile(r'hostPID\s*:\s*true|hostIPC\s*:\s*true', re.IGNORECASE),
        "nexus/l6/k8s-host-pid-ipc",
        "K8s Pod Shares Host PID/IPC Namespace",
        "Sharing host PID/IPC breaks isolation and allows process injection.",
        NexusSeverity.CRITICAL, 0.97, 0.85, 10,
        "Remove hostPID: true and hostIPC: true from pod spec.",
    ),
    (
        re.compile(r'hostNetwork\s*:\s*true', re.IGNORECASE),
        "nexus/l6/k8s-host-network",
        "K8s Pod Using Host Network",
        "hostNetwork: true exposes the pod to all services on the host network.",
        NexusSeverity.HIGH, 0.97, 0.80, 9,
        "Use ClusterIP services and proper DNS for service discovery. Remove hostNetwork.",
    ),
    (
        re.compile(r'automountServiceAccountToken\s*:\s*true', re.IGNORECASE),
        "nexus/l6/k8s-service-account-token",
        "K8s Service Account Token Auto-Mounted",
        "Auto-mounted tokens expose Kubernetes API credentials inside every pod.",
        NexusSeverity.MEDIUM, 0.90, 0.55, 7,
        "Set automountServiceAccountToken: false unless the pod explicitly needs API access.",
    ),
    (
        re.compile(r'readOnlyRootFilesystem\s*:\s*false', re.IGNORECASE),
        "nexus/l6/k8s-writable-root-fs",
        "K8s Container Has Writable Root Filesystem",
        "readOnlyRootFilesystem is explicitly set to false, allowing attackers to modify binaries or config after compromise.",
        NexusSeverity.MEDIUM, 0.70, 0.50, 6,
        "Set readOnlyRootFilesystem: true. Mount writable volumes only for tmp/data dirs.",
    ),
    (
        re.compile(r'resources\s*:\s*\{\s*\}|limits\s*:\s*\{\s*\}', re.IGNORECASE),
        "nexus/l6/k8s-no-resource-limits",
        "K8s Container Has No Resource Limits",
        "Without resource limits, a compromised or buggy container can exhaust host resources (DoS).",
        NexusSeverity.MEDIUM, 0.85, 0.45, 6,
        "Set cpu and memory limits under resources.limits in the container spec.",
    ),
]

# ── GitHub Actions patterns ────────────────────────────────────────────────────
_GH_ACTIONS_PATTERNS = [
    (
        re.compile(r'GITHUB_TOKEN\s*:', re.IGNORECASE),
        "nexus/l6/gha-github-token-exposed",
        "GitHub Actions GITHUB_TOKEN Referenced in Workflow",
        "GITHUB_TOKEN should use minimal permissions. Ensure it's not over-permissioned.",
        NexusSeverity.MEDIUM, 0.80, 0.50, 6,
        "Set 'permissions: read-all' and only grant write where necessary.",
    ),
    (
        re.compile(r'uses:\s+actions/checkout@v[12]\b', re.IGNORECASE),
        "nexus/l6/gha-old-checkout",
        "Using Outdated actions/checkout Version (v1/v2)",
        "Older actions/checkout versions have known security issues. Use v4.",
        NexusSeverity.LOW, 0.90, 0.25, 4,
        "Upgrade to 'uses: actions/checkout@v4'.",
    ),
    (
        re.compile(r'run:\s*.*\$\{\{\s*github\.event\.(issue|pull_request)\.', re.IGNORECASE),
        "nexus/l6/gha-pwn-request",
        "GitHub Actions Workflow Injection via PR/Issue Body",
        "Interpolating github.event.issue or PR body into 'run:' enables workflow injection attacks.",
        NexusSeverity.CRITICAL, 0.90, 0.85, 8,
        "Never interpolate github.event.*.body directly into run steps. Use environment variables.",
    ),
    (
        re.compile(r'on:\s*\[?\s*pull_request_target\b', re.IGNORECASE),
        "nexus/l6/gha-pull-request-target",
        "Dangerous 'pull_request_target' Trigger",
        "pull_request_target runs with write permissions in the context of the base branch, enabling privilege escalation from forks.",
        NexusSeverity.HIGH, 0.88, 0.80, 8,
        "Use pull_request (not pull_request_target) unless you specifically need the elevated permissions and understand the risk.",
    ),
    (
        re.compile(r'cache:\s*true|actions/cache@', re.IGNORECASE),
        "nexus/l6/gha-cache-poisoning",
        "GitHub Actions Cache Usage — Review for Cache Poisoning",
        "Caches shared between branches/PRs can be poisoned by attacker-controlled PRs.",
        NexusSeverity.LOW, 0.60, 0.35, 5,
        "Use key patterns that include the branch name. Don't cache sensitive build artifacts.",
    ),
]

# ── Terraform patterns ─────────────────────────────────────────────────────────
_TERRAFORM_PATTERNS = [
    (
        re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', re.IGNORECASE),
        "nexus/l6/tf-open-ingress",
        "Terraform Security Group Open to the World (0.0.0.0/0)",
        "Allowing all inbound traffic from any IP exposes services to the internet.",
        NexusSeverity.HIGH, 0.97, 0.80, 8,
        "Restrict cidr_blocks to specific trusted IP ranges. Avoid 0.0.0.0/0.",
    ),
    (
        re.compile(r'encryption\s*=\s*false|encrypted\s*=\s*false', re.IGNORECASE),
        "nexus/l6/tf-storage-not-encrypted",
        "Terraform Storage Resource Not Encrypted",
        "Storage (S3, RDS, EBS) without encryption exposes data at rest.",
        NexusSeverity.HIGH, 0.93, 0.65, 7,
        "Set encrypted = true and specify kms_key_id for all storage resources.",
    ),
    (
        re.compile(r'publicly_accessible\s*=\s*true', re.IGNORECASE),
        "nexus/l6/tf-db-public",
        "Terraform Database Publicly Accessible",
        "RDS/database with publicly_accessible=true is reachable from the internet.",
        NexusSeverity.CRITICAL, 0.97, 0.85, 9,
        "Set publicly_accessible = false. Use VPC and private subnets for databases.",
    ),
    (
        re.compile(r'deletion_protection\s*=\s*false|force_destroy\s*=\s*true', re.IGNORECASE),
        "nexus/l6/tf-no-deletion-protection",
        "Terraform Resource Has No Deletion Protection",
        "Without deletion protection, misconfigured Terraform can permanently delete production data.",
        NexusSeverity.HIGH, 0.90, 0.70, 8,
        "Set deletion_protection = true for production databases and critical resources.",
    ),
    (
        re.compile(r'multi_az\s*=\s*false|backup_retention_period\s*=\s*0', re.IGNORECASE),
        "nexus/l6/tf-no-ha",
        "Terraform Database Without Multi-AZ or Backup",
        "Single-AZ and no backups means data loss in a zone failure or accidental deletion.",
        NexusSeverity.MEDIUM, 0.88, 0.50, 7,
        "Enable multi_az = true and set backup_retention_period >= 7 for production.",
    ),
    (
        re.compile(r'log_group_name\s*=|cloudwatch_log_group', re.IGNORECASE),
        "nexus/l6/tf-logging-good",
        "NOT USED", NexusSeverity.INFO, 0.0, 0.0, 0, "",
    ),
]


def run_layer6_iac(repo_path: str, file_map: Optional["RepoFileMap"] = None) -> list[NexusFinding]:
    """Run Layer 6: IaC and configuration blast-radius analysis.
    If file_map is provided, uses pre-loaded file data (no filesystem I/O).
    """
    findings: list[NexusFinding] = []

    def _process(content: str, rel: str, fname: str, ext: str, fpath: str) -> None:
        if fname == "Dockerfile" or fname.startswith("Dockerfile."):
            findings.extend(_run_patterns(content, rel, _DOCKERFILE_PATTERNS))
        elif fname in ("docker-compose.yml", "docker-compose.yaml") or \
                fname.startswith("docker-compose."):
            findings.extend(_run_patterns(content, rel, _COMPOSE_PATTERNS))
        elif ext in (".yaml", ".yml"):
            if any(k in content for k in ("apiVersion:", "kind: Pod", "kind: Deployment", "kind: Service")):
                findings.extend(_run_patterns(content, rel, _K8S_PATTERNS))
            if ".github/workflows" in fpath.replace("\\", "/") or "runs-on" in content:
                findings.extend(_run_patterns(content, rel, _GH_ACTIONS_PATTERNS))
        elif ext == ".tf" or fname.endswith(".tf"):
            findings.extend(_run_patterns(content, rel, _TERRAFORM_PATTERNS))

    if file_map is not None:
        for rel_path, fi in file_map.files.items():
            _process(fi.content, rel_path, fi.filename, fi.extension, fi.abs_path)
    else:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, repo_path)
                ext   = Path(fname).suffix.lower()
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except Exception:
                    continue
                _process(content, rel, fname, ext, fpath)

    log.info(f"[Layer 6] IaC blast-radius → {len(findings)} findings")
    return findings


def _run_patterns(content: str, rel_path: str, patterns: list) -> list[NexusFinding]:
    findings: list[NexusFinding] = []
    lines = content.splitlines()

    for entry in patterns:
        patt, rule_id, issue, desc, sev, conf, exploit, blast, fix = entry
        if conf == 0.0:  # Skip disabled entries
            continue
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*")):
                continue
            if patt.search(line):
                findings.append(NexusFinding(
                    layer=NexusLayer.IAC,
                    rule_id=rule_id, issue=issue, description=desc,
                    file=rel_path, line=lineno,
                    code_snippet=stripped[:200],
                    severity=sev, confidence=conf,
                    exploitability=exploit, blast_radius=blast,
                    suggested_fix=fix,
                ))
                break  # one per rule per file

    return findings
