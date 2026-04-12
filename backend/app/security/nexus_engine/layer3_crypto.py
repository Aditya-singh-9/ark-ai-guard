"""
ARK Nexus Engine — Layer 3: Cryptographic Audit

Uses information-theoretic entropy analysis (Shannon entropy) to detect hidden
secrets in arbitrary strings — beyond simple regex patterns. Also audits:
- Weak cipher usage (ECB, DES, RC2, RC4)
- Timing oracle patterns (non-constant-time comparisons)
- Hardcoded IVs / nonces
- Weak key derivation (PBKDF2 with low iterations)
- Insecure TLS configuration
"""
from __future__ import annotations
import math
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
             "dist", "build", "vendor", ".next", "target"}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
                   ".rb", ".cs", ".php", ".env", ".yml", ".yaml", ".json",
                   ".conf", ".cfg", ".ini", ".toml"}

# Strings that look like entropy but are probably not secrets
ENTROPY_FALSE_POSITIVE_PREFIXES = (
    "sha256:", "sha512:", "base64:", "data:", "http://", "https://",
    "$argon2", "$2b$", "$scrypt$", "sha256sum", "md5sum",
)

ENTROPY_EXCEPTIONS = {
    # Common non-secret patterns
    "aaaaaaaaaaaaaaaa", "0000000000000000", "1111111111111111",
    "################################", "================",
    "00000000-0000-0000-0000-000000000000",
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# High-entropy string detection: look for long strings with >3.5 bits/char
_HIGH_ENTROPY_RE = re.compile(
    r'["\']([A-Za-z0-9+/=_\-]{20,})["\']'
)

# Threshold: base64-like strings have ~6 bits/char, random hex has ~4 bits/char
ENTROPY_THRESHOLD_B64  = 5.0   # base64 string with secret
ENTROPY_THRESHOLD_HEX  = 3.7   # hex string with secret
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/=]+$')

# Crypto-specific patterns
_CRYPTO_PATTERNS = [
    # ECB mode
    (
        re.compile(r'MODE_ECB|\.ECB\b|"ECB"|\'ECB\'', re.IGNORECASE),
        "nexus/l3/ecb-mode",
        "ECB Mode Encryption — Pattern Leakage",
        "ECB mode encrypts each block independently, revealing data patterns.",
        NexusSeverity.HIGH, 0.95, 0.70, 5,
        "Use AES-GCM or AES-CBC with a cryptographically random IV.",
    ),
    # DES/3DES
    (
        re.compile(r'\b(DES|TripleDES|3DES)\b', re.IGNORECASE),
        "nexus/l3/des-3des",
        "DES/3DES Cipher — Deprecated and Weak",
        "DES is broken (56-bit key). 3DES vulnerable to Sweet32 attack (CVE-2016-2183).",
        NexusSeverity.HIGH, 0.95, 0.60, 5,
        "Replace with AES-256-GCM.",
    ),
    # RC4
    (
        re.compile(r'\bRC4\b|\bARC4\b|\barcfour\b', re.IGNORECASE),
        "nexus/l3/rc4",
        "RC4 Stream Cipher — Broken",
        "RC4 has multiple cryptographic weaknesses. Banned in TLS 1.3.",
        NexusSeverity.CRITICAL, 0.98, 0.65, 5,
        "Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    # RC2
    (
        re.compile(r'\bRC2\b', re.IGNORECASE),
        "nexus/l3/rc2",
        "RC2 Cipher — Deprecated",
        "RC2 is obsolete and weak. Do not use.",
        NexusSeverity.HIGH, 0.95, 0.55, 4,
        "Replace with AES-256-GCM.",
    ),
    # Hardcoded IV (all zeros or constant)
    (
        re.compile(r'iv\s*=\s*(b["\']\\x00{8,}["\']|\[\s*0\s*(,\s*0\s*){7,}\]|"0{16,}")', re.IGNORECASE),
        "nexus/l3/hardcoded-iv",
        "Hardcoded IV / Nonce — Encryption Oracle Risk",
        "Using a fixed IV for CBC/CTR mode allows ciphertext comparison attacks.",
        NexusSeverity.HIGH, 0.90, 0.65, 6,
        "Generate IV with os.urandom(16) for each encryption operation.",
    ),
    # Non-constant-time comparison (timing oracle)
    (
        re.compile(r'if\s+\w+\s*==\s*\w+.*?(token|hmac|signature|hash|secret|mac)', re.IGNORECASE),
        "nexus/l3/timing-oracle",
        "Non-Constant-Time Comparison — Timing Oracle Risk",
        "Using == for HMAC/token comparison leaks secret via timing side-channel.",
        NexusSeverity.HIGH, 0.70, 0.55, 6,
        "Use hmac.compare_digest() (Python) or crypto.timingSafeEqual() (Node.js).",
    ),
    # Weak PBKDF2 iterations
    (
        re.compile(r'pbkdf2[_-]?hmac\s*\([^)]*,\s*(\d+)\s*\)', re.IGNORECASE),
        "nexus/l3/pbkdf2-low-iterations",
        "PBKDF2 With Potentially Low Iteration Count",
        "PBKDF2 below 100,000 iterations is too fast for offline attacks.",
        NexusSeverity.MEDIUM, 0.70, 0.45, 4,
        "Use at least 600,000 iterations (OWASP 2023). Prefer Argon2id.",
    ),
    # SSLv3/TLS 1.0 forced
    (
        re.compile(r'SSLv3|TLSv1\.0|ssl\.PROTOCOL_TLSv1\b|TLS_1_0', re.IGNORECASE),
        "nexus/l3/tls-old-version",
        "Outdated TLS Version (SSLv3 / TLS 1.0)",
        "TLS 1.0 and SSLv3 have known attacks (POODLE, BEAST). Deprecated by PCI DSS.",
        NexusSeverity.HIGH, 0.95, 0.60, 7,
        "Use TLS 1.2 minimum; prefer TLS 1.3.",
    ),
    # Null cipher
    (
        re.compile(r'TLS_NULL_WITH_NULL_NULL|SSL_NULL_WITH_NULL_NULL', re.IGNORECASE),
        "nexus/l3/null-cipher",
        "NULL Cipher Suite — No Encryption",
        "NULL cipher provides authentication but zero encryption.",
        NexusSeverity.CRITICAL, 0.98, 0.80, 8,
        "Remove NULL cipher suites from TLS configuration.",
    ),
    # Weak RSA key size in code
    (
        re.compile(r'generate_private_key\s*\([^)]*\b(512|1024)\b', re.IGNORECASE),
        "nexus/l3/rsa-weak-key",
        "RSA Key Generation with Weak Size (< 2048 bits)",
        "RSA keys of 512 or 1024 bits can be factored with modern hardware.",
        NexusSeverity.HIGH, 0.95, 0.65, 6,
        "Use RSA-2048 minimum. Prefer RSA-4096 or ECDSA P-256.",
    ),
    # Seeded random for crypto
    (
        re.compile(r'random\.seed\s*\(|srand\s*\('),
        "nexus/l3/seeded-random-crypto",
        "Seeded PRNG — Predictable if Seed Is Known",
        "random.seed() with predictable seed makes all generated values predictable.",
        NexusSeverity.HIGH, 0.80, 0.60, 5,
        "Use secrets.token_bytes() or os.urandom() for crypto purposes.",
    ),
    # Entropy sources
    (
        re.compile(r'/dev/urandom', re.IGNORECASE),
        "nexus/l3/dev-urandom-direct",
        "Direct /dev/urandom Access (Review Required)",
        "Direct reads from /dev/urandom are OK for most uses but review context.",
        NexusSeverity.INFO, 0.50, 0.10, 1,
        "Prefer language-level CSPRNG APIs (os.urandom(), secrets, crypto.randomBytes()).",
    ),
    # JWT secret too short
    (
        re.compile(r'jwt\.sign\s*\([^)]+,\s*["\'][^"\']{1,15}["\']', re.IGNORECASE),
        "nexus/l3/jwt-weak-secret",
        "JWT Signed With Short Secret (< 16 chars)",
        "Short JWT secrets are vulnerable to offline dictionary/brute-force attacks.",
        NexusSeverity.HIGH, 0.85, 0.70, 7,
        "Use a CSPRNG-generated secret of at least 256 bits (32 bytes).",
    ),
    # Insecure cipher without authentication
    (
        re.compile(r'MODE_CBC|MODE_CTR|MODE_CFB', re.IGNORECASE),
        "nexus/l3/unauthenticated-cipher",
        "Unauthenticated Cipher Mode (CBC/CTR/CFB)",
        "CBC/CTR/CFB without MAC allows bit-flipping attacks. Use authenticated encryption.",
        NexusSeverity.MEDIUM, 0.75, 0.55, 5,
        "Use AES-GCM which provides both encryption and authentication (AEAD).",
    ),
]


def run_layer3_crypto(repo_path: str, file_map: Optional["RepoFileMap"] = None) -> list[NexusFinding]:
    """Run Layer 3: Cryptographic audit + entropy analysis.
    If file_map is provided, uses pre-loaded file data (no filesystem I/O).
    """
    findings: list[NexusFinding] = []

    def _process(content: str, rel: str) -> None:
        findings.extend(_scan_crypto_patterns(content, rel))
        findings.extend(_scan_entropy(content, rel))

    if file_map is not None:
        for rel_path, fi in file_map.files.items():
            if fi.extension in CODE_EXTENSIONS:
                try:
                    _process(fi.content, rel_path)
                except Exception as exc:
                    log.debug(f"L3 error on {rel_path}: {exc}")
    else:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in CODE_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, repo_path)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    _process(content, rel)
                except Exception as exc:
                    log.debug(f"L3 error on {rel}: {exc}")

    log.info(f"[Layer 3] Crypto audit → {len(findings)} findings")
    return findings


def _scan_crypto_patterns(content: str, rel_path: str) -> list[NexusFinding]:
    """Apply crypto-specific pattern library."""
    findings: list[NexusFinding] = []
    lines = content.splitlines()
    seen_rules: set[str] = set()

    for patt, rule_id, issue, desc, sev, conf, exploit, blast, fix in _CRYPTO_PATTERNS:
        if rule_id in seen_rules:
            continue
        for lineno, line in enumerate(lines, 1):
            if line.strip().startswith(("#", "//", "/*", "*")):
                continue
            m = patt.search(line)
            if m:
                seen_rules.add(rule_id)
                # Special case: PBKDF2 — check actual iteration count
                if "pbkdf2" in rule_id:
                    try:
                        iters = int(m.group(1))
                        if iters >= 100_000:
                            break  # Sufficient iterations — skip
                        sev = NexusSeverity.HIGH if iters < 10_000 else NexusSeverity.MEDIUM
                    except (IndexError, ValueError):
                        pass

                findings.append(NexusFinding(
                    layer=NexusLayer.CRYPTO,
                    rule_id=rule_id, issue=issue, description=desc,
                    file=rel_path, line=lineno,
                    code_snippet=line.strip()[:200],
                    severity=sev if isinstance(sev, NexusSeverity) else NexusSeverity.MEDIUM,
                    confidence=conf, exploitability=exploit, blast_radius=blast,
                    suggested_fix=fix,
                ))
                break
    return findings


def _scan_entropy(content: str, rel_path: str) -> list[NexusFinding]:
    """
    Shannon entropy scan: detect high-entropy strings likely to be secrets.

    Uses the heuristic: a base64-encoded secret has ~6 bits/char entropy,
    while English text has ~4 bits/char. Strings with >5.0 bits/char and
    length > 20 chars are flagged as potential secrets.
    """
    findings: list[NexusFinding] = []
    lines = content.splitlines()
    seen_lines: set[int] = set()

    for lineno, line in enumerate(lines, 1):
        if lineno in seen_lines:
            continue
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue
        # Skip comment-heavy files
        if any(x in stripped.lower() for x in ("example", "placeholder", "your-secret", "<your", "xxx")):
            continue

        for m in _HIGH_ENTROPY_RE.finditer(line):
            candidate = m.group(1)

            # Skip known FP prefixes
            if any(candidate.startswith(p) for p in ENTROPY_FALSE_POSITIVE_PREFIXES):
                continue
            if candidate.lower() in ENTROPY_EXCEPTIONS:
                continue
            # Skip URL-like strings
            if "/" in candidate and candidate.count("/") > 2:
                continue

            entropy = shannon_entropy(candidate)
            is_hex  = bool(_HEX_RE.match(candidate))
            is_b64  = bool(_B64_RE.match(candidate))

            threshold = ENTROPY_THRESHOLD_HEX if is_hex else ENTROPY_THRESHOLD_B64
            if entropy < threshold:
                continue

            # Confidence scales with entropy — truly random strings are at ~6.0
            confidence = min(0.92, (entropy - threshold) / (6.5 - threshold) * 0.85 + 0.40)

            # Only flag if there's an assignment context (key = "...", secret: "...")
            context_re = re.compile(
                r'(?i)(key|secret|token|password|credential|api|auth|jwt|hmac|seed|salt|nonce|private)',
                re.IGNORECASE
            )
            has_context = bool(context_re.search(line[:m.start()]))

            if not has_context:
                continue  # Skip out-of-context high-entropy strings

            seen_lines.add(lineno)
            findings.append(NexusFinding(
                layer=NexusLayer.CRYPTO,
                rule_id="nexus/l3/high-entropy-secret",
                issue="High-Entropy String — Potential Hardcoded Secret",
                description=(
                    f"String of length {len(candidate)} with Shannon entropy "
                    f"{entropy:.2f} bits/char detected near secret-context keyword. "
                    "Likely a hardcoded credential or key.",
                ),
                file=rel_path,
                line=lineno,
                code_snippet=stripped[:200],
                severity=NexusSeverity.HIGH,
                confidence=round(confidence, 2),
                exploitability=0.70,
                blast_radius=7,
                suggested_fix="Move this value to an environment variable or secrets manager.",
            ))
            break  # One entropy finding per line

    return findings
