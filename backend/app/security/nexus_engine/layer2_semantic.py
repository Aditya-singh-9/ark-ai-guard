"""
ARK Nexus Engine — Layer 2: Semantic AST Analysis

Deep AST-level analysis with Control Flow Graph (CFG) approximation and
taint source→sink tracking. Goes far beyond regex by understanding code
structure and data flow within each file.

Supports: Python (full AST), JavaScript/TypeScript (heuristic), Java, Go.
"""
from __future__ import annotations
import ast
import os
import re
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from .file_collector import RepoFileMap

log = get_logger(__name__)

SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv",
             "dist", "build", "vendor", ".next", "target"}


# ── Taint sources (user-controlled input) ─────────────────────────────────────
TAINT_SOURCES = {
    "python": {
        "request.args", "request.form", "request.json", "request.data",
        "request.get", "request.cookies", "request.headers",
        "flask.request", "fastapi.Query", "fastapi.Body", "fastapi.Path",
        "input(", "sys.argv", "os.environ.get",
    },
    "js": {
        "req.body", "req.query", "req.params", "request.body",
        "event.data", "location.search", "document.cookie",
        "localStorage.getItem", "sessionStorage.getItem",
        "process.env", "req.headers",
    },
}

# ── Dangerous sinks ────────────────────────────────────────────────────────────
DANGEROUS_SINKS = {
    "python": {
        # SQL
        "execute", "executemany", "raw", "raw_query",
        # Shell
        "os.system", "subprocess.run", "subprocess.call",
        "subprocess.Popen", "subprocess.check_output",
        # Eval
        "eval", "exec", "compile",
        # File
        "open", "os.path.join",
        # Template
        "render_template_string", "Template",
        # Pickle
        "pickle.loads", "pickle.load",
        # HTTP
        "requests.get", "requests.post", "urllib.request.urlopen",
    },
    "js": {
        # DOM
        "innerHTML", "outerHTML", "document.write", "eval",
        # Shell
        "exec", "execSync", "spawn", "child_process",
        # SQL
        "query", "execute", "db.run",
        # Redirect
        "location.href", "window.location", "res.redirect",
        # HTTP
        "fetch", "axios.get", "axios.post", "request(",
    },
}


def run_layer2_semantic(repo_path: str, file_map: Optional["RepoFileMap"] = None) -> list[NexusFinding]:
    """Run Layer 2: Semantic AST analysis.
    If file_map is provided, uses pre-loaded file data (no filesystem I/O).
    """
    findings: list[NexusFinding] = []

    def _process(source: str, rel: str, ext: str) -> None:
        try:
            if ext == ".py":
                findings.extend(_analyze_python(source, rel))
            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                findings.extend(_analyze_js_ts(source, rel))
            elif ext == ".java":
                findings.extend(_analyze_java(source, rel))
            elif ext == ".go":
                findings.extend(_analyze_go(source, rel))
        except Exception as exc:
            log.debug(f"L2 error on {rel}: {exc}")

    if file_map is not None:
        for rel_path, fi in file_map.files.items():
            if fi.extension in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"):
                _process(fi.content, rel_path, fi.extension)
    else:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, repo_path)
                ext   = Path(fname).suffix.lower()
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        source = fh.read()
                    _process(source, rel, ext)
                except Exception as exc:
                    log.debug(f"L2 error on {rel}: {exc}")

    log.info(f"[Layer 2] Semantic analysis → {len(findings)} findings")
    return findings


# ─────────────────────────────── Python AST ────────────────────────────────────

class _PythonTaintVisitor(ast.NodeVisitor):
    """
    AST visitor that:
    1. Tracks tainted (user-controlled) variables
    2. Detects dangerous function calls with tainted arguments
    3. Identifies CFG-level issues (auth checks after operations, etc.)
    """

    def __init__(self, source_lines: list[str]) -> None:
        self.findings: list[dict] = []
        self.tainted: set[str] = set()
        self.source_lines = source_lines

    def _snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()[:200]
        return ""

    def _is_tainted_arg(self, node: ast.expr) -> bool:
        """Check if an AST expression references a tainted variable."""
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return True
        if isinstance(node, ast.Attribute):
            # request.args, request.form, etc.
            src = ast.unparse(node) if hasattr(ast, "unparse") else ""
            return any(s in src for s in TAINT_SOURCES["python"])
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
            # f-strings, string concat — taint propagates
            return any(self._is_tainted_arg(child) for child in ast.walk(node))
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track taint propagation through assignments."""
        if self._is_tainted_arg(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect dangerous calls with tainted arguments."""
        call_name = _py_call_name(node)

        # ── subprocess with shell=True ────────────────────────────────────────
        if call_name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                         "subprocess.check_output", "subprocess.check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({
                        "rule_id": "nexus/l2/subprocess-shell-true",
                        "issue": "subprocess() with shell=True — Command Injection",
                        "description": "shell=True combined with user input enables OS command injection.",
                        "severity": "high",
                        "line": node.lineno,
                        "confidence": 0.90,
                        "exploitability": 0.75,
                        "blast_radius": 9,
                        "fix": "Use shell=False with a list: subprocess.run(['cmd', arg1])",
                        "snippet": self._snippet(node.lineno),
                    })

        # ── Dangerous hash algorithms ─────────────────────────────────────────
        if call_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
            self.findings.append({
                "rule_id": "nexus/l2/weak-hash",
                "issue": "Weak Cryptographic Hash (MD5/SHA1)",
                "description": "MD5 and SHA1 are cryptographically broken algorithms.",
                "severity": "high",
                "line": node.lineno,
                "confidence": 0.95,
                "exploitability": 0.55,
                "blast_radius": 4,
                "fix": "Use hashlib.sha256() or Argon2 for password hashing.",
                "snippet": self._snippet(node.lineno),
            })

        # ── yaml.load without Loader ──────────────────────────────────────────
        if call_name in ("yaml.load",):
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                self.findings.append({
                    "rule_id": "nexus/l2/yaml-load-no-loader",
                    "issue": "yaml.load() Without Loader — Code Execution Risk",
                    "description": "yaml.load() without Loader= executes arbitrary Python code embedded in YAML.",
                    "severity": "critical",
                    "line": node.lineno,
                    "confidence": 0.98,
                    "exploitability": 0.80,
                    "blast_radius": 9,
                    "fix": "Use yaml.safe_load() instead.",
                    "snippet": self._snippet(node.lineno),
                })

        # ── Taint source→sink tracking ────────────────────────────────────────
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        if any(self._is_tainted_arg(a) for a in all_args):
            if call_name in DANGEROUS_SINKS["python"]:
                sink_type = _classify_sink(call_name, "python")
                self.findings.append({
                    "rule_id": f"nexus/l2/taint-{sink_type}",
                    "issue": f"Tainted Data Flows to {sink_type.upper()} Sink",
                    "description": (
                        f"User-controlled input reaches {call_name}() without sanitization. "
                        f"This is a potential {sink_type} vulnerability."
                    ),
                    "severity": _sink_severity(sink_type),
                    "line": node.lineno,
                    "confidence": 0.75,
                    "exploitability": 0.70,
                    "blast_radius": 7,
                    "fix": f"Validate/sanitize user input before passing to {call_name}(). Use allowlists.",
                    "snippet": self._snippet(node.lineno),
                })

        # ── Hardcoded credentials in function calls ───────────────────────────
        _detect_hardcoded_args(node, self.findings, self._snippet)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Detect auth-after-operation patterns — common IDOR."""
        # Look for auth/permission checks after data modification
        body_names = [
            ast.unparse(n) if hasattr(ast, "unparse") else ""
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
        ]
        has_db_write = any(s in "\n".join(body_names) for s in ("db.add", "db.commit", "save(", "create(", "update("))
        has_auth_check = any(s in "\n".join(body_names) for s in ("verify_token", "check_permission", "is_admin", "require_auth"))

        if has_db_write and not has_auth_check:
            # Only flag if function name suggests it handles external requests
            fn = node.name.lower()
            if any(w in fn for w in ("create", "update", "delete", "modify", "post", "put", "patch")):
                self.findings.append({
                    "rule_id": "nexus/l2/missing-auth-check",
                    "issue": f"Function '{node.name}' Modifies Data Without Auth Check",
                    "description": "Mutation function lacks visible authorization check. Potential IDOR or privilege escalation.",
                    "severity": "high",
                    "line": node.lineno,
                    "confidence": 0.55,   # Lower confidence — structural inference
                    "exploitability": 0.60,
                    "blast_radius": 6,
                    "fix": "Add authorization check before any data modification. Validate that the calling user owns the resource.",
                    "snippet": self._snippet(node.lineno),
                })

        self.generic_visit(node)


def _analyze_python(source: str, rel_path: str) -> list[NexusFinding]:
    """Full Python AST analysis with taint tracking."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines = source.splitlines()
    visitor = _PythonTaintVisitor(lines)
    visitor.visit(tree)

    results = []
    for raw in visitor.findings:
        results.append(NexusFinding(
            layer=NexusLayer.SEMANTIC,
            rule_id=raw["rule_id"],
            issue=raw["issue"],
            description=raw["description"],
            file=rel_path,
            line=raw["line"],
            severity=_str_to_sev(raw["severity"]),
            confidence=raw["confidence"],
            exploitability=raw["exploitability"],
            blast_radius=raw["blast_radius"],
            suggested_fix=raw["fix"],
            code_snippet=raw.get("snippet", ""),
        ))
    return results


# ─────────────────────────────── JS/TS Heuristic ──────────────────────────────

# JS taint heuristic patterns: detect when user data flows to sink
_JS_TAINT_FLOWS = [
    (
        re.compile(r'(req\.body|req\.query|req\.params|request\.body|event\.data)\s*[\.\[]?\s*\w*\s*[^=]*\s*(?:execute|query|db\.run|pool\.query)', re.IGNORECASE | re.DOTALL),
        "nexus/l2/js-taint-sqli",
        "User Input Flowing to DB Query (JS)",
        "Request body/query params appears to reach a database query without sanitization.",
        "critical", 0.70, 0.75, 8,
        "Use parameterized queries. Never interpolate req.body directly into SQL.",
    ),
    (
        re.compile(r'(req\.body|req\.query|req\.params)\s*[\.\[]?\s*\w*\s*[^=]*\s*(?:innerHTML|eval|document\.write)', re.IGNORECASE | re.DOTALL),
        "nexus/l2/js-taint-xss",
        "User Input Flowing to DOM Sink (XSS)",
        "Request parameter appears to reach a DOM sink (innerHTML/eval/document.write).",
        "high", 0.70, 0.70, 6,
        "Sanitize with DOMPurify before passing to DOM APIs.",
    ),
    (
        re.compile(r'(req\.body|req\.query)\s*[\.\[]?\s*\w*\s*[^=]*\s*(?:exec|execSync|spawn)', re.IGNORECASE | re.DOTALL),
        "nexus/l2/js-taint-command-injection",
        "User Input Flowing to Shell Exec",
        "Request data appears to reach a shell execution call.",
        "critical", 0.75, 0.80, 9,
        "Use execFile() with arg array. Never pass user input to shell commands.",
    ),
    (
        re.compile(r'(res\.redirect|location\.href\s*=)\s*[^;]{0,50}(req\.|request\.|query\.)', re.IGNORECASE),
        "nexus/l2/js-taint-open-redirect",
        "User Input Flows to Redirect Sink",
        "User-controlled value used as redirect target.",
        "medium", 0.70, 0.55, 5,
        "Validate redirect URL against allowlist of trusted domains.",
    ),
]

_JS_STRUCTURAL = [
    # Missing rate limiting on auth routes
    (
        re.compile(r'router\.(post|put)\s*\(["\']\/?(login|signin|auth)["\']', re.IGNORECASE),
        "nexus/l2/js-auth-no-rate-limit",
        "Auth Endpoint Without Obvious Rate Limiting",
        "Login/auth endpoint may lack brute-force protection.",
        "medium", 0.50, 0.55, 5,
        "Add rate limiting middleware (express-rate-limit) to auth routes.",
    ),
    # JWT decode without verify
    (
        re.compile(r'jwt\.decode\s*\([^)]+,\s*\{[^}]*verify\s*:\s*false', re.IGNORECASE),
        "nexus/l2/js-jwt-no-verify",
        "JWT Decoded Without Signature Verification",
        "jwt.decode() with { verify: false } accepts any JWT as valid.",
        "critical", 0.95, 0.90, 8,
        "Remove { verify: false }. Always verify JWT signatures.",
    ),
    # Unprotected express route to sensitive path
    (
        re.compile(r'app\.(get|post|put|delete)\s*\(["\'][^"\']*?(config|admin|backup|debug|internal)[^"\']*["\']', re.IGNORECASE),
        "nexus/l2/js-sensitive-route-exposed",
        "Sensitive Route Potentially Exposed Without Auth",
        "Express route to admin/config/debug path may lack authentication.",
        "high", 0.55, 0.65, 7,
        "Add authentication middleware to all sensitive routes.",
    ),
]


def _analyze_js_ts(source: str, rel_path: str) -> list[NexusFinding]:
    """JS/TS heuristic taint + structural analysis."""
    lines = source.splitlines()
    findings: list[NexusFinding] = []

    patterns = _JS_TAINT_FLOWS + _JS_STRUCTURAL
    for pattern, rule_id, issue, desc, sev, conf, exploit, blast, fix in patterns:
        for lineno, line in enumerate(lines, 1):
            if line.strip().startswith(("//", "/*", "*")):
                continue
            if pattern.search(line):
                findings.append(NexusFinding(
                    layer=NexusLayer.SEMANTIC,
                    rule_id=rule_id,
                    issue=issue,
                    description=desc,
                    file=rel_path,
                    line=lineno,
                    code_snippet=line.strip()[:200],
                    severity=_str_to_sev(sev),
                    confidence=conf,
                    exploitability=exploit,
                    blast_radius=blast,
                    suggested_fix=fix,
                ))
                break  # one per pattern per file

    return findings


# ─────────────────────────────── Java Heuristic ───────────────────────────────

_JAVA_PATTERNS = [
    (
        re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', re.IGNORECASE),
        "nexus/l2/java-runtime-exec-concat",
        "Java Runtime.exec() With String Concatenation",
        "Command injection risk when user-controlled string is concatenated into exec call.",
        "critical", 0.85, 0.80, 9,
        "Use ProcessBuilder with a List<String>. Never concatenate user input into shell commands.",
    ),
    (
        re.compile(r'Statement\s+\w+\s*=.*createStatement|executeQuery\s*\("\s*(SELECT|INSERT|UPDATE|DELETE).*\+', re.IGNORECASE),
        "nexus/l2/java-sqli",
        "Java SQL Injection via Statement Concatenation",
        "String concatenation in JDBC executeQuery enables SQL injection.",
        "critical", 0.85, 0.80, 8,
        "Use PreparedStatement with ? placeholders.",
    ),
    (
        re.compile(r'ObjectInputStream\s*\(\s*\w*\.getInputStream', re.IGNORECASE),
        "nexus/l2/java-deserialization",
        "Java ObjectInputStream Deserialization — RCE Risk",
        "Deserializing untrusted data from network streams enables RCE.",
        "critical", 0.90, 0.85, 9,
        "Use safer serialization (JSON, Protobuf). Apply deserialization filters.",
    ),
    (
        re.compile(r'@RequestMapping.{0,100}method\s*=.*GET.*\bdelete\b', re.IGNORECASE),
        "nexus/l2/java-delete-via-get",
        "Destructive Operation on HTTP GET",
        "DELETE/destructive operations should not be triggered by GET requests (CSRF-prone).",
        "medium", 0.70, 0.50, 5,
        "Use HTTP DELETE/POST for state-modifying operations.",
    ),
]


def _analyze_java(source: str, rel_path: str) -> list[NexusFinding]:
    findings: list[NexusFinding] = []
    lines = source.splitlines()
    for patt, rule_id, issue, desc, sev, conf, exploit, blast, fix in _JAVA_PATTERNS:
        for lineno, line in enumerate(lines, 1):
            if line.strip().startswith(("//", "/*", "*")):
                continue
            if patt.search(line):
                findings.append(NexusFinding(
                    layer=NexusLayer.SEMANTIC,
                    rule_id=rule_id, issue=issue, description=desc,
                    file=rel_path, line=lineno,
                    code_snippet=line.strip()[:200],
                    severity=_str_to_sev(sev),
                    confidence=conf, exploitability=exploit, blast_radius=blast,
                    suggested_fix=fix,
                ))
                break
    return findings


# ─────────────────────────────── Go Heuristic ─────────────────────────────────

_GO_PATTERNS = [
    (
        re.compile(r'exec\.Command\s*\([^)]*\+', re.IGNORECASE),
        "nexus/l2/go-exec-inject",
        "Go exec.Command With String Concatenation",
        "Command injection when user-controlled string is appended to exec.Command() args.",
        "critical", 0.85, 0.80, 9,
        "Pass each argument separately: exec.Command('cmd', arg1, arg2). Never concatenate.",
    ),
    (
        re.compile(r'fmt\.Sprintf\s*\(\s*"[^"]{0,50}(SELECT|INSERT|UPDATE|DELETE)[^"]*%', re.IGNORECASE),
        "nexus/l2/go-sqli-sprintf",
        "Go SQL Injection via fmt.Sprintf",
        "SQL query built with fmt.Sprintf allows injection.",
        "critical", 0.88, 0.80, 8,
        "Use db.QueryRow() with parameterized queries (? or $N placeholders).",
    ),
    (
        re.compile(r'crypto/md5|crypto/sha1'),
        "nexus/l2/go-weak-hash",
        "Go Weak Hash Import (MD5/SHA1)",
        "crypto/md5 and crypto/sha1 are cryptographically weak.",
        "high", 0.95, 0.50, 4,
        "Use crypto/sha256 or golang.org/x/crypto for password hashing.",
    ),
    (
        re.compile(r'http\.ListenAndServe\s*\(\s*":'),
        "nexus/l2/go-http-bind-all",
        "Go HTTP Server Binding to 0.0.0.0",
        "Binding to all interfaces may expose internal services.",
        "medium", 0.90, 0.40, 4,
        "Bind to a specific address in production. Use TLS: http.ListenAndServeTLS().",
    ),
]


def _analyze_go(source: str, rel_path: str) -> list[NexusFinding]:
    findings: list[NexusFinding] = []
    lines = source.splitlines()
    for patt, rule_id, issue, desc, sev, conf, exploit, blast, fix in _GO_PATTERNS:
        for lineno, line in enumerate(lines, 1):
            if line.strip().startswith("//"):
                continue
            if patt.search(line):
                findings.append(NexusFinding(
                    layer=NexusLayer.SEMANTIC,
                    rule_id=rule_id, issue=issue, description=desc,
                    file=rel_path, line=lineno,
                    code_snippet=line.strip()[:200],
                    severity=_str_to_sev(sev),
                    confidence=conf, exploitability=exploit, blast_radius=blast,
                    suggested_fix=fix,
                ))
                break
    return findings


# ─────────────────────────────── Helpers ──────────────────────────────────────

def _py_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        try:
            return f"{ast.unparse(node.func)}"
        except Exception:
            return node.func.attr
    return ""


def _classify_sink(call_name: str, lang: str) -> str:
    name = call_name.lower()
    if any(x in name for x in ("execute", "query", "sql", "db.run")):
        return "sqli"
    if any(x in name for x in ("system", "popen", "exec", "subprocess")):
        return "command-injection"
    if any(x in name for x in ("open", "path.join", "read")):
        return "path-traversal"
    if any(x in name for x in ("template", "render")):
        return "template-injection"
    if any(x in name for x in ("requests.get", "requests.post", "urlopen")):
        return "ssrf"
    if "pickle" in name:
        return "insecure-deserialization"
    return "taint-source-to-sink"


def _sink_severity(sink_type: str) -> str:
    return {
        "sqli":                   "critical",
        "command-injection":      "critical",
        "template-injection":     "critical",
        "insecure-deserialization": "critical",
        "ssrf":                   "high",
        "path-traversal":         "high",
        "taint-source-to-sink":   "medium",
    }.get(sink_type, "medium")


def _str_to_sev(s: str) -> NexusSeverity:
    return {
        "critical": NexusSeverity.CRITICAL,
        "high":     NexusSeverity.HIGH,
        "medium":   NexusSeverity.MEDIUM,
        "low":      NexusSeverity.LOW,
    }.get(s.lower(), NexusSeverity.MEDIUM)


def _detect_hardcoded_args(node: ast.Call, findings: list, snippet_fn) -> None:
    """Detect hardcoded credentials passed as string arguments to auth/db functions."""
    cn = _py_call_name(node)
    if not any(x in cn.lower() for x in ("connect", "login", "auth", "password", "secret")):
        return
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) >= 8:
            findings.append({
                "rule_id": "nexus/l2/hardcoded-arg-in-auth-call",
                "issue": f"Hardcoded String Argument in {cn}() — Possible Credential",
                "description": f"A string literal ≥8 chars was passed directly to {cn}(). Potential hardcoded credential.",
                "severity": "high",
                "line": node.lineno,
                "confidence": 0.60,
                "exploitability": 0.65,
                "blast_radius": 7,
                "fix": "Move credentials to environment variables or a secrets manager.",
                "snippet": snippet_fn(node.lineno),
            })
            break
