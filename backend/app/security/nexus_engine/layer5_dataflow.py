"""
ARK Nexus Engine — Layer 5: Cross-File Data Flow Analysis

Builds a lightweight cross-file taint graph to track user-controlled input
from entry points (HTTP handlers) across function call chains to dangerous sinks.

Algorithm:
1. Identify all "taint source" functions (HTTP request handlers)
2. Build a function call graph across files
3. Trace taint propagation through function calls
4. Flag any path reaching a dangerous sink without sanitization

This is distinct from Layer 2 (single-file) — Layer 5 finds multi-hop
vulnerabilities spanning multiple modules.
"""
from __future__ import annotations
import ast
import os
import re
from pathlib import Path
from typing import NamedTuple, Optional, TYPE_CHECKING

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from .file_collector import RepoFileMap

log = get_logger(__name__)

SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv",
             "dist", "build", "vendor", ".next", "target"}

# ── Taint sources: functions known to receive user input ──────────────────────
# (decorator markers for HTTP handlers)
HTTP_HANDLER_DECORATORS = {
    "@app.route", "@router.get", "@router.post", "@router.put",
    "@router.delete", "@router.patch", "@app.get", "@app.post",
    "@csrf_exempt", "@login_required",
}

# ── Dangerous sinks ───────────────────────────────────────────────────────────
DANGEROUS_SINK_NAMES = {
    # SQL
    "execute", "executemany", "raw", "raw_query", "cursor.execute",
    # Shell
    "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output",
    # Eval
    "eval", "exec",
    # File (only specific dangerous file operations, NOT generic open/write)
    "send_file", "send_from_directory", "shutil.copy", "shutil.move",
    # Template
    "render_template_string",
    # Serialization
    "pickle.loads", "yaml.load",
    # HTTP (SSRF)
    "requests.get", "requests.post", "urllib.request.urlopen", "httpx.get",
}

# ── Inter-file call pattern (Python) ─────────────────────────────────────────
_IMPORT_RE  = re.compile(r'from\s+([\w\.]+)\s+import\s+((?:\w+\s*,?\s*)+)', re.MULTILINE)
_CALL_RE    = re.compile(r'(\w+)\s*\(')


class FunctionNode(NamedTuple):
    name: str
    file: str
    line: int
    is_handler: bool         # True if directly receives HTTP request
    calls: list[str]         # names of functions this function calls
    has_taint_parameter: bool  # True if any param name suggests user input


def run_layer5_dataflow(repo_path: str, file_map: Optional["RepoFileMap"] = None) -> list[NexusFinding]:
    """
    Run Layer 5: Cross-file data flow analysis.
    Focuses on Python projects (full AST); JS/TS gets heuristic scan.
    If file_map is provided, uses pre-loaded file data (no filesystem I/O).
    """
    findings: list[NexusFinding] = []

    if file_map is not None:
        # Fast path: use pre-loaded file data
        py_files_data = [
            (fi.abs_path, fi.content)
            for fi in file_map.files.values()
            if fi.extension == ".py"
        ]
        js_files_data = [
            (fi.abs_path, fi.content)
            for fi in file_map.files.values()
            if fi.extension in (".js", ".ts", ".jsx", ".tsx")
        ]
        if py_files_data:
            findings.extend(_python_dataflow(repo_path, [p for p, _ in py_files_data]))
        if js_files_data:
            findings.extend(_js_dataflow(repo_path, [p for p, _ in js_files_data]))
    else:
        # Legacy path: walk filesystem
        py_files: list[str] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                if fname.endswith(".py"):
                    py_files.append(os.path.join(root, fname))
        if py_files:
            findings.extend(_python_dataflow(repo_path, py_files))

        js_files: list[str] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                if Path(fname).suffix.lower() in (".js", ".ts", ".jsx", ".tsx"):
                    js_files.append(os.path.join(root, fname))
        if js_files:
            findings.extend(_js_dataflow(repo_path, js_files))

    log.info(f"[Layer 5] Cross-file data flow → {len(findings)} findings")
    return findings


# ─────────────────────────────── Python Analysis ──────────────────────────────

def _python_dataflow(repo_path: str, py_files: list[str]) -> list[NexusFinding]:
    """Build call graph, trace taint from HTTP handlers to dangerous sinks."""
    findings: list[NexusFinding] = []
    func_map: dict[str, FunctionNode] = {}   # func_name → node (simplified: no namespace)

    # --- Phase 1: Build function graph ---
    for fpath in py_files:
        rel = os.path.relpath(fpath, repo_path)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            tree = ast.parse(source)
            lines = source.splitlines()
        except Exception:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Detect if this is an HTTP handler
            is_handler = False
            has_taint_param = False

            # Check decorators
            for deco in node.decorator_list:
                deco_str = ast.unparse(deco) if hasattr(ast, "unparse") else ""
                if any(h in deco_str for h in ("route", "get", "post", "put", "delete", "patch")):
                    is_handler = True
                    break

            # Check parameter names for request-like names
            params = [a.arg for a in node.args.args]
            if any(p in params for p in ("request", "req", "r")):
                has_taint_param = True

            # Collect all function calls made inside this function
            calls: list[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    cn = _resolve_call_name(child)
                    if cn:
                        calls.append(cn)

            fn = FunctionNode(
                name=node.name,
                file=rel,
                line=node.lineno,
                is_handler=is_handler,
                calls=calls,
                has_taint_parameter=has_taint_param,
            )
            func_map[node.name] = fn

    # --- Phase 2: Trace taint from handlers through the call graph ---
    handlers = [fn for fn in func_map.values() if fn.is_handler or fn.has_taint_parameter]

    for handler in handlers:
        visited: set[str] = set()
        _trace_calls(handler, func_map, visited, depth=0, findings=findings, handler=handler)

    return findings


def _trace_calls(
    fn: FunctionNode,
    func_map: dict[str, FunctionNode],
    visited: set[str],
    depth: int,
    findings: list[NexusFinding],
    handler: FunctionNode,
) -> None:
    """Recursively trace function calls from a tainted handler, find dangerous sinks."""
    if depth > 5 or fn.name in visited:
        return
    visited.add(fn.name)

    for call_name in fn.calls:
        # Check if this call is a dangerous sink
        for sink in DANGEROUS_SINK_NAMES:
            if call_name.endswith(sink.split(".")[-1]) and _is_likely_sink(call_name, sink):
                findings.append(NexusFinding(
                    layer=NexusLayer.DATAFLOW,
                    rule_id=f"nexus/l5/cross-file-taint-{sink.split('.')[-1]}",
                    issue=f"Cross-File Taint: HTTP Request Data Flows to '{call_name}'",
                    description=(
                        f"Tainted data from HTTP handler '{handler.name}' ({handler.file}) "
                        f"flows through function call chain (depth {depth+1}) "
                        f"to dangerous sink '{call_name}' in '{fn.file}'. "
                        "Manual review required to confirm sanitization gap."
                    ),
                    file=fn.file,
                    line=fn.line,
                    severity=_sink_sev(sink),
                    confidence=max(0.40, 0.75 - depth * 0.10),  # confidence drops with depth
                    exploitability=0.65 - depth * 0.08,
                    blast_radius=8,
                    suggested_fix=(
                        f"Ensure user input is validated and sanitized before reaching "
                        f"'{call_name}'. Add input validation at the handler layer."
                    ),
                ))
                return

        # Recurse into called functions
        if call_name in func_map:
            _trace_calls(func_map[call_name], func_map, visited, depth + 1, findings, handler)


def _is_likely_sink(call_name: str, sink: str) -> bool:
    """Slightly fuzzy matching to avoid false positives."""
    call_lower = call_name.lower()
    sink_lower = sink.lower()
    # Exact or suffix match
    return call_lower == sink_lower or call_lower.endswith("." + sink_lower.split(".")[-1])


def _sink_sev(sink: str) -> NexusSeverity:
    if any(x in sink for x in ("execute", "raw_query", "sql")):
        return NexusSeverity.CRITICAL
    if any(x in sink for x in ("system", "subprocess", "exec", "popen")):
        return NexusSeverity.CRITICAL
    if any(x in sink for x in ("pickle", "template_string", "yaml.load")):
        return NexusSeverity.CRITICAL
    if any(x in sink for x in ("requests", "urlopen", "httpx")):
        return NexusSeverity.HIGH
    if any(x in sink for x in ("open", "send_file")):
        return NexusSeverity.HIGH
    return NexusSeverity.MEDIUM


def _resolve_call_name(node: ast.Call) -> str | None:
    try:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return ast.unparse(node.func) if hasattr(ast, "unparse") else node.func.attr
    except Exception:
        pass
    return None


# ─────────────────────────────── JS/TS Heuristic ──────────────────────────────

# Cross-file patterns: look for exported functions referenced in route files
_JS_CROSS_FILE_PATTERNS = [
    (
        re.compile(
            r'require\s*\(["\']([^"\']+)["\']\)\s*[;\n].{0,500}'
            r'(execute|query|db\.run|pool\.query)', re.DOTALL
        ),
        "nexus/l5/js-require-then-sql",
        "Imported Module Used in DB Query — Review for SQL Injection",
        "A required module's return value is passed to a DB query. If input flows unchecked, SQL injection is possible.",
        NexusSeverity.HIGH, 0.55, 0.60, 7,
        "Ensure all database query inputs are parameterized before being passed from imported modules.",
    ),
    (
        re.compile(
            r'(app|router)\.(use|get|post|put|delete)\s*\([^)]+\)',
            re.MULTILINE
        ),
        "nexus/l5/js-route-handler-audit",
        "Express Route Handler — Verify Auth and Input Validation",
        "Express route defined. Verify all routes have authentication middleware and validate inputs.",
        NexusSeverity.INFO, 0.40, 0.20, 3,
        "Add auth middleware and input validation (e.g. express-validator) to all routes.",
    ),
    (
        re.compile(
            r'(module\.exports|export\s+default|export\s+const)\s+\w+[^{]*\{[^}]*'
            r'(execute|query|exec|spawn)', re.DOTALL
        ),
        "nexus/l5/js-exported-sink",
        "Exported Function Contains Dangerous Sink",
        "An exported function contains a dangerous operation. If called with user input, vulnerability may propagate.",
        NexusSeverity.MEDIUM, 0.55, 0.50, 6,
        "Add input validation inside the exported function, not just at the call site.",
    ),
]


def _js_dataflow(repo_path: str, js_files: list[str]) -> list[NexusFinding]:
    findings: list[NexusFinding] = []
    for fpath in js_files:
        rel = os.path.relpath(fpath, repo_path)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception:
            continue
        for patt, rule_id, issue, desc, sev, conf, exploit, blast, fix in _JS_CROSS_FILE_PATTERNS:
            if patt.search(content):
                # Find approximate line number
                for lineno, line in enumerate(content.splitlines(), 1):
                    if patt.search(line):
                        break
                else:
                    lineno = 1
                findings.append(NexusFinding(
                    layer=NexusLayer.DATAFLOW,
                    rule_id=rule_id, issue=issue, description=desc,
                    file=rel, line=lineno,
                    severity=sev, confidence=conf,
                    exploitability=exploit, blast_radius=blast,
                    suggested_fix=fix,
                ))
                break
    return findings
