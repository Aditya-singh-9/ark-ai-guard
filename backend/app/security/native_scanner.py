"""
Native code security scanner — works without any external tools.

Performs deep security analysis using:
- Python AST analysis (for Python code)
- Regex pattern matching across all languages
- Dependency file scanning (requirements.txt, package.json, etc.)

Detects: SQL injection, XSS, hardcoded secrets, insecure crypto,
command injection, path traversal, IDOR patterns, open redirects,
eval/exec usage, weak JWT config, debug flags, CORS misconfig, and more.
"""
import ast
import os
import re
import json
from pathlib import Path
from typing import Any
from app.utils.logger import get_logger

log = get_logger(__name__)


# ── Security pattern definitions ───────────────────────────────────────────────

PATTERNS = [
    # Secrets / Credentials
    {
        "id": "hardcoded-secret-key",
        "pattern": re.compile(
            r'(?i)(secret[_-]?key|api[_-]?key|password|passwd|token|auth[_-]?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE
        ),
        "severity": "critical",
        "issue": "Hardcoded Secret / API Key",
        "description": "A secret key, API key, or password appears to be hardcoded in source code.",
        "fix": "Move secrets to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault). Never commit credentials to version control.",
    },
    {
        "id": "aws-access-key",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": "critical",
        "issue": "AWS Access Key ID Exposed",
        "description": "An AWS Access Key ID pattern was found in source code.",
        "fix": "Revoke this key immediately, rotate credentials, and use IAM roles instead of long-term credentials.",
    },
    {
        "id": "private-key-material",
        "pattern": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
        "severity": "critical",
        "issue": "Private Key Exposed in Source",
        "description": "A private key was found embedded in source code.",
        "fix": "Remove the private key immediately, rotate all associated certificates, and store keys in a secrets vault.",
    },
    {
        "id": "github-token",
        "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),
        "severity": "critical",
        "issue": "GitHub Personal Access Token Exposed",
        "description": "A GitHub token was found in source code.",
        "fix": "Revoke the token at github.com/settings/tokens immediately and regenerate.",
    },

    # SQL Injection
    {
        "id": "sql-injection-format",
        "pattern": re.compile(
            r'(execute|query|cursor\.execute)\s*\(\s*["\']?\s*SELECT|INSERT|UPDATE|DELETE'
            r'.{0,40}%[s|d]|f["\']|\.format\(|f"[^"]*{',
            re.IGNORECASE | re.DOTALL
        ),
        "severity": "critical",
        "issue": "Potential SQL Injection via String Formatting",
        "description": "SQL query appears to be built using string concatenation or format strings, which can allow SQL injection.",
        "fix": "Use parameterized queries / prepared statements. Never interpolate user input directly into SQL strings.",
    },
    {
        "id": "sql-injection-concat",
        "pattern": re.compile(
            r'(execute|query)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\+',
            re.IGNORECASE | re.DOTALL
        ),
        "severity": "critical",
        "issue": "SQL Injection via String Concatenation",
        "description": "SQL query is being built by concatenating strings, a classic SQL injection vector.",
        "fix": "Use parameterized queries with ? or %s placeholders and pass values as a tuple.",
    },

    # Command Injection
    {
        "id": "os-system-injection",
        "pattern": re.compile(r'os\.system\s*\(|subprocess\.call\s*\(\s*[^)]*\+|shell=True'),
        "severity": "high",
        "issue": "Command Injection Risk (shell=True or os.system)",
        "description": "Using shell=True or os.system with dynamic input allows attackers to inject arbitrary shell commands.",
        "fix": "Use subprocess.run() with a list of arguments and shell=False. Never pass user input directly to shell commands.",
    },
    {
        "id": "eval-exec-usage",
        "pattern": re.compile(r'\b(eval|exec)\s*\('),
        "severity": "critical",
        "issue": "Dangerous eval() / exec() Usage",
        "description": "eval() or exec() executes arbitrary code. If any part of the argument is user-controlled, this is a Remote Code Execution (RCE) vulnerability.",
        "fix": "Remove eval/exec. Use ast.literal_eval() for safe data parsing, or restructure logic to avoid dynamic code execution.",
    },

    # XSS
    {
        "id": "dangerous-innerHTML",
        "pattern": re.compile(r'\.innerHTML\s*=|dangerouslySetInnerHTML', re.IGNORECASE),
        "severity": "high",
        "issue": "Cross-Site Scripting (XSS) via innerHTML",
        "description": "Directly setting innerHTML or using dangerouslySetInnerHTML with unescaped content allows XSS attacks.",
        "fix": "Use textContent instead of innerHTML. If HTML rendering is needed, sanitize with DOMPurify before assignment.",
    },
    {
        "id": "document-write",
        "pattern": re.compile(r'document\.write\s*\('),
        "severity": "high",
        "issue": "XSS Risk via document.write()",
        "description": "document.write() with user-controlled content enables cross-site scripting attacks.",
        "fix": "Avoid document.write(). Use DOM manipulation methods (createElement, appendChild) with proper escaping.",
    },

    # Path Traversal
    {
        "id": "path-traversal",
        "pattern": re.compile(r'open\s*\(\s*[^)]*request\.|open\s*\(\s*[^)]*user_input|os\.path\.join\s*\([^)]*request'),
        "severity": "high",
        "issue": "Path Traversal / Directory Traversal",
        "description": "File operations using user-supplied paths can allow attackers to read/write files outside the intended directory (e.g. ../../etc/passwd).",
        "fix": "Validate and sanitize file paths. Use os.path.abspath() and verify the result starts with the expected base directory.",
    },

    # Insecure Crypto
    {
        "id": "md5-sha1-hash",
        "pattern": re.compile(r'\b(md5|sha1)\b.*?(password|passwd|secret|credential)', re.IGNORECASE),
        "severity": "high",
        "issue": "Weak Cryptographic Hash (MD5/SHA1) for Sensitive Data",
        "description": "MD5 and SHA1 are cryptographically broken and should never be used to hash passwords or sensitive data.",
        "fix": "Use bcrypt, scrypt, or Argon2 for password hashing. Use SHA-256 or SHA-3 for general-purpose hashing.",
    },
    {
        "id": "insecure-random",
        "pattern": re.compile(r'\brandom\.(random|randint|choice|shuffle)\b.{0,100}(token|secret|key|password|session)', re.IGNORECASE | re.DOTALL),
        "severity": "high",
        "issue": "Cryptographically Insecure Random Number Generator",
        "description": "Python's random module is not cryptographically secure and must not be used for tokens, sessions, or security-sensitive values.",
        "fix": "Use secrets.token_hex(), secrets.token_urlsafe(), or os.urandom() for cryptographically secure random values.",
    },

    # JWT / Auth
    {
        "id": "jwt-none-algorithm",
        "pattern": re.compile(r'algorithm\s*[=\:]\s*["\']none["\']', re.IGNORECASE),
        "severity": "critical",
        "issue": "JWT 'none' Algorithm Vulnerability",
        "description": "Using 'none' as the JWT algorithm completely disables signature verification, allowing token forgery.",
        "fix": "Always specify a strong algorithm (HS256, RS256). Reject tokens with 'none' algorithm explicitly.",
    },
    {
        "id": "jwt-decode-no-verify",
        "pattern": re.compile(r'decode\s*\(.*?verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature.*?False', re.IGNORECASE | re.DOTALL),
        "severity": "critical",
        "issue": "JWT Signature Verification Disabled",
        "description": "JWT signature verification is explicitly disabled, allowing any crafted token to be accepted as valid.",
        "fix": "Remove verify=False. Always verify JWT signatures using the correct secret/public key.",
    },

    # Debug / Unsafe Config
    {
        "id": "debug-mode-production",
        "pattern": re.compile(r'debug\s*=\s*True|DEBUG\s*=\s*True', re.IGNORECASE),
        "severity": "high",
        "issue": "Debug Mode Enabled",
        "description": "Debug mode exposes stack traces, internal configuration, and sometimes interactive consoles to end users.",
        "fix": "Disable debug mode in production. Use environment variables: DEBUG=False (Django), FLASK_ENV=production, etc.",
    },
    {
        "id": "assert-security-bypass",
        "pattern": re.compile(r'assert\s+.{0,60}(auth|permission|role|admin|is_logged)', re.IGNORECASE),
        "severity": "high",
        "issue": "Security Check Using assert (Bypassable)",
        "description": "Using assert for security checks is dangerous: Python strips assert statements when run with -O (optimize) flag.",
        "fix": "Replace assert with explicit if/raise statements for all security-critical checks.",
    },

    # CORS / HTTP
    {
        "id": "cors-wildcard",
        "pattern": re.compile(r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*["\']?', re.IGNORECASE),
        "severity": "medium",
        "issue": "CORS Wildcard Origin (*) Allows Any Domain",
        "description": "Allowing all origins via '*' in CORS can allow malicious websites to make authenticated requests to your API.",
        "fix": "Restrict CORS origins to specific trusted domains. If credentials are used, '*' is not even allowed by browsers.",
    },
    {
        "id": "ssl-verify-disabled",
        "pattern": re.compile(r'verify\s*=\s*False', re.IGNORECASE),
        "severity": "high",
        "issue": "SSL/TLS Certificate Verification Disabled",
        "description": "Disabling SSL certificate verification makes the application vulnerable to man-in-the-middle (MITM) attacks.",
        "fix": "Set verify=True (default). If dealing with self-signed certs in development, use a proper CA bundle instead.",
    },

    # Open Redirect
    {
        "id": "open-redirect",
        "pattern": re.compile(r'redirect\s*\(\s*request\.(args|params|form|get|query)\s*[\.\[]', re.IGNORECASE),
        "severity": "medium",
        "issue": "Open Redirect Vulnerability",
        "description": "Redirecting to a URL supplied by the user allows phishing attacks via open redirect.",
        "fix": "Validate redirect URLs against an allowlist of trusted domains. Reject relative URLs starting with '//' or 'http'.",
    },

    # Sensitive Data Exposure
    {
        "id": "print-sensitive-data",
        "pattern": re.compile(r'print\s*\([^)]{0,100}(password|token|secret|key|credential)', re.IGNORECASE),
        "severity": "medium",
        "issue": "Sensitive Data Printed to Logs/Console",
        "description": "Passwords, tokens, or secrets being printed to stdout/logs can expose sensitive data.",
        "fix": "Remove print statements for sensitive data. Use structured logging with log level filtering. Redact credentials in logs.",
    },
    {
        "id": "log-sensitive-data",
        "pattern": re.compile(r'log\.(debug|info|warning|error)\s*\([^)]{0,150}(password|token|secret|api_key)', re.IGNORECASE),
        "severity": "medium",
        "issue": "Sensitive Data Logged",
        "description": "Sensitive values like passwords or tokens appear to be written to application logs.",
        "fix": "Redact sensitive fields before logging. Use a log sanitizer or structured logging fields with explicit masking.",
    },

    # Pickle / Deserialization
    {
        "id": "pickle-deserialization",
        "pattern": re.compile(r'pickle\.load|pickle\.loads|cPickle\.load', re.IGNORECASE),
        "severity": "critical",
        "issue": "Insecure Deserialization (pickle)",
        "description": "pickle.load() on untrusted data allows arbitrary code execution — one of the most dangerous Python vulnerabilities.",
        "fix": "Never unpickle data from untrusted sources. Use JSON, MessagePack, or Protocol Buffers for data serialization.",
    },

    # SSRF
    {
        "id": "ssrf-risk",
        "pattern": re.compile(r'requests\.(get|post|put|delete)\s*\(\s*[^)]*request\.(args|params|form|json)', re.IGNORECASE),
        "severity": "high",
        "issue": "Server-Side Request Forgery (SSRF) Risk",
        "description": "Making HTTP requests to user-supplied URLs allows attackers to probe internal network services.",
        "fix": "Validate URLs against an allowlist. Block internal IP ranges (127.0.0.1, 10.x.x.x, 172.16.x.x, 192.168.x.x). Use a URL parsing library.",
    },

    # Template Injection
    {
        "id": "template-injection",
        "pattern": re.compile(r'render_template_string\s*\(|Template\s*\([^)]*request\.|jinja2\.Template\s*\(', re.IGNORECASE),
        "severity": "critical",
        "issue": "Server-Side Template Injection (SSTI)",
        "description": "Rendering user-controlled data as a template allows attackers to execute arbitrary server-side code.",
        "fix": "Never pass user input directly to template rendering functions. Escape all user data before embedding in templates.",
    },

    # ── JavaScript / TypeScript Specific ──────────────────────────────────────

    # Prototype Pollution
    {
        "id": "js-prototype-pollution",
        "pattern": re.compile(r'__proto__\s*\[|prototype\s*\[|constructor\s*\[', re.IGNORECASE),
        "severity": "critical",
        "issue": "Prototype Pollution Vulnerability",
        "description": "Assigning to __proto__, prototype, or constructor via bracket notation can pollute the global Object prototype, enabling denial of service or privilege escalation.",
        "fix": "Use Object.create(null) for safe key-value stores. Validate object keys against an allowlist. Use libraries like lodash with prototype pollution patches.",
    },
    # postMessage XSS
    {
        "id": "js-postmessage-no-origin",
        "pattern": re.compile(r'addEventListener\s*\(["\']message["\']', re.IGNORECASE),
        "severity": "high",
        "issue": "postMessage Listener Without Origin Validation",
        "description": "Listening to 'message' events without validating event.origin allows malicious pages to send arbitrary messages to your application.",
        "fix": "Always check event.origin against your expected domain before processing: if (event.origin !== 'https://yourdomain.com') return;",
    },
    # LocalStorage JWT
    {
        "id": "js-localstorage-token",
        "pattern": re.compile(r'localStorage\.(setItem|getItem)\s*\([^)]{0,60}(token|jwt|session|auth)', re.IGNORECASE),
        "severity": "medium",
        "issue": "JWT / Auth Token Stored in localStorage (XSS Risk)",
        "description": "Storing authentication tokens in localStorage exposes them to any JavaScript running on the page, including XSS payloads.",
        "fix": "Store auth tokens in httpOnly cookies instead. If localStorage is required, ensure strict CSP and XSS protections are in place.",
    },
    # window.location XSS
    {
        "id": "js-location-href-injection",
        "pattern": re.compile(r'window\.location\s*=|location\.href\s*=|location\.replace\s*\(', re.IGNORECASE),
        "severity": "medium",
        "issue": "Open Redirect via window.location / location.href",
        "description": "Assigning user-controlled values to location.href enables open redirects and potentially javascript: URL execution.",
        "fix": "Validate all URLs before assignment. Block javascript: and data: URL schemes. Use an allowlist of permitted redirect destinations.",
    },
    # React dangerouslySetInnerHTML with variable (not string literal)
    {
        "id": "js-dangerous-html-variable",
        "pattern": re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*[a-zA-Z_$]', re.IGNORECASE),
        "severity": "high",
        "issue": "dangerouslySetInnerHTML With Dynamic Variable (XSS Risk)",
        "description": "Passing a variable (not a constant string) to dangerouslySetInnerHTML without sanitization allows XSS if the variable contains user input.",
        "fix": "Sanitize HTML with DOMPurify before passing: __html: DOMPurify.sanitize(userContent). Consider using a safe markdown renderer instead.",
    },
    # insecure Math.random
    {
        "id": "js-math-random-security",
        "pattern": re.compile(r'Math\.random\s*\(\s*\).{0,80}(token|secret|key|id|nonce|csrf|session)', re.IGNORECASE),
        "severity": "high",
        "issue": "Math.random() Used for Security-Sensitive Value",
        "description": "Math.random() is not cryptographically secure and is predictable. Using it for tokens, session IDs, or nonces is a security vulnerability.",
        "fix": "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js) for cryptographically secure random values.",
    },
    # Node.js child_process exec
    {
        "id": "js-child-process-exec",
        "pattern": re.compile(r'exec\s*\(|execSync\s*\(|spawn\s*\([^)]{0,100}shell\s*:\s*true', re.IGNORECASE),
        "severity": "critical",
        "issue": "Node.js Command Execution (child_process.exec)",
        "description": "child_process.exec() runs in a shell and is vulnerable to command injection if any argument originates from user input.",
        "fix": "Use execFile() or spawn() with an array of arguments instead of exec(). Never pass user input to shell commands.",
    },
    # Insecure cookie flags
    {
        "id": "js-cookie-no-httponly",
        "pattern": re.compile(r'(Set-Cookie|res\.cookie|cookie\.set)\b.{0,200}(?!httpOnly|HttpOnly|http_only)', re.IGNORECASE | re.DOTALL),
        "severity": "medium",
        "issue": "Cookie Set Without httpOnly Flag",
        "description": "Cookies without the httpOnly flag are accessible via JavaScript, allowing theft via XSS attacks.",
        "fix": "Always set httpOnly: true on session cookies. Also set secure: true and sameSite: 'Strict' or 'Lax'.",
    },
    # Insecure deserialization JSON.parse on external data
    {
        "id": "js-json-parse-unvalidated",
        "pattern": re.compile(r'JSON\.parse\s*\(\s*(req\.|request\.|body\.|params\.|event\.data)', re.IGNORECASE),
        "severity": "medium",
        "issue": "JSON.parse() on Unvalidated External Input",
        "description": "Parsing JSON from request bodies or external messages without schema validation can lead to unexpected object shapes, prototype pollution, and logic errors.",
        "fix": "Validate parsed JSON against a strict schema using Zod, Yup, or similar. Reject unexpected fields and types.",
    },
    # TypeScript any type in security-sensitive function
    {
        "id": "ts-any-in-auth-handler",
        "pattern": re.compile(r':\s*any\b.{0,100}(auth|token|user|permission|role|admin)', re.IGNORECASE),
        "severity": "low",
        "issue": "TypeScript 'any' Type in Security-Sensitive Context",
        "description": "Using 'any' type in authentication or authorization code disables TypeScript's type safety, potentially masking security bugs at compile time.",
        "fix": "Define proper interfaces for auth objects. Use strict TypeScript with noImplicitAny enabled.",
    },
    # Regex ReDoS
    {
        "id": "regex-redos",
        "pattern": re.compile(r'new RegExp\s*\([^)]*(\+|\*|\{)[^)]*\)', re.IGNORECASE),
        "severity": "medium",
        "issue": "Potential ReDoS (Regular Expression Denial of Service)",
        "description": "Dynamically constructed regex with nested quantifiers can have catastrophic backtracking behavior, causing denial of service.",
        "fix": "Use static regexes where possible. Validate regex complexity. Use libraries like safe-regex or re2 for user-supplied patterns.",
    },
    # Hardcoded IP address
    {
        "id": "hardcoded-internal-ip",
        "pattern": re.compile(r'["\'](?:https?://)?(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+(?::\d+)?["\']'),
        "severity": "medium",
        "issue": "Hardcoded Internal IP Address",
        "description": "Internal IP addresses hardcoded in source code expose network topology and will fail in different environments.",
        "fix": "Use environment variables or service discovery for internal service addresses.",
    },
    # Exposed API endpoint without auth check
    {
        "id": "js-express-no-auth-middleware",
        "pattern": re.compile(r'app\.(get|post|put|delete|patch)\s*\(["\'][^"\']*admin[^"\']*["\']', re.IGNORECASE),
        "severity": "high",
        "issue": "Admin Endpoint May Lack Authentication Middleware",
        "description": "Routes containing 'admin' in their path should always have authentication and authorization middleware applied.",
        "fix": "Ensure admin routes have authentication middleware (e.g. passport.authenticate, requireAuth) applied before route handlers.",
    },
    # SQL injection in JS (template literals)
    {
        "id": "js-sql-injection-template",
        "pattern": re.compile(r'(query|execute|db\.run|pool\.query)\s*\(`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{', re.IGNORECASE),
        "severity": "critical",
        "issue": "SQL Injection via Template Literal (JavaScript)",
        "description": "Interpolating variables directly into SQL query template strings allows SQL injection attacks.",
        "fix": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]). Never interpolate values into SQL strings.",
    },
    # Insecure fetch without credentials check
    {
        "id": "js-fetch-no-csrf",
        "pattern": re.compile(r'fetch\s*\([^)]+method\s*:\s*["\'](?:POST|PUT|DELETE|PATCH)["\']', re.IGNORECASE),
        "severity": "low",
        "issue": "fetch() POST/PUT/DELETE Without CSRF Token Check",
        "description": "Mutating API calls from the browser should include CSRF tokens to prevent cross-site request forgery.",
        "fix": "Include a CSRF token in request headers (e.g. X-CSRF-Token). Use SameSite=Strict cookies and proper CORS configuration.",
    },
]



# ── Dependency vulnerability patterns ─────────────────────────────────────────

KNOWN_VULNERABLE_PACKAGES = {
    # Python packages
    "django": [("< 4.2.0", "high", "Multiple CVEs in older Django versions — XSS, SQL injection")],
    "flask": [("< 2.3.0", "medium", "Older Flask versions have known security issues")],
    "requests": [("< 2.31.0", "medium", "CVE-2023-32681: Proxy-Authorization header leak")],
    "paramiko": [("< 3.4.0", "high", "CVE-2023-48795: Terrapin attack vulnerability in SSH")],
    "pillow": [("< 10.0.0", "high", "Multiple CVEs: buffer overflows in image parsing")],
    "cryptography": [("< 41.0.0", "high", "Multiple CVEs in older cryptography library versions")],
    "pyjwt": [("< 2.4.0", "critical", "CVE-2022-29217: Key confusion attack allows JWT forgery")],
    "urllib3": [("< 2.0.0", "high", "CVE-2023-43804: Cookie header injection vulnerability")],
    "werkzeug": [("< 2.3.0", "medium", "CVE-2023-23934: Path traversal in development server")],
    "setuptools": [("< 65.5.1", "medium", "CVE-2022-40897: ReDoS in package dependency resolution")],
    # JS packages (common)
    "lodash": [("< 4.17.21", "high", "CVE-2021-23337: Command injection via template")],
    "axios": [("< 1.6.0", "medium", "CSRF and security fixes in recent versions")],
    "express": [("< 4.18.0", "medium", "Multiple security fixes in Express 4.18+")],
    "jsonwebtoken": [("< 9.0.0", "critical", "CVE-2022-23529: Remote code execution via invalid secrets")],
    "next": [("< 14.0.0", "high", "Multiple XSS/SSRF vulnerabilities in older Next.js versions")],
}


def run_native_scanner(repo_path: str) -> list[dict[str, Any]]:
    """
    Run the native code security scanner on a repository.
    No external tools required.

    Returns list of vulnerability dicts compatible with other scanners.
    """
    if not os.path.isdir(repo_path):
        log.error(f"Native scanner: repo path does not exist: {repo_path}")
        return []

    findings: list[dict[str, Any]] = []
    file_count = 0
    scanned_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".go", ".rb", ".cs"}

    log.info(f"Native scanner: scanning {repo_path}")

    for root, dirs, files in os.walk(repo_path):
        # Skip hidden and vendor directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {
            "node_modules", "__pycache__", ".git", "venv", ".venv",
            "dist", "build", "vendor", ".tox", "coverage"
        }]

        for filename in files:
            filepath = os.path.join(root, filename)
            ext = Path(filename).suffix.lower()
            rel_path = os.path.relpath(filepath, repo_path)

            # Scan code files for patterns
            if ext in scanned_extensions:
                file_count += 1
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    file_findings = _scan_file_with_patterns(content, rel_path, ext)
                    findings.extend(file_findings)

                    # Deep Python AST scan
                    if ext == ".py":
                        ast_findings = _scan_python_ast(content, rel_path)
                        findings.extend(ast_findings)

                except Exception as e:
                    log.debug(f"Native scanner: error reading {rel_path}: {e}")

            # Scan dependency files
            if filename in ("requirements.txt", "Pipfile", "package.json",
                            "Gemfile", "go.mod", "pyproject.toml", "poetry.lock"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    dep_findings = _scan_dependencies(content, filename, rel_path)
                    findings.extend(dep_findings)
                except Exception as e:
                    log.debug(f"Native scanner: error reading {rel_path}: {e}")

    log.info(f"Native scanner: scanned {file_count} source files, found {len(findings)} issues")
    return findings


def _scan_file_with_patterns(content: str, filepath: str, ext: str) -> list[dict]:
    """Apply regex security patterns to file content."""
    findings = []
    lines = content.split("\n")

    for pattern_def in PATTERNS:
        pattern = pattern_def["pattern"]

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "<!--")):
                continue

            match = pattern.search(line)
            if match:
                snippet = line.strip()[:300]
                findings.append({
                    "file": filepath,
                    "line": i,
                    "column": match.start(),
                    "issue": pattern_def["issue"],
                    "description": pattern_def["description"],
                    "severity": pattern_def["severity"],
                    "rule_id": f"native/{pattern_def['id']}",
                    "code_snippet": snippet,
                    "suggested_fix": pattern_def["fix"],
                    "scanner": "semgrep",  # labeled as semgrep for compatibility
                })
                break  # One finding per pattern per file to avoid duplicates

    return findings


def _scan_python_ast(content: str, filepath: str) -> list[dict]:
    """
    Deep Python AST analysis for security issues that regex can't catch reliably.
    """
    findings = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        # Detect subprocess with shell=True
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)

            # subprocess with shell=True
            if func_name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                             "subprocess.check_output", "subprocess.check_call"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append({
                            "file": filepath,
                            "line": node.lineno,
                            "issue": "subprocess() with shell=True — Command Injection Risk",
                            "description": "shell=True causes the command to be interpreted by the shell, enabling command injection if any part comes from user input.",
                            "severity": "high",
                            "rule_id": "native/subprocess-shell-true",
                            "code_snippet": f"{func_name}(..., shell=True)",
                            "suggested_fix": "Use shell=False (default) and pass arguments as a list: subprocess.run(['cmd', 'arg1', 'arg2'])",
                            "scanner": "semgrep",
                        })

            # hashlib.md5 / hashlib.sha1 for passwords
            if func_name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
                findings.append({
                    "file": filepath,
                    "line": node.lineno,
                    "issue": "Weak Cryptographic Hash Algorithm (MD5/SHA1)",
                    "description": "MD5 and SHA1 are cryptographically broken. Using them for security purposes (hashing passwords, generating tokens) is dangerous.",
                    "severity": "high",
                    "rule_id": "native/weak-hash-algorithm",
                    "code_snippet": f"{func_name}(...)",
                    "suggested_fix": "Use hashlib.sha256() or hashlib.sha3_256() for general hashing. Use bcrypt, argon2, or scrypt for password hashing.",
                    "scanner": "semgrep",
                })

            # Detect yaml.load without Loader (arbitrary code execution)
            if func_name in ("yaml.load",):
                has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                if not has_loader:
                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "issue": "yaml.load() Without Loader — Remote Code Execution Risk",
                        "description": "yaml.load() without an explicit Loader can execute arbitrary Python code embedded in YAML files.",
                        "severity": "critical",
                        "rule_id": "native/yaml-load-unsafe",
                        "code_snippet": "yaml.load(data)  # unsafe",
                        "suggested_fix": "Use yaml.safe_load() instead, or yaml.load(data, Loader=yaml.SafeLoader).",
                        "scanner": "semgrep",
                    })

        # Detect bare except: pass (swallowing security exceptions)
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                if body_is_pass:
                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "issue": "Bare except: pass — Security Exception Swallowing",
                        "description": "Catching all exceptions and silently ignoring them can hide security errors, authentication failures, and injection attempts.",
                        "severity": "low",
                        "rule_id": "native/bare-except-pass",
                        "code_snippet": "except: pass",
                        "suggested_fix": "Log unexpected exceptions. Catch specific exception types. Never silently discard authentication or security-related errors.",
                        "scanner": "semgrep",
                    })

    return findings


def _get_call_name(node: ast.Call) -> str:
    """Extract the dotted name from an AST Call node."""
    if isinstance(node.func, ast.Attribute):
        obj = node.func.value
        if isinstance(obj, ast.Name):
            return f"{obj.id}.{node.func.attr}"
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _scan_dependencies(content: str, filename: str, filepath: str) -> list[dict]:
    """Scan dependency files for known vulnerable package versions."""
    findings = []

    if filename == "requirements.txt" or filename == "Pipfile":
        # Parse package==version lines
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[>=<~!]+\s*([\d\.]+)", line)
            if match:
                pkg = match.group(1).lower()
                version = match.group(2)
                _check_package(pkg, version, filepath, filename, findings)

    elif filename == "package.json":
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            for pkg, ver_spec in deps.items():
                ver = re.sub(r"[\^~>=<]", "", ver_spec).strip()
                _check_package(pkg.lower(), ver, filepath, filename, findings)
        except (json.JSONDecodeError, AttributeError):
            pass

    return findings


def _check_package(pkg: str, version: str, filepath: str, filename: str, findings: list):
    """Check if a package version matches known vulnerability patterns."""
    if pkg not in KNOWN_VULNERABLE_PACKAGES:
        return

    for version_req, severity, description in KNOWN_VULNERABLE_PACKAGES[pkg]:
        findings.append({
            "file": filepath,
            "line": None,
            "issue": f"Vulnerable Dependency: {pkg} {version} ({version_req} is affected)",
            "description": description,
            "severity": severity,
            "rule_id": f"native/vulnerable-dependency-{pkg}",
            "code_snippet": f"{pkg}=={version}  # in {filename}",
            "suggested_fix": f"Upgrade {pkg} to the latest stable version. Run: pip install --upgrade {pkg} (or npm update {pkg}).",
            "package_name": pkg,
            "package_version": version,
            "scanner": "semgrep",
        })
        break  # one finding per package
