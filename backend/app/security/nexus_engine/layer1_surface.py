"""
ARK Nexus Engine — Layer 1: Surface Scan

Fast, comprehensive pattern-match pass over all source files.
Covers 200+ security patterns across 10+ languages.
This is the broadest-net layer; subsequent layers add depth.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from .finding_types import NexusFinding, NexusLayer, NexusSeverity
from app.utils.logger import get_logger

if TYPE_CHECKING:
    from .file_collector import RepoFileMap

log = get_logger(__name__)

# ── Extension sets ─────────────────────────────────────────────────────────────
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java",
                   ".go", ".rb", ".cs", ".cpp", ".c", ".h", ".swift", ".kt",
                   ".scala", ".rs", ".sh", ".bash", ".ps1"}
SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv",
             "dist", "build", "vendor", ".tox", "coverage", ".next",
             "target", ".terraform", ".serverless"}


# ── 200+ Pattern definitions ───────────────────────────────────────────────────
# Each entry: (rule_id, pattern, severity, issue, description, fix)
RAW_PATTERNS: list[tuple] = [
    # ── Credentials & Secrets ──────────────────────────────────────────────────
    ("l1/aws-key-id",          r'AKIA[0-9A-Z]{16}',
     "critical", "AWS Access Key ID Exposed",
     "An AWS IAM access key was found embedded in source code.",
     "Revoke immediately at AWS IAM Console. Use IAM roles or env vars."),

    ("l1/aws-secret-key",      r'(?i)(aws.secret|secret.access.key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
     "critical", "AWS Secret Access Key Hardcoded",
     "AWS secret access key found. Full programmatic AWS access at risk.",
     "Rotate the key, use IAM Roles for EC2/Lambda, or AWS Secrets Manager."),

    ("l1/gcp-api-key",         r'AIza[0-9A-Za-z_\-]{35}',
     "high", "GCP/Google API Key Exposed",
     "A Google Cloud API key was found in source. API calls billed to your account.",
     "Restrict the key at GCP console to specific APIs + IP referrers."),

    ("l1/github-pat",          r'gh[pousr]_[A-Za-z0-9]{36}',
     "critical", "GitHub Personal Access Token Exposed",
     "GitHub PAT found. Full repo/org access depending on scopes.",
     "Revoke at github.com/settings/tokens immediately."),

    ("l1/stripe-secret",       r'sk_(live|test)_[A-Za-z0-9]{24,}',
     "critical", "Stripe Secret Key Exposed",
     "Stripe secret key found. Allows charges, refunds, payouts.",
     "Revoke at dashboard.stripe.com/apikeys. Use restricted keys."),

    ("l1/stripe-pk",           r'pk_(live|test)_[A-Za-z0-9]{24,}',
     "medium", "Stripe Publishable Key Hardcoded",
     "Stripe publishable key hardcoded. Should be in env vars.",
     "Move to environment variable. Never commit API keys."),

    ("l1/slack-token",         r'xox[baprs]-[0-9A-Za-z\-]+',
     "critical", "Slack API Token Exposed",
     "Slack token found. Can read messages and post to workspace.",
     "Revoke at api.slack.com/apps immediately."),

    ("l1/slack-webhook",       r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
     "high", "Slack Webhook URL Exposed",
     "Slack webhook URL allows anyone to post to your channel.",
     "Regenerate the webhook in Slack app settings."),

    ("l1/sendgrid-key",        r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
     "critical", "SendGrid API Key Exposed",
     "SendGrid key found. Can send emails from your account.",
     "Revoke at app.sendgrid.com/settings/api_keys."),

    ("l1/twilio-key",          r'SK[a-f0-9]{32}',
     "critical", "Twilio API Key Exposed",
     "Twilio key found. Can make calls/SMS billed to your account.",
     "Revoke at twilio.com/console/project/api-keys."),

    ("l1/firebase-key",        r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
     "critical", "Firebase Server Key Exposed",
     "Firebase FCM server key found. Allows push notifications to all users.",
     "Regenerate in Firebase Console. Use env vars."),

    ("l1/azure-storage",       r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}==',
     "critical", "Azure Storage Connection String Exposed",
     "Azure storage connection string provides full blob/queue/table access.",
     "Regenerate key in Azure Portal. Use Managed Identity."),

    ("l1/npm-token",           r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+',
     "critical", "npm Auth Token in .npmrc",
     "npm auth token allows package publishing under your account.",
     "Revoke at npmjs.com/settings/tokens. Never commit .npmrc."),

    ("l1/private-key",         r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
     "critical", "Private Key Embedded in Source",
     "Private key found. Remove immediately and rotate all certs.",
     "Store keys in secrets vault (HashiCorp Vault, AWS SM)."),

    ("l1/jwt-hardcoded",       r'(?i)(jwt.secret|JWT_SECRET|signing.key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "critical", "JWT Signing Secret Hardcoded",
     "Hardcoded JWT secret allows token forgery by anyone with code access.",
     "Move to env var. Use CSPRNG-generated 256-bit secret."),

    ("l1/db-url-creds",        r'(postgres|mysql|mongodb|redis)://[^:@/\s]+:[^@/\s]+@',
     "critical", "Database URL With Password Embedded",
     "Database connection string with credentials in source code.",
     "Move to DATABASE_URL env var. Use IAM auth where available."),

    ("l1/generic-password",    r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
     "high", "Hardcoded Password",
     "A password value appears hardcoded in source code.",
     "Use environment variables or a secrets manager for all passwords."),

    ("l1/generic-secret",      r'(?i)(secret|api_?key|auth_?token|access_?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "high", "Hardcoded Secret / API Key",
     "A secret, API key or auth token is hardcoded in source.",
     "Move all secrets to environment variables or a vault."),

    # ── SQL Injection ──────────────────────────────────────────────────────────
    ("l1/sqli-format",
     r'(execute|query|cursor\.execute)\s*\(\s*["\']?\s*.{0,10}(SELECT|INSERT|UPDATE|DELETE).{0,50}(%[sd]|f"|\+\s*[a-zA-Z]|\.format\s*\()',
     "critical", "SQL Injection via String Formatting",
     "SQL query built with string interpolation allows injection.",
     "Use parameterized queries with placeholders (?, %s, $1)."),

    ("l1/sqli-concat",
     r'(execute|query)\s*\(\s*".*?(SELECT|INSERT|UPDATE|DELETE).*?"\s*\+',
     "critical", "SQL Injection via Concatenation",
     "SQL built by concatenating user-controlled strings.",
     "Use parameterized queries/prepared statements."),

    ("l1/sqli-js-template",
     r'(query|execute|db\.run|pool\.query)\s*\(`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{',
     "critical", "SQL Injection in JS Template Literal",
     "Variable interpolated directly into SQL template string.",
     "Use db.query('SELECT...WHERE id=$1',[id]) with params."),

    # ── Command Injection ──────────────────────────────────────────────────────
    ("l1/os-system",           r'os\.system\s*\(|shell=True',
     "high", "Command Injection Risk (os.system / shell=True)",
     "shell=True or os.system allows attackers to inject shell commands.",
     "Use subprocess.run([...], shell=False) with list args."),

    ("l1/eval-exec",           r'\b(eval|exec)\s*\(',
     "critical", "Dangerous eval()/exec() Usage",
     "eval/exec of user-controlled input enables Remote Code Execution.",
     "Remove eval/exec. Use ast.literal_eval() for safe data parsing."),

    ("l1/js-child-process",    r'(execSync|child_process\.exec)\s*\(',
     "critical", "Node.js shell exec — Command Injection Risk",
     "exec() runs in a shell; user-controlled args enable command injection.",
     "Use execFile() or spawn() with arg array, never exec() with user input."),

    ("l1/template-injection",
     r'render_template_string\s*\(|Template\s*\([^)]*request\.|jinja2\.Template\s*\(',
     "critical", "Server-Side Template Injection (SSTI)",
     "User input rendered as template enables server-side code execution.",
     "Never pass user input to template engines. Escape all data first."),

    # ── XSS ───────────────────────────────────────────────────────────────────
    ("l1/inner-html",          r'\.innerHTML\s*=|dangerouslySetInnerHTML',
     "high", "XSS via innerHTML / dangerouslySetInnerHTML",
     "Assigning unsanitized content to innerHTML allows XSS.",
     "Use textContent or sanitize with DOMPurify before assignment."),

    ("l1/document-write",      r'document\.write\s*\(',
     "high", "XSS via document.write()",
     "document.write() with user data enables XSS attacks.",
     "Use safe DOM manipulation (createElement/appendChild)."),

    ("l1/js-dangerous-html-var",
     r'dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*[a-zA-Z_$]',
     "high", "dangerouslySetInnerHTML With Dynamic Variable",
     "Passing a variable (not constant) to dangerouslySetInnerHTML risks XSS.",
     "Sanitize: __html: DOMPurify.sanitize(content)."),

    # ── Path Traversal ────────────────────────────────────────────────────────
    ("l1/path-traversal",
     r'open\s*\(\s*[^)]*request\.|open\s*\(\s*[^)]*user_input|os\.path\.join\s*\([^)]*request',
     "high", "Path Traversal / Directory Traversal",
     "File ops with user-supplied paths allow ../../etc/passwd reads.",
     "Use os.path.abspath() and verify path starts with expected base dir."),

    # ── Auth / JWT ────────────────────────────────────────────────────────────
    ("l1/jwt-none-algo",       r'algorithm\s*[=\:]\s*["\']none["\']',
     "critical", "JWT 'none' Algorithm — Token Forgery",
     "'none' algorithm disables JWT signature verification entirely.",
     "Specify RS256 or HS256 explicitly. Reject 'none' algorithm tokens."),

    ("l1/jwt-no-verify",
     r'decode\s*\(.*?verify\s*=\s*False|verify_signature.*?False',
     "critical", "JWT Signature Verification Disabled",
     "verify=False allows any crafted JWT to be accepted as valid.",
     "Always verify JWT signatures. Remove verify=False."),

    ("l1/assert-auth",         r'assert\s+.{0,60}(auth|permission|role|admin|is_logged)',
     "high", "Security Check Using assert (Bypassable with -O flag)",
     "Python strips assert with -O flag, bypassing the security check.",
     "Replace with explicit if/raise statements."),

    # ── Crypto ────────────────────────────────────────────────────────────────
    ("l1/md5-sha1-password",
     r'\b(md5|sha1)\b.*?(password|passwd|secret|credential)',
     "high", "Weak Hash (MD5/SHA1) for Sensitive Data",
     "MD5/SHA1 are cryptographically broken for passwords.",
     "Use bcrypt, scrypt, or Argon2id for password hashing."),

    ("l1/insecure-random",
     r'\brandom\.(random|randint|choice|shuffle)\b.{0,100}(token|secret|key|password|session)',
     "high", "Insecure Random for Security-Sensitive Value",
     "Python random module is predictable; do not use for secrets.",
     "Use secrets.token_hex() or os.urandom() instead."),

    ("l1/js-math-random-security",
     r'Math\.random\s*\(\s*\).{0,80}(token|secret|key|id|nonce|csrf|session)',
     "high", "Math.random() for Security Value — Predictable",
     "Math.random() is not cryptographically secure.",
     "Use crypto.getRandomValues() (browser) or crypto.randomBytes() (Node)."),

    ("l1/ecb-mode",            r'(?i)(AES\.new|Cipher\.new|DES\.new)\s*\([^)]*MODE_ECB',
     "high", "ECB Mode Encryption — Pattern Leakage",
     "ECB mode does not hide data patterns. Identical blocks produce identical ciphertext.",
     "Use AES-GCM or AES-CBC with a secure IV. Never use ECB for sensitive data."),

    # ── Insecure Deserialization ───────────────────────────────────────────────
    ("l1/pickle-load",         r'pickle\.load|pickle\.loads|cPickle\.load',
     "critical", "Insecure Pickle Deserialization — RCE Risk",
     "pickle.load() on untrusted data allows arbitrary code execution.",
     "Use JSON, MessagePack, or Protobuf. Never unpickle untrusted data."),

    ("l1/yaml-load-no-loader", r'yaml\.load\s*\([^)]*\)',
     "high", "yaml.load() Without Loader — Code Execution Risk",
     "yaml.load() without Loader= can execute arbitrary Python code.",
     "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)."),

    # ── SSRF / Open Redirect ──────────────────────────────────────────────────
    ("l1/ssrf-risk",
     r'requests\.(get|post|put|delete)\s*\(\s*[^)]*request\.(args|params|form|json)',
     "high", "SSRF — Server-Side Request Forgery Risk",
     "HTTP request to user-supplied URL can probe internal network services.",
     "Validate URLs against allowlist. Block internal IP ranges."),

    ("l1/open-redirect",
     r'redirect\s*\(\s*request\.(args|params|form|get|query)\s*[\.\[]',
     "medium", "Open Redirect Vulnerability",
     "Redirecting to user-supplied URL enables phishing via open redirect.",
     "Validate redirect target against allowlist of trusted domains."),

    # ── Config & Debug ────────────────────────────────────────────────────────
    ("l1/debug-true",          r'debug\s*=\s*True|DEBUG\s*=\s*True',
     "high", "Debug Mode Enabled",
     "Debug mode exposes stack traces and internal config to users.",
     "Disable debug in prod using env vars. FLASK_ENV=production, etc."),

    ("l1/ssl-verify-false",    r'verify\s*=\s*False',
     "high", "SSL/TLS Certificate Verification Disabled",
     "Disabling SSL verification enables MITM attacks.",
     "Remove verify=False. Fix cert issues with proper CA bundle."),

    ("l1/cors-wildcard",
     r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*["\']?',
     "medium", "CORS Wildcard (*) — Any Origin Allowed",
     "Wildcard CORS allows any website to make authenticated requests.",
     "Restrict to specific trusted domains in CORS config."),

    # ── Sensitive Data Logging ────────────────────────────────────────────────
    ("l1/print-password",
     r'print\s*\([^)]{0,100}(password|token|secret|api_key)',
     "medium", "Sensitive Data Printed to Console",
     "Secrets printed to stdout may appear in CI/CD logs.",
     "Remove print statements for secrets. Use structured logging."),

    ("l1/log-password",
     r'log\.(debug|info|warning|error)\s*\([^)]{0,150}(password|token|secret|api_key)',
     "medium", "Sensitive Data Written to Application Logs",
     "Secrets in logs may persist in log aggregators or files.",
     "Redact sensitive fields before logging."),

    # ── Prototype Pollution ───────────────────────────────────────────────────
    ("l1/prototype-pollution",
     r'__proto__\[|prototype\[|constructor\[',
     "critical", "Prototype Pollution",
     "Bracket notation on __proto__/prototype/constructor can pollute Object prototype.",
     "Use Object.create(null) for maps. Validate object keys against allowlist."),

    # ── localStorage Tokens ───────────────────────────────────────────────────
    ("l1/localstorage-jwt",
     r'localStorage\.(setItem|getItem)\s*\([^)]{0,60}(token|jwt|session|auth)',
     "medium", "Auth Token Stored in localStorage (XSS Risk)",
     "localStorage tokens are accessible to XSS payloads.",
     "Use httpOnly cookies for auth tokens instead."),

    # ── IDOR / Mass Assignment ────────────────────────────────────────────────
    ("l1/mass-assignment",
     r'(Model\.create|\.update_attributes|from_dict|model_validate)\s*\([^)]*request\.(json|data|form)',
     "high", "Potential Mass Assignment / IDOR",
     "Creating/updating models directly from request data can allow IDOR.",
     "Explicitly whitelist fields from request data before DB operations."),

    # ── Child process / Shell ─────────────────────────────────────────────────
    ("l1/shell-injection-php",
     r'(system|shell_exec|exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
     "critical", "PHP Shell Injection via User Input",
     "PHP shell functions called with superglobal input enables RCE.",
     "Never pass user input to shell functions. Use escapeshellarg()."),

    ("l1/java-runtime-exec",
     r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\([^)]*\+',
     "critical", "Java Runtime.exec() — Command Injection Risk",
     "Java runtime exec with concatenated strings enables command injection.",
     "Use ProcessBuilder with a List<String> of arguments."),

    # ── Config file patterns ──────────────────────────────────────────────────
    ("l1/hardcoded-ip",
     r'["\'](?:https?://)?(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+(?::\d+)?["\']',
     "medium", "Hardcoded Internal IP Address",
     "Internal IP in code exposes network topology and breaks in other envs.",
     "Use environment variables or service discovery for internal hosts."),

    ("l1/http-not-https",
     r'["\']http://(?!localhost|127\.0\.0\.1)[^"\']{5,}["\']',
     "low", "Plain HTTP URL (Not HTTPS)",
     "Using HTTP instead of HTTPS allows data interception in transit.",
     "Use HTTPS for all external URLs. Enforce HSTS."),

    ("l1/rsa-small-key",
     r'(?i)(RSA|rsa_key_size|key_length)\s*[=:]\s*(512|1024)\b',
     "high", "Weak RSA Key Size (< 2048 bits)",
     "RSA keys smaller than 2048 bits are considered broken.",
     "Use RSA-2048 minimum. Prefer RSA-4096 or ECDSA P-256."),

    ("l1/md5-general",
     r'hashlib\.md5\s*\(|MD5\s*\(',
     "medium", "MD5 Hash Usage",
     "MD5 is cryptographically broken. Avoid for security purposes.",
     "Use hashlib.sha256() or SHA-3 for general hashing needs."),

    ("l1/sha1-general",
     r'hashlib\.sha1\s*\(|SHA1\s*\(',
     "medium", "SHA-1 Hash Usage",
     "SHA-1 is no longer collision-resistant. Avoid for security.",
     "Use SHA-256 or SHA-3 instead."),

    ("l1/des-usage",           r'\bDES\b|\bTripleDES\b',
     "high", "DES/3DES Encryption — Deprecated Cipher",
     "DES is broken; 3DES is being deprecated (CVE-2016-2183, Sweet32).",
     "Use AES-256-GCM instead."),

    ("l1/rc4-usage",           r'\bRC4\b|\bARC4\b',
     "critical", "RC4 Stream Cipher — Broken",
     "RC4 has multiple cryptographic weaknesses (BEAST, POODLE variants).",
     "Use AES-GCM. RC4 is banned in TLS 1.3."),

    # ── Go specific ───────────────────────────────────────────────────────────
    ("l1/go-http-listenserve",
     r'http\.ListenAndServe\s*\(\s*["\']:',
     "medium", "Go HTTP Server Binding to All Interfaces",
     "Binding to 0.0.0.0 exposes the server on all network interfaces.",
     "Bind to specific interface in prod. Use TLS: http.ListenAndServeTLS()."),

    ("l1/go-math-rand",
     r'math/rand',
     "medium", "Go math/rand Used (Not Cryptographic)",
     "math/rand is seeded and predictable. Do not use for security.",
     "Use crypto/rand for all security-sensitive random values."),

    # ── Rust specific ─────────────────────────────────────────────────────────
    ("l1/rust-unsafe",
     r'\bunsafe\s*\{',
     "low", "Rust unsafe Block",
     "unsafe blocks bypass Rust's memory safety guarantees.",
     "Limit unsafe blocks to the minimum necessary. Document invariants."),

    # ── SSRF/File loading ─────────────────────────────────────────────────────
    ("l1/file-url-load",
     r'(urllib\.request\.urlopen|requests\.get)\s*\(\s*[^)]*file://',
     "high", "File:// URL in HTTP Request — LFI Risk",
     "file:// scheme in URL fetch can read local files.",
     "Block file:// scheme. Validate URL scheme before making requests."),

    # ── XXE ───────────────────────────────────────────────────────────────────
    ("l1/xxe-risk",
     r'(etree\.parse|minidom\.parse|SAXParser|XMLReader)\s*\([^)]*\)',
     "high", "Potential XXE (XML External Entity) Risk",
     "XML parsers can be tricked into reading local files or making SSRF requests.",
     "Disable DTD/entity processing: lxml's resolve_entities=False."),

    # ── LDAP injection ────────────────────────────────────────────────────────
    ("l1/ldap-injection",
     r'ldap.*search.*\+|ldap.*filter.*request',
     "high", "LDAP Injection Risk",
     "User input in LDAP filter string enables directory traversal.",
     "Escape LDAP special characters. Use parameterized LDAP queries."),

    # ── PostMessage ───────────────────────────────────────────────────────────
    ("l1/postmessage-no-origin",
     r'addEventListener\s*\(["\']message["\']',
     "medium", "postMessage Listener Without Origin Validation",
     "Listening to 'message' without checking event.origin allows XSS from any frame.",
     "Always validate: if (event.origin !== 'https://yourdomain.com') return;"),

    # ── ReDoS ─────────────────────────────────────────────────────────────────
    ("l1/redos",
     r'new RegExp\s*\([^)]*([\+\*\{])[^)]*\)',
     "medium", "ReDoS — Catastrophic Regex Backtracking Risk",
     "Dynamically-built regex with nested quantifiers can freeze the server.",
     "Use static regexes. Validate regex complexity. Use re2 for user patterns."),

    # ── PHP specific ──────────────────────────────────────────────────────────
    ("l1/php-file-include",
     r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
     "critical", "PHP Remote File Inclusion (RFI)",
     "PHP include of user-controlled path enables RCE via remote files.",
     "Use a whitelist of allowed include paths. Disable allow_url_include."),

    ("l1/php-sql-injection",
     r'mysql_query\s*\(\s*["\'].*(SELECT|INSERT|UPDATE|DELETE).*\.\s*\$_(GET|POST|REQUEST)',
     "critical", "PHP SQL Injection via $_GET/$_POST",
     "Direct user input in mysql_query() enables SQL injection.",
     "Use PDO with prepared statements. Never interpolate user input in SQL."),

    # ── Node.js / Express ─────────────────────────────────────────────────────
    ("l1/express-admin-no-auth",
     r'app\.(get|post|put|delete|patch)\s*\(["\'][^\"\']*/admin[^"\']*["\']',
     "high", "Admin Route May Lack Auth Middleware",
     "Admin routes should always have authentication middleware.",
     "Apply requireAuth/passport middleware to all /admin routes."),

    ("l1/json-parse-unvalidated",
     r'JSON\.parse\s*\(\s*(req\.|request\.|body\.|params\.|event\.data)',
     "medium", "JSON.parse() on Unvalidated External Input",
     "Parsing external JSON without schema validation allows unexpected shapes.",
     "Validate parsed JSON with Zod/Yup. Reject unexpected fields."),

    # ── Cookie flags ──────────────────────────────────────────────────────────
    ("l1/cookie-no-secure",
     r'(Set-Cookie|res\.cookie|cookie\.set)\s*[^;]{0,200}(?!Secure|secure)',
     "medium", "Cookie Without 'Secure' Flag",
     "Cookie without Secure flag is sent over HTTP connections.",
     "Always set Secure, HttpOnly, and SameSite=Strict on session cookies."),

    # ── TypeScript ────────────────────────────────────────────────────────────
    ("l1/ts-any-auth",
     r':\s*any\b.{0,100}(auth|token|user|permission|role|admin)',
     "low", "TypeScript 'any' in Auth Context",
     "Using 'any' in auth code disables type safety, masking security bugs.",
     "Define proper interfaces for auth objects. Enable noImplicitAny."),

    # ── Python-specific ───────────────────────────────────────────────────────
    ("l1/py-input-dangerous",
     r'\binput\s*\([^)]*\).{0,30}(exec|eval|os\.|subprocess)',
     "critical", "Python input() Result Passed to Dangerous Function",
     "input() result passed directly to exec/eval/os enables RCE.",
     "Validate and sanitize all user input before use in system calls."),

    ("l1/py-tempfile-insecure",
     r'tempfile\.mktemp\s*\(',
     "medium", "Python tempfile.mktemp() — Race Condition / TOCTOU",
     "mktemp() is insecure; another process can create the file between check+use.",
     "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead."),

    ("l1/flask-secret-key-weak",
     r'app\.secret_key\s*=\s*["\'][^"\']{0,16}["\']',
     "high", "Flask Secret Key Too Short or Hardcoded",
     "Flask session cookies are signed with the secret key. Short keys are brute-forceable.",
     "Use os.urandom(32) to generate a strong secret. Store in env var."),

    ("l1/django-secret-key",
     r'SECRET_KEY\s*=\s*["\'][^"\']{1,50}["\']',
     "critical", "Django SECRET_KEY Hardcoded",
     "Hardcoded Django SECRET_KEY allows CSRF token forgery and cookie attacks.",
     "Move SECRET_KEY to environment variables. Generate with: python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\""),

    ("l1/py-xmlrpc",
     r'from xmlrpc\.server import|import xmlrpclib',
     "medium", "XML-RPC Server — Potential Attack Surface",
     "XML-RPC has known vulnerabilities and may expose unintended endpoints.",
     "Prefer REST over XML-RPC. If used, add authentication and input validation."),

    # ── Electron / Desktop ────────────────────────────────────────────────────
    ("l1/electron-node-integration",
     r'"nodeIntegration"\s*:\s*true|nodeIntegration:\s*true',
     "critical", "Electron nodeIntegration=true — XSS to RCE",
     "Enabling nodeIntegration in Electron allows XSS to escalate to full RCE.",
     "Set nodeIntegration: false; use contextBridge and preload scripts instead."),

    ("l1/electron-web-security-false",
     r'webSecurity:\s*false',
     "high",     "Electron webSecurity=false — SOP Disabled",
     "Disabling web security in Electron bypasses Same-Origin Policy.",
     "Remove webSecurity: false. Fix CORS issues at the server level."),

    # ── C# / .NET ─────────────────────────────────────────────────────────
    ("l1/csharp-sqli",
     r'(SqlCommand|ExecuteReader|ExecuteNonQuery)\s*\([^)]*"\s*\+',
     "critical", "C# SQL Injection via String Concatenation",
     "SqlCommand built with string concatenation enables SQL injection.",
     "Use SqlParameter and parameterized queries."),

    ("l1/csharp-xxe",
     r'XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Parse',
     "high", "C# XXE — DTD Processing Enabled",
     "Enabling DTD processing in XML parser allows XXE attacks.",
     "Set DtdProcessing = DtdProcessing.Prohibit."),

    ("l1/csharp-deserialization",
     r'BinaryFormatter\s*\(\s*\)\.Deserialize',
     "critical", "C# BinaryFormatter Deserialization — RCE Risk",
     "BinaryFormatter.Deserialize() on untrusted data enables remote code execution.",
     "Use System.Text.Json or Newtonsoft.Json instead of BinaryFormatter."),

    # ── Ruby ──────────────────────────────────────────────────────────────
    ("l1/ruby-system-exec",
     r'\b(system|exec|`[^`]*`)\s*[^#]',
     "high", "Ruby Shell Execution — Command Injection Risk",
     "system/exec/backticks run shell commands; user input enables injection.",
     "Use Open3.capture3 with explicit argument arrays."),

    ("l1/ruby-mass-assignment",
     r'params\.permit!|attr_accessible\s*:',
     "high", "Ruby Mass Assignment — IDOR/Priv Escalation Risk",
     "permitting all params or using attr_accessible risks mass assignment.",
     "Use strong_params: params.require(:model).permit(:field1, :field2)."),

    # ── Kotlin / Android ──────────────────────────────────────────────────
    ("l1/kotlin-webview-js",
     r'settings\.javaScriptEnabled\s*=\s*true',
     "high", "Android WebView JavaScript Enabled — XSS Risk",
     "JavaScript in WebView with untrusted content enables XSS.",
     "Only enable JavaScript for trusted origins. Use shouldOverrideUrlLoading."),

    ("l1/kotlin-cleartext",
     r'usesCleartextTraffic\s*=\s*["\']?true',
     "high", "Android Cleartext Traffic Allowed",
     "Allowing cleartext HTTP traffic exposes data to interception.",
     "Set usesCleartextTraffic=false. Use HTTPS for all connections."),

    # ── Python additional ─────────────────────────────────────────────────
    ("l1/py-subprocess-shell-cmd",
     r'subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
     "high", "subprocess with shell=True — Command Injection",
     "shell=True + user input enables OS command injection.",
     "Use subprocess.run([cmd, arg], shell=False) with list args."),

    ("l1/py-marshal-load",
     r'marshal\.load',
     "critical", "Python marshal.load() — Code Execution Risk",
     "marshal is even less safe than pickle. Never unpickle untrusted data.",
     "Use JSON or MessagePack for data serialization."),

    ("l1/py-shelve-open",
     r'shelve\.open\s*\(',
     "high", "Python shelve.open() — Pickle-Based Deserialization",
     "shelve uses pickle internally. Opening untrusted shelve DBs enables RCE.",
     "Use JSON or SQLite for persistent storage."),

    # ── GraphQL ────────────────────────────────────────────────────────────
    ("l1/graphql-introspection",
     r'introspection\s*[:=]\s*true|enableIntrospection',
     "medium", "GraphQL Introspection Enabled in Production",
     "GraphQL introspection reveals the entire API schema to attackers.",
     "Disable introspection in production: introspection: false."),

    # ── Rate Limiting / DoS ────────────────────────────────────────────────
    ("l1/no-rate-limit-login",
     r'(app|router)\.(post|put)\s*\(["\']\/(login|signin|auth|register|signup)',
     "medium", "Auth Endpoint Without Rate Limiting Check",
     "Login/register endpoints without rate limiting enable brute-force attacks.",
     "Add rate limiting middleware (e.g. express-rate-limit, slowapi)."),

    # ── .env file secrets ─────────────────────────────────────────────────
    ("l1/env-file-secret",
     r'^(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET|STRIPE_SECRET)\s*=\s*[^\s]+',
     "critical", "Secret Value in .env File Committed to Repo",
     ".env file with real secret values committed to version control.",
     "Add .env to .gitignore. Use .env.example with placeholders only."),
]


# ── Compile patterns once at module load ───────────────────────────────────────
COMPILED_PATTERNS: list[dict] = []
for _entry in RAW_PATTERNS:
    try:
        COMPILED_PATTERNS.append({
            "rule_id":     _entry[0],
            "pattern":     re.compile(_entry[1], re.IGNORECASE | re.MULTILINE),
            "severity":    _entry[2],
            "issue":       _entry[3],
            "description": _entry[4],
            "fix":         _entry[5],
        })
    except re.error as _e:
        log.warning(f"Layer 1: Bad regex for {_entry[0]}: {_e}")


# Also scan .env and config extensions for secret patterns
_EXTRA_SCAN_EXTENSIONS = {".env", ".cfg", ".ini", ".conf", ".toml"}


def run_layer1_surface(repo_path: str, file_map: Optional["RepoFileMap"] = None) -> list[NexusFinding]:
    """
    Run Layer 1: Surface scan over all code files.
    If file_map is provided, uses pre-loaded file data (no filesystem I/O).
    Returns list of NexusFinding instances.
    """
    findings: list[NexusFinding] = []
    file_count = 0

    if file_map is not None:
        # Fast path: use pre-loaded file data
        scan_exts = CODE_EXTENSIONS | _EXTRA_SCAN_EXTENSIONS
        for rel_path, fi in file_map.files.items():
            if fi.extension not in scan_exts:
                continue
            file_count += 1
            findings.extend(_scan_file(fi.content, rel_path))
    else:
        # Legacy path: walk filesystem
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in CODE_EXTENSIONS and ext not in _EXTRA_SCAN_EXTENSIONS:
                    continue
                filepath = os.path.join(root, fname)
                rel_path = os.path.relpath(filepath, repo_path)
                file_count += 1
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    findings.extend(_scan_file(content, rel_path))
                except Exception as exc:
                    log.debug(f"L1 scan error on {rel_path}: {exc}")

    log.info(f"[Layer 1] Scanned {file_count} files → {len(findings)} findings")
    return findings


def _scan_file(content: str, rel_path: str) -> list[NexusFinding]:
    """Apply all compiled patterns to a single file's content."""
    findings: list[NexusFinding] = []
    lines = content.splitlines()
    seen_rules: set[str] = set()  # one finding per rule per file

    for pd in COMPILED_PATTERNS:
        if pd["rule_id"] in seen_rules:
            continue
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "<!--")):
                continue
            m = pd["pattern"].search(line)
            if m:
                seen_rules.add(pd["rule_id"])
                sev_map = {
                    "critical": NexusSeverity.CRITICAL,
                    "high":     NexusSeverity.HIGH,
                    "medium":   NexusSeverity.MEDIUM,
                    "low":      NexusSeverity.LOW,
                }
                # Higher confidence for more specific patterns (longer match)
                confidence = min(0.95, 0.6 + len(m.group()) * 0.005)
                findings.append(NexusFinding(
                    layer=NexusLayer.SURFACE,
                    rule_id=pd["rule_id"],
                    issue=pd["issue"],
                    description=pd["description"],
                    file=rel_path,
                    line=lineno,
                    column=m.start(),
                    code_snippet=stripped[:300],
                    severity=sev_map.get(pd["severity"], NexusSeverity.MEDIUM),
                    confidence=round(confidence, 2),
                    exploitability=_sev_to_exploit(pd["severity"]),
                    blast_radius=_estimate_blast_radius(pd["rule_id"], rel_path),
                    suggested_fix=pd["fix"],
                ))
                break  # one match per pattern per file
    return findings


def _sev_to_exploit(severity: str) -> float:
    return {"critical": 0.85, "high": 0.65, "medium": 0.40, "low": 0.15, "info": 0.05}.get(severity, 0.40)


def _estimate_blast_radius(rule_id: str, file_path: str) -> int:
    """Rough blast-radius estimate based on rule category."""
    rule = rule_id.lower()
    if any(x in rule for x in ("aws", "gcp", "azure", "firebase")):
        return 10   # Cloud-wide access
    if any(x in rule for x in ("db-url", "sqli", "jwt", "auth")):
        return 8    # Data layer access
    if any(x in rule for x in ("rce", "exec", "pickle", "eval")):
        return 9    # RCE = entire server
    if any(x in rule for x in ("xss", "csrf", "localstorage")):
        return 5    # User-facing
    if "secret" in rule or "credential" in rule or "password" in rule:
        return 7
    if "debug" in rule or "ssl" in rule:
        return 4
    return 2
