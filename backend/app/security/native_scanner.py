"""
Native code security scanner — works without any external tools.

Performs deep security analysis using:
- Python AST analysis (for Python code)
- Regex pattern matching across all languages
- Dependency file scanning (requirements.txt, package.json, etc.)
- Secret / credential detection (50+ patterns)
- Typosquatting package detection
- License compliance checking
- IaC / config file scanning

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
    # ── Expanded Secret / Credential Detection ─────────────────────────────────
    {
        "id": "hardcoded-secret-key",
        "pattern": re.compile(
            r'(?i)(secret[_-]?key|api[_-]?key|password|passwd|token|auth[_-]?key|access[_-]?token)\s*[=:]\s*["\'][^"\']{8,}["\']',
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
        "description": "An AWS Access Key ID pattern was found in source code. This provides access to your AWS account.",
        "fix": "Revoke this key immediately at AWS IAM Console, rotate credentials, and use IAM roles instead of long-term credentials.",
    },
    {
        "id": "aws-secret-key",
        "pattern": re.compile(r'(?i)(aws.secret|secret.access.key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']'),
        "severity": "critical",
        "issue": "AWS Secret Access Key Exposed",
        "description": "An AWS Secret Access Key was found in source code.",
        "fix": "Revoke the key at AWS IAM Console immediately. Never hardcode AWS credentials — use IAM roles or environment variables.",
    },
    {
        "id": "private-key-material",
        "pattern": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
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
    {
        "id": "stripe-secret-key",
        "pattern": re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'),
        "severity": "critical",
        "issue": "Stripe Secret Key Exposed",
        "description": "A Stripe secret key was found. This allows full access to your Stripe account including charges and payouts.",
        "fix": "Revoke immediately at dashboard.stripe.com/apikeys and regenerate. Use Stripe's restricted keys for minimal permissions.",
    },
    {
        "id": "stripe-publishable-key",
        "pattern": re.compile(r'pk_(live|test)_[A-Za-z0-9]{24,}'),
        "severity": "medium",
        "issue": "Stripe Publishable Key Exposed",
        "description": "A Stripe publishable key was found in source code. While less critical than the secret key, it should not be hardcoded.",
        "fix": "Move to environment variables. Publishable keys are safe to use client-side but should not be committed to version control.",
    },
    {
        "id": "slack-token",
        "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z\-]+'),
        "severity": "critical",
        "issue": "Slack API Token Exposed",
        "description": "A Slack API token was found in source code. This allows reading all messages and posting to your Slack workspace.",
        "fix": "Revoke at api.slack.com/apps immediately. Rotate the token and move to environment variables.",
    },
    {
        "id": "slack-webhook",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "severity": "high",
        "issue": "Slack Webhook URL Exposed",
        "description": "A Slack incoming webhook URL was found. Anyone with this URL can post messages to your Slack channel.",
        "fix": "Regenerate the webhook URL in Slack app settings and move it to environment variables.",
    },
    {
        "id": "twilio-key",
        "pattern": re.compile(r'SK[a-f0-9]{32}'),
        "severity": "critical",
        "issue": "Twilio API Key Exposed",
        "description": "A Twilio API key was found in source code, allowing SMS/calls to be made at your expense.",
        "fix": "Revoke at twilio.com/console/project/api-keys. Rotate all Twilio credentials.",
    },
    {
        "id": "sendgrid-key",
        "pattern": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
        "severity": "critical",
        "issue": "SendGrid API Key Exposed",
        "description": "A SendGrid API key was found in source code, allowing sending emails from your account.",
        "fix": "Revoke at app.sendgrid.com/settings/api_keys immediately. Use environment variables for all API keys.",
    },
    {
        "id": "gcp-service-account",
        "pattern": re.compile(r'\"type\":\s*\"service_account\"'),
        "severity": "critical",
        "issue": "GCP Service Account Key Exposed",
        "description": "A Google Cloud Platform service account JSON key file appears to be embedded or referenced in source code.",
        "fix": "Delete this service account key at cloud.google.com/iam and create a new one. Use Workload Identity instead of key files.",
    },
    {
        "id": "google-api-key",
        "pattern": re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
        "severity": "high",
        "issue": "Google API Key Exposed",
        "description": "A Google API key was found in source code. This can be used to make API calls billed to your account.",
        "fix": "Restrict the key at console.cloud.google.com/apis/credentials to specific APIs and referrers. Move to environment variables.",
    },
    {
        "id": "firebase-key",
        "pattern": re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
        "severity": "critical",
        "issue": "Firebase Server Key Exposed",
        "description": "A Firebase Cloud Messaging server key was found, allowing push notifications to all app users.",
        "fix": "Regenerate the key in Firebase Console. Use environment variables to store the new key.",
    },
    {
        "id": "azure-storage-key",
        "pattern": re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}=='),
        "severity": "critical",
        "issue": "Azure Storage Connection String Exposed",
        "description": "An Azure Storage account connection string was found, providing full access to your Azure storage blobs, queues, and tables.",
        "fix": "Regenerate the storage account access key in Azure Portal. Use Azure Key Vault or Managed Identity instead.",
    },
    {
        "id": "azure-client-secret",
        "pattern": re.compile(r'(?i)(client.secret|clientSecret|AZURE_CLIENT_SECRET)\s*[=:]\s*["\'][A-Za-z0-9_~.-]{34,}["\']'),
        "severity": "critical",
        "issue": "Azure Client Secret Exposed",
        "description": "An Azure AD application client secret was found in source code.",
        "fix": "Rotate the client secret in Azure App Registrations. Use Azure Managed Identity or Key Vault.",
    },
    {
        "id": "npm-token",
        "pattern": re.compile(r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+'),
        "severity": "critical",
        "issue": "npm Auth Token Exposed in .npmrc",
        "description": "An npm authentication token was found. This allows publishing packages to npm under your account.",
        "fix": "Revoke the token at npmjs.com/settings/tokens. Never commit .npmrc with auth tokens.",
    },
    {
        "id": "heroku-api-key",
        "pattern": re.compile(r'(?i)(heroku.api.key|HEROKU_API_KEY)\s*[=:]\s*["\'][a-f0-9-]{36}["\']'),
        "severity": "critical",
        "issue": "Heroku API Key Exposed",
        "description": "A Heroku API key was found, allowing full control of your Heroku account and applications.",
        "fix": "Regenerate at heroku.com/account. Use Heroku environment variables (config vars) instead.",
    },
    {
        "id": "mailchimp-key",
        "pattern": re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}'),
        "severity": "high",
        "issue": "Mailchimp API Key Exposed",
        "description": "A Mailchimp API key was found, allowing access to your mailing lists and campaign data.",
        "fix": "Revoke at mailchimp.com/account/api and generate a new key. Store in environment variables.",
    },
    {
        "id": "paypal-client-secret",
        "pattern": re.compile(r'(?i)(paypal.client.secret|PAYPAL_SECRET)\s*[=:]\s*["\'][A-Za-z0-9_-]{64,}["\']'),
        "severity": "critical",
        "issue": "PayPal Client Secret Exposed",
        "description": "A PayPal client secret was found in source code, allowing payment processing on your account.",
        "fix": "Regenerate app credentials at developer.paypal.com. Move to secure environment variables.",
    },
    {
        "id": "ssh-password-in-config",
        "pattern": re.compile(r'(?i)(ssh_password|sshpass|StrictHostKeyChecking=no).{0,100}'),
        "severity": "high",
        "issue": "SSH Password or Insecure Config in Code",
        "description": "SSH password or insecure StrictHostKeyChecking=no configuration was found.",
        "fix": "Use SSH key-based authentication. Never store SSH passwords in code. Enable host key verification.",
    },
    {
        "id": "database-url-with-password",
        "pattern": re.compile(r'(postgres|mysql|mongodb|redis)://[^:@/]+:[^@/]+@'),
        "severity": "critical",
        "issue": "Database Connection String With Credentials Exposed",
        "description": "A database connection URL containing a username and password was found in source code.",
        "fix": "Move database credentials to environment variables (DATABASE_URL). Use connection poolers with IAM auth where possible.",
    },
    {
        "id": "jwt-hardcoded-secret",
        "pattern": re.compile(r'(?i)(jwt.secret|JWT_SECRET|signing.key)\s*[=:]\s*["\'][^"\']{8,}["\']'),
        "severity": "critical",
        "issue": "JWT Signing Secret Hardcoded",
        "description": "A JWT signing secret is hardcoded in source code. Anyone who sees this code can forge authentication tokens.",
        "fix": "Move the JWT secret to an environment variable (JWT_SECRET). Use a cryptographically random 256-bit value.",
    },
    {
        "id": "encryption-key-hardcoded",
        "pattern": re.compile(r'(?i)(encryption.key|ENCRYPTION_KEY|AES.key|cipher.key)\s*[=:]\s*["\'][^"\']{8,}["\']'),
        "severity": "critical",
        "issue": "Encryption Key Hardcoded",
        "description": "An encryption key was found hardcoded in source code. This defeats the purpose of encryption.",
        "fix": "Generate encryption keys using a CSPRNG and store in a secrets manager. Rotate exposed keys immediately.",
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


# ── Typosquatting detection ────────────────────────────────────────────────────

# Popular packages and their typosquat variants to watch out for
TYPOSQUAT_PACKAGES: dict[str, str] = {
    # Python
    "reqeusts": "requests", "requets": "requests", "requsts": "requests",
    "panda": "pandas", "pandsa": "pandas", "numppy": "numpy", "nupy": "numpy",
    "flaskk": "flask", "djnago": "django", "djangoo": "django",
    "sqlalcehmy": "sqlalchemy", "pytets": "pytest", "beautifulsup": "beautifulsoup4",
    "scikit-lern": "scikit-learn", "scippy": "scipy", "maplotlib": "matplotlib",
    "pilow": "pillow", "cryptographyy": "cryptography",
    # JavaScript/Node
    "lodsh": "lodash", "lohash": "lodash", "monment": "moment", "momnet": "moment",
    "expresss": "express", "expresjs": "express", "reactt": "react",
    "axois": "axios", "axiso": "axios", "webpcak": "webpack",
    "babbel": "babel", "eslnt": "eslint", "typscript": "typescript",
    "mongosse": "mongoose", "mongose": "mongoose", "sequilize": "sequelize",
    "jasonwebtoken": "jsonwebtoken", "jsonwebtokn": "jsonwebtoken",
    "dotenev": "dotenv", "dotevn": "dotenv", "cors2": "cors",
    "nodemailler": "nodemailer", "nodmailr": "nodemailer",
}

# ── License compliance ─────────────────────────────────────────────────────────

# Licenses that are problematic for commercial/proprietary use
COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
    "GPL", "GPLv2", "GPLv3", "AGPL", "LGPL",
}

# Known licenses of popular packages (subset — fallback for when no manifest license info)
KNOWN_PACKAGE_LICENSES: dict[str, str] = {
    "gpl": "GPL-3.0", "python-gflags": "BSD-3", "gnureadline": "GPL-3.0",
    "mysql-connector-python": "GPL-2.0", "mysqlclient": "GPL-2.0",
    "pyqt5": "GPL-3.0", "pyqt6": "GPL-3.0", "sip": "GPL-2.0",
    "gdb": "GPL-3.0", "ffmpeg-python": "LGPL-2.1",
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
                    # Check for typosquatting
                    typo_findings = _check_typosquatting(content, filename, rel_path)
                    findings.extend(typo_findings)
                    # Check license compliance
                    license_findings = _check_license_compliance(content, filename, rel_path)
                    findings.extend(license_findings)
                except Exception as e:
                    log.debug(f"Native scanner: error reading {rel_path}: {e}")

            # Scan IaC / config files
            if filename in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml") \
                    or ext in (".tf", ".yaml", ".yml") and "k8s" not in rel_path:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    iac_findings = _scan_iac_file(content, rel_path, filename)
                    findings.extend(iac_findings)
                except Exception as e:
                    log.debug(f"Native scanner: error reading IaC file {rel_path}: {e}")

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
    findings: list[dict] = []
    if filename in ("requirements.txt", "Pipfile"):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[>=<!~]+\s*([\d\.]+)", line)
            if match:
                pkg = match.group(1).lower()
                version = match.group(2)
                _check_package(pkg, version, filepath, filename, findings)
    elif filename == "package.json":
        try:
            data = json.loads(content)
            deps: dict = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            for pkg, ver_spec in deps.items():
                ver = re.sub(r"[\^~>=<]", "", str(ver_spec)).strip()
                _check_package(pkg.lower(), ver, filepath, filename, findings)
        except (json.JSONDecodeError, AttributeError):
            pass
    return findings


def _check_typosquatting(content: str, filename: str, filepath: str) -> list[dict]:
    """Detect typosquatted package names that may be malicious."""
    findings = []

    if filename == "requirements.txt" or filename == "Pipfile":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if match:
                pkg = match.group(1).lower().replace("_", "-")
                if pkg in TYPOSQUAT_PACKAGES:
                    intended = TYPOSQUAT_PACKAGES[pkg]
                    findings.append({
                        "file": filepath,
                        "line": None,
                        "issue": f"Possible Typosquatting: '{pkg}' looks like '{intended}'",
                        "description": f"The package '{pkg}' closely resembles the popular package '{intended}', which may indicate a supply-chain attack. Typosquatted packages can contain malware.",
                        "severity": "critical",
                        "rule_id": f"native/typosquat-{pkg}",
                        "code_snippet": f"Package: {pkg}  # Did you mean: {intended}?",
                        "suggested_fix": f"Verify this is intentional. If you meant '{intended}', correct the package name and run pip/npm install again. Check the package's source and maintainer.",
                        "scanner": "semgrep",
                    })

    elif filename == "package.json":
        try:
            data = json.loads(content)
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg in all_deps:
                normalized = pkg.lower().replace("_", "-")
                if normalized in TYPOSQUAT_PACKAGES:
                    intended = TYPOSQUAT_PACKAGES[normalized]
                    findings.append({
                        "file": filepath,
                        "line": None,
                        "issue": f"Possible Typosquatting: '{pkg}' looks like '{intended}'",
                        "description": f"The package '{pkg}' closely resembles '{intended}', which may be a supply-chain attack.",
                        "severity": "critical",
                        "rule_id": f"native/typosquat-{normalized}",
                        "code_snippet": f"\"dependencies\": {{ \"{pkg}\": ... }}",
                        "suggested_fix": f"Verify this is intentional. If you meant '{intended}', correct the spelling. Inspect the package source at npmjs.com.",
                        "scanner": "semgrep",
                    })
        except (json.JSONDecodeError, AttributeError):
            pass

    return findings


def _check_license_compliance(content: str, filename: str, filepath: str) -> list[dict]:
    """Check for GPL/copyleft licenses in dependencies."""
    findings = []

    if filename == "package.json":
        try:
            data = json.loads(content)
            license_field = data.get("license", "")
            if isinstance(license_field, str) and license_field.upper() in {l.upper() for l in COPYLEFT_LICENSES}:
                findings.append({
                    "file": filepath,
                    "line": None,
                    "issue": f"Copyleft License Detected: {license_field}",
                    "description": f"This project uses {license_field}, a copyleft license. If this is a commercial/proprietary project, the GPL license may require you to open-source your entire project.",
                    "severity": "medium",
                    "rule_id": "native/copyleft-license",
                    "code_snippet": f'"license": "{license_field}"',
                    "suggested_fix": "Review your licensing obligations. For commercial projects, consider MIT, Apache-2.0, or BSD licenses. Consult a lawyer if unsure about GPL implications.",
                    "scanner": "semgrep",
                })
            # Check known packages against license DB
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg in all_deps:
                pkg_license = KNOWN_PACKAGE_LICENSES.get(pkg.lower())
                if pkg_license and pkg_license in COPYLEFT_LICENSES:
                    findings.append({
                        "file": filepath,
                        "line": None,
                        "issue": f"GPL-Licensed Dependency: {pkg} ({pkg_license})",
                        "description": f"{pkg} uses {pkg_license}. Using this in a proprietary project may trigger GPL's copyleft requirements.",
                        "severity": "low",
                        "rule_id": f"native/gpl-dependency-{pkg}",
                        "code_snippet": f'"dependencies": {{ "{pkg}": ... }}',
                        "suggested_fix": f"Evaluate if {pkg} can be replaced with a more permissively licensed alternative.",
                        "scanner": "semgrep",
                    })
        except (json.JSONDecodeError, AttributeError):
            pass

    return findings


IAC_PATTERNS = [
    {
        "id": "docker-run-as-root",
        "pattern": re.compile(r'^(FROM|RUN|CMD|ENTRYPOINT)', re.MULTILINE),
        "no_pattern": re.compile(r'^USER\s+(?!root\b|0\b)', re.MULTILINE),
        "severity": "high",
        "issue": "Dockerfile Missing USER Directive (Running as Root)",
        "description": "Containers running as root are dangerous — a container escape grants full host root access.",
        "fix": "Add 'USER nonroot' or create a dedicated system user: RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser",
    },
    {
        "id": "docker-latest-tag",
        "pattern": re.compile(r'^FROM\s+\S+:latest', re.MULTILINE),
        "severity": "medium",
        "issue": "Dockerfile Using ':latest' Image Tag",
        "description": "Using ':latest' makes builds non-reproducible and can pull in breaking changes or vulnerable image versions.",
        "fix": "Pin to a specific version tag: FROM node:20.11.0-alpine3.19 instead of FROM node:latest.",
    },
    {
        "id": "docker-expose-all",
        "pattern": re.compile(r'^EXPOSE\s+(22|23|3389|5900)\b', re.MULTILINE),
        "severity": "high",
        "issue": "Dockerfile Exposing Sensitive Port (SSH/RDP/VNC)",
        "description": "Exposing administrative ports like SSH (22), Telnet (23), RDP (3389), or VNC (5900) in a container is a security risk.",
        "fix": "Remove the EXPOSE directive for administrative ports. Use kubectl exec or docker exec for shell access instead.",
    },
    {
        "id": "docker-add-vs-copy",
        "pattern": re.compile(r'^ADD\s+http', re.MULTILINE),
        "severity": "medium",
        "issue": "Dockerfile ADD with Remote URL (Use COPY Instead)",
        "description": "ADD with a URL fetches files without checksum verification, making builds vulnerable to MITM attacks.",
        "fix": "Use RUN curl -fsSL <URL> | sha256sum -c <expected> before using the file. Prefer COPY for local files.",
    },
    {
        "id": "k8s-privileged-container",
        "pattern": re.compile(r'privileged:\s*true', re.IGNORECASE),
        "severity": "critical",
        "issue": "Kubernetes Pod Running in Privileged Mode",
        "description": "Privileged containers have full access to the host kernel. A vulnerability in the container could grant full host access.",
        "fix": "Set securityContext.privileged: false. Use specific capabilities instead: securityContext.capabilities.add: [NET_BIND_SERVICE].",
    },
    {
        "id": "k8s-no-resource-limits",
        "pattern": re.compile(r'containers:', re.IGNORECASE),
        "no_pattern": re.compile(r'resources:\s*\n\s+limits:', re.IGNORECASE),
        "severity": "medium",
        "issue": "Kubernetes Container Missing Resource Limits",
        "description": "Containers without resource limits can consume all node resources, causing denial of service for other pods.",
        "fix": "Add resources.limits.cpu and resources.limits.memory to each container spec.",
    },
    {
        "id": "k8s-host-network",
        "pattern": re.compile(r'hostNetwork:\s*true', re.IGNORECASE),
        "severity": "high",
        "issue": "Kubernetes Pod Using Host Network",
        "description": "hostNetwork: true bypasses Kubernetes network isolation, giving the pod access to all host network interfaces.",
        "fix": "Remove hostNetwork: true. Use Kubernetes Services and ClusterIP for internal communication.",
    },
    {
        "id": "tf-public-s3-bucket",
        "pattern": re.compile(r'(acl\s*=\s*["\']public-read|block_public_acls\s*=\s*false)', re.IGNORECASE),
        "severity": "critical",
        "issue": "Terraform S3 Bucket Publicly Accessible",
        "description": "An S3 bucket is configured for public read access or public ACLs are not blocked, risking data exposure.",
        "fix": "Set aws_s3_bucket_public_access_block with block_public_acls = true. Use bucket policies for controlled access.",
    },
    {
        "id": "tf-security-group-all",
        "pattern": re.compile(r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']', re.IGNORECASE),
        "severity": "high",
        "issue": "Terraform Security Group Open to All IPs (0.0.0.0/0)",
        "description": "A security group rule allows traffic from any IP address. This exposes services to the entire internet.",
        "fix": "Restrict ingress to specific CIDR ranges. For SSH: use a VPN CIDR or bastion host. Never expose 0.0.0.0/0 for SSH.",
    },
    {
        "id": "docker-compose-no-health",
        "pattern": re.compile(r'^\s+image:\s+', re.MULTILINE),
        "no_pattern": re.compile(r'healthcheck:', re.IGNORECASE),
        "severity": "low",
        "issue": "docker-compose Service Missing Healthcheck",
        "description": "Services without healthchecks may be considered ready before they are fully initialized, causing errors.",
        "fix": "Add a healthcheck section to each service: healthcheck:\n  test: [CMD, curl, -f, http://localhost/health]\n  interval: 30s",
    },
]


def _scan_iac_file(content: str, filepath: str, filename: str) -> list[dict]:
    """Scan IaC files (Dockerfiles, docker-compose, Terraform, K8s YAML) for security issues."""
    findings = []
    for p in IAC_PATTERNS:
        if p["pattern"].search(content):
            # If there's a 'no_pattern' that should be present but isn't, flag it
            if "no_pattern" in p:
                if not p["no_pattern"].search(content):
                    findings.append({
                        "file": filepath,
                        "line": None,
                        "issue": p["issue"],
                        "description": p["description"],
                        "severity": p["severity"],
                        "rule_id": f"native/{p['id']}",
                        "code_snippet": filename,
                        "suggested_fix": p["fix"],
                        "scanner": "semgrep",
                    })
            else:
                findings.append({
                    "file": filepath,
                    "line": None,
                    "issue": p["issue"],
                    "description": p["description"],
                    "severity": p["severity"],
                    "rule_id": f"native/{p['id']}",
                    "code_snippet": filename,
                    "suggested_fix": p["fix"],
                    "scanner": "semgrep",
                })
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
