import VulnerabilityCard from "@/components/dashboard/VulnerabilityCard";

const vulns = [
  {
    file: "src/auth/login.ts",
    issue: "SQL Injection vulnerability in user authentication query",
    severity: "critical" as const,
    fix: "Use parameterized queries instead of string concatenation",
    snippet: `const query = "SELECT * FROM users WHERE email = '" + email + "'";`,
  },
  {
    file: "package.json",
    issue: "Outdated dependency 'lodash' with known prototype pollution vulnerability",
    severity: "high" as const,
    fix: "Update lodash to version 4.17.21 or later",
    snippet: `"lodash": "^4.17.15"`,
  },
  {
    file: "src/api/upload.ts",
    issue: "Missing file type validation on upload endpoint",
    severity: "medium" as const,
    fix: "Add MIME type checking and file extension whitelist",
    snippet: `app.post('/upload', (req, res) => {\n  const file = req.files.document;\n  file.mv('./uploads/' + file.name);\n});`,
  },
  {
    file: ".env",
    issue: "Hardcoded API secret exposed in environment file",
    severity: "critical" as const,
    fix: "Use a secrets manager and add .env to .gitignore",
    snippet: `API_SECRET=sk_live_abc123xyz789`,
  },
  {
    file: "src/utils/crypto.ts",
    issue: "Weak hashing algorithm MD5 used for password storage",
    severity: "high" as const,
    fix: "Use bcrypt or argon2 for password hashing",
    snippet: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
  },
];

const VulnerabilitiesPage = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold mb-1">Vulnerability Reports</h1>
      <p className="text-sm text-muted-foreground">{vulns.length} vulnerabilities detected across repositories.</p>
    </div>
    <div className="grid gap-4 md:grid-cols-2">
      {vulns.map((v, i) => (
        <VulnerabilityCard key={i} {...v} />
      ))}
    </div>
  </div>
);

export default VulnerabilitiesPage;
