import VulnerabilityCard from "@/components/dashboard/VulnerabilityCard";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, Filter, Search } from "lucide-react";
import { useState } from "react";

const vulns = [
  {
    file: "src/auth/login.ts",
    issue: "SQL Injection vulnerability in user authentication query — untrusted user input fed directly into SQL string.",
    severity: "critical" as const,
    fix: "Use parameterized queries or an ORM instead of string concatenation",
    snippet: `const query = "SELECT * FROM users WHERE email = '" + email + "'";`,
  },
  {
    file: "package.json",
    issue: "Outdated dependency 'lodash@4.17.15' with known prototype pollution vulnerability (CVE-2020-8203).",
    severity: "high" as const,
    fix: "Update lodash to version 4.17.21 or later via: npm update lodash",
    snippet: `"lodash": "^4.17.15"`,
  },
  {
    file: "src/api/upload.ts",
    issue: "Missing MIME type and file extension validation on the upload endpoint allows arbitrary file execution.",
    severity: "medium" as const,
    fix: "Add MIME type checking and whitelist allowed extensions before processing uploads",
    snippet: `app.post('/upload', (req, res) => {\n  const file = req.files.document;\n  file.mv('./uploads/' + file.name);\n});`,
  },
  {
    file: ".env",
    issue: "Hardcoded API secret exposed in version-controlled environment file. This credential may be compromised.",
    severity: "critical" as const,
    fix: "Use a secrets manager (Vault, AWS Secrets Manager) and add .env to .gitignore immediately",
    snippet: `API_SECRET=sk_live_abc123xyz789\nDB_PASSWORD=my_prod_pass123`,
  },
  {
    file: "src/utils/crypto.ts",
    issue: "MD5 hashing algorithm used for password storage. MD5 is cryptographically broken and unsuitable for passwords.",
    severity: "high" as const,
    fix: "Replace with bcrypt (cost factor ≥ 12) or argon2id for password hashing",
    snippet: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
  },
  {
    file: "src/middleware/cors.ts",
    issue: "Wildcard CORS policy allows unauthorized cross-origin requests from any domain.",
    severity: "medium" as const,
    fix: "Restrict CORS origin to trusted domains using an allowlist",
    snippet: `app.use(cors({ origin: '*' }));`,
  },
];

const counts = {
  critical: vulns.filter((v) => v.severity === "critical").length,
  high: vulns.filter((v) => v.severity === "high").length,
  medium: vulns.filter((v) => v.severity === "medium").length,
  low: vulns.filter((v) => v.severity === "low").length,
};

const VulnerabilitiesPage = () => {
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? vulns : vulns.filter((v) => v.severity === filter);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Vulnerability Reports</h1>
        <p className="text-sm text-muted-foreground">{vulns.length} vulnerabilities detected across repositories.</p>
      </div>

      {/* Summary bar */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 sm:grid-cols-4 gap-3"
      >
        {[
          { label: "Critical", count: counts.critical, color: "text-critical", bg: "bg-critical/10 border-critical/30" },
          { label: "High", count: counts.high, color: "text-warning", bg: "bg-warning/10 border-warning/30" },
          { label: "Medium", count: counts.medium, color: "text-neon-blue", bg: "bg-neon-blue/10 border-neon-blue/30" },
          { label: "Low", count: counts.low, color: "text-neon-green", bg: "bg-neon-green/10 border-neon-green/30" },
        ].map((item) => (
          <button
            key={item.label}
            onClick={() => setFilter(filter === item.label.toLowerCase() ? "all" : item.label.toLowerCase())}
            className={`glass rounded-xl p-4 text-center border transition-all hover:-translate-y-0.5 ${item.bg} ${
              filter === item.label.toLowerCase() ? "ring-1 ring-current" : ""
            }`}
          >
            <div className={`text-2xl font-bold ${item.color}`}>{item.count}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{item.label}</div>
          </button>
        ))}
      </motion.div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <Shield className="w-4 h-4 text-muted-foreground" />
        <span className="text-xs text-muted-foreground">Filter:</span>
        {["all", "critical", "high", "medium", "low"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-all ${
              filter === f
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:bg-muted/80"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Vulnerability cards */}
      <div className="grid gap-4 md:grid-cols-2">
        {filtered.map((v, i) => (
          <VulnerabilityCard key={i} {...v} index={i} />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-16 text-muted-foreground">
          <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No vulnerabilities of this severity level.</p>
        </div>
      )}
    </div>
  );
};

export default VulnerabilitiesPage;
