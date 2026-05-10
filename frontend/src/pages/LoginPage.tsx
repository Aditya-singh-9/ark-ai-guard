import { useState, useRef, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Shield, Mail, Lock, Eye, EyeOff, Github, ArrowRight, Loader2,
  Upload, Code2, FileArchive, X, Play, AlertTriangle, CheckCircle,
  ChevronDown, Zap, ExternalLink
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { githubOAuthUrl } from "@/lib/api";
import { toast } from "sonner";

const configUrl = import.meta.env.VITE_API_URL;
const API_BASE = configUrl
  ? (configUrl.endsWith("/api/v1") ? configUrl : `${configUrl.replace(/\/$/, "")}/api/v1`)
  : "http://localhost:8000/api/v1";

type Language = "python" | "javascript" | "typescript" | "java" | "go" | "rust" | "php" | "ruby";
const LANGUAGES: { value: Language; label: string }[] = [
  { value: "python", label: "Python" },
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "java", label: "Java" },
  { value: "go", label: "Go" },
  { value: "rust", label: "Rust" },
  { value: "php", label: "PHP" },
  { value: "ruby", label: "Ruby" },
];

const SNIPPET_EXAMPLE = `import sqlite3\n\n# SQL injection vulnerability\ndef get_user(username: str):\n    conn = sqlite3.connect('users.db')\n    cursor = conn.cursor()\n    query = f"SELECT * FROM users WHERE username = '{username}'"\n    cursor.execute(query)\n    return cursor.fetchall()\n\n# Hardcoded secret\nAPI_KEY = "sk-1234567890abcdef"\n`;

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
};

// ── Quick Scan Panel (no login required) ─────────────────────────────────────

function QuickScanPanel() {
  const [mode, setMode] = useState<"snippet" | "zip">("snippet");
  const [code, setCode] = useState(SNIPPET_EXAMPLE);
  const [language, setLanguage] = useState<Language>("python");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<null | {
    score: number;
    vulnerabilities: { severity: string; title: string; description: string; line?: number; file?: string }[];
    files_scanned?: number;
    critical_count: number;
    high_count: number;
  }>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file?.name.endsWith(".zip")) setZipFile(file);
    else toast.error("Please drop a .zip file");
  }, []);

  // Client-side fallback scanner
  const simulateScan = (src: string, lang: Language) => {
    const patterns = [
      { re: /eval\s*\(/, title: "Code Injection via eval()", severity: "critical", desc: "Replace eval() with safe alternatives." },
      { re: /innerHTML\s*=/, title: "XSS via innerHTML", severity: "high", desc: "Use textContent instead of innerHTML." },
      { re: /(password|secret|api_key|token)\s*=\s*['"][^'"]{8,}/i, title: "Hardcoded Secret", severity: "critical", desc: "Store secrets in environment variables." },
      { re: /MD5|SHA1|md5\(|sha1\(/i, title: "Weak Cryptographic Hash", severity: "high", desc: "Use SHA-256 or bcrypt instead." },
      { re: /SELECT\s+\*?\s+FROM.*(\$\{|'\s*\+)/i, title: "SQL Injection Risk", severity: "critical", desc: "Use parameterized queries." },
      { re: /exec\s*\(|system\s*\(|subprocess\.call.*shell=True/i, title: "Command Injection", severity: "critical", desc: "Validate all shell command inputs." },
    ];
    const vulns: { severity: string; title: string; description: string; line: number }[] = [];
    src.split("\n").forEach((line, i) => {
      patterns.forEach(p => {
        if (p.re.test(line)) vulns.push({ severity: p.severity, title: p.title, description: p.desc, line: i + 1 });
      });
    });
    const critical = vulns.filter(v => v.severity === "critical").length;
    const high = vulns.filter(v => v.severity === "high").length;
    return { score: Math.max(0, 100 - critical * 20 - high * 10 - vulns.length * 3), vulnerabilities: vulns, critical_count: critical, high_count: high };
  };

  const handleScan = async () => {
    setScanning(true);
    setResults(null);
    try {
      if (mode === "snippet") {
        const res = await fetch(`${API_BASE}/scan/snippet`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code, language }),
        });
        if (!res.ok) {
          const mock = simulateScan(code, language);
          setResults(mock);
          toast.info("Using client-side scanner (backend offline)");
          return;
        }
        setResults(await res.json());
        toast.success("Scan complete!");
      } else if (zipFile) {
        const form = new FormData();
        form.append("file", zipFile);
        const res = await fetch(`${API_BASE}/scan/upload`, { method: "POST", body: form });
        if (!res.ok) {
          const detail = await res.json().catch(() => ({ detail: "Upload failed" }));
          toast.error(detail.detail || "Upload scan failed");
          return;
        }
        setResults(await res.json());
        toast.success("ZIP scan complete!");
      }
    } catch {
      const mock = simulateScan(code, language);
      setResults(mock);
      toast.info("Using offline scanner — connect backend for AI-powered results");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="mt-8 bg-white/3 border border-white/8 rounded-2xl p-6 backdrop-blur-sm">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center">
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">Try it now — no account needed</h2>
          <p className="text-xs text-gray-500">Paste code or upload a .zip to scan instantly</p>
        </div>
      </div>

      {/* Mode Tabs */}
      <div className="flex gap-1.5 mb-4 p-1 bg-white/5 rounded-lg w-fit">
        {[
          { id: "snippet", icon: Code2, label: "Paste Code" },
          { id: "zip", icon: FileArchive, label: "Upload ZIP" },
        ].map(tab => (
          <button
            key={tab.id}
            id={`quick-scan-tab-${tab.id}`}
            onClick={() => setMode(tab.id as "snippet" | "zip")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              mode === tab.id ? "bg-purple-600 text-white shadow-lg shadow-purple-500/20" : "text-gray-400 hover:text-white"
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4">
        {/* Input */}
        {mode === "snippet" ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-gray-400">Language</label>
              <div className="relative">
                <select
                  id="quick-scan-language"
                  value={language}
                  onChange={e => setLanguage(e.target.value as Language)}
                  className="appearance-none pl-2 pr-6 py-1 rounded-md bg-white/5 border border-white/10 text-xs text-white focus:outline-none focus:border-purple-500 cursor-pointer"
                >
                  {LANGUAGES.map(l => <option key={l.value} value={l.value} className="bg-gray-900">{l.label}</option>)}
                </select>
                <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
              </div>
            </div>
            <div className="relative">
              <textarea
                id="quick-scan-code"
                value={code}
                onChange={e => setCode(e.target.value)}
                className="w-full h-44 font-mono text-xs bg-[#0d0d16] border border-white/10 rounded-xl p-3 text-green-300 placeholder-gray-600 focus:outline-none focus:border-purple-500 resize-none leading-relaxed"
                placeholder="Paste your code here..."
                spellCheck={false}
              />
              <button
                onClick={() => setCode("")}
                className="absolute bottom-2 right-2 p-1 rounded-md hover:bg-white/10 text-gray-600 hover:text-white transition-all"
                title="Clear"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ) : (
          <div
            onDrop={handleDrop}
            onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onClick={() => fileRef.current?.click()}
            className={`flex flex-col items-center justify-center h-36 border-2 border-dashed rounded-xl cursor-pointer transition-all ${
              isDragging ? "border-purple-400 bg-purple-500/10" : "border-white/10 hover:border-purple-500/40 hover:bg-white/3"
            }`}
          >
            <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) setZipFile(f); }} />
            {zipFile ? (
              <div className="text-center">
                <FileArchive className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                <p className="text-sm font-medium text-white">{zipFile.name}</p>
                <p className="text-xs text-gray-500 mt-0.5">{(zipFile.size / 1024 / 1024).toFixed(2)} MB</p>
                <button onClick={e => { e.stopPropagation(); setZipFile(null); }} className="mt-2 text-xs text-red-400 hover:text-red-300">Remove</button>
              </div>
            ) : (
              <div className="text-center">
                <Upload className="w-8 h-8 text-gray-500 mx-auto mb-2" />
                <p className="text-sm text-gray-400">Drop your .zip file here</p>
                <p className="text-xs text-gray-600 mt-1">or click to browse · max 10MB</p>
              </div>
            )}
          </div>
        )}

        <button
          id="quick-scan-run-btn"
          onClick={handleScan}
          disabled={scanning || (mode === "zip" && !zipFile) || (mode === "snippet" && !code.trim())}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-semibold text-sm hover:from-purple-500 hover:to-cyan-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-purple-500/20 hover:scale-[1.01]"
        >
          {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</> : <><Play className="w-4 h-4" /> Run Security Scan</>}
        </button>

        {/* Results */}
        {results && (
          <div className="space-y-3 border-t border-white/8 pt-4">
            {/* Score bar */}
            <div className="bg-white/5 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-gray-400">Security Score</span>
                <span className={`text-xl font-bold ${results.score >= 80 ? "text-green-400" : results.score >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                  {results.score}/100
                </span>
              </div>
              <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-1000 ${results.score >= 80 ? "bg-green-500" : results.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                  style={{ width: `${results.score}%` }}
                />
              </div>
              <div className="flex items-center gap-2 mt-2 text-xs">
                {results.vulnerabilities.length === 0 ? (
                  <span className="flex items-center gap-1 text-green-400"><CheckCircle className="w-3.5 h-3.5" /> Clean! No issues found</span>
                ) : (
                  <span className="flex items-center gap-1 text-orange-400"><AlertTriangle className="w-3.5 h-3.5" /> {results.vulnerabilities.length} issue{results.vulnerabilities.length !== 1 ? "s" : ""} found</span>
                )}
                {"files_scanned" in results && results.files_scanned !== undefined && (
                  <span className="text-gray-600">· {results.files_scanned} files scanned</span>
                )}
              </div>
            </div>

            {/* Vulnerability list */}
            {results.vulnerabilities.length > 0 && (
              <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                {results.vulnerabilities.slice(0, 10).map((v, i) => (
                  <div key={i} className={`border rounded-lg p-3 ${SEV_COLORS[v.severity] ?? "text-gray-400 bg-white/5 border-white/10"}`}>
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <span className="font-medium text-xs">{v.title}</span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {v.file && <span className="text-xs opacity-50 truncate max-w-[100px]">{v.file.split("/").pop()}</span>}
                        {v.line && <span className="text-xs opacity-60">:{v.line}</span>}
                        <span className={`text-xs uppercase font-bold tracking-wide px-1.5 py-0.5 rounded border ${SEV_COLORS[v.severity]}`}>{v.severity}</span>
                      </div>
                    </div>
                    <p className="text-xs opacity-70 leading-relaxed">{v.description}</p>
                  </div>
                ))}
                {results.vulnerabilities.length > 10 && (
                  <p className="text-center text-xs text-gray-600 py-1">
                    + {results.vulnerabilities.length - 10} more issues — <Link to="/dashboard/manual-scan" className="text-purple-400 hover:underline">view all in full scanner</Link>
                  </p>
                )}
              </div>
            )}

            <p className="text-center text-xs text-gray-600">
              <Link to="/register" className="text-purple-400 hover:text-purple-300">Create a free account</Link>
              {" "}for AI-powered deep scans with full repo analysis
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Login Page ────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showQuickScan, setShowQuickScan] = useState(false);

  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : data.message || `Error ${res.status}: Login failed`
        );
      }
      if (!data.access_token || !data.user) {
        throw new Error("Invalid server response. Please try again.");
      }
      login(data.access_token, data.user);
      toast.success(`Welcome back, ${data.user.display_name ?? data.user.username}! 🎉`);
      navigate("/dashboard");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Login failed. Please check your email and password.";
      toast.error(msg);
      console.error("[Login Error]", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-start justify-center p-4 py-10">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-purple-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-purple-500/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-white">DevScops Guard</span>
          </Link>
          <h1 className="mt-6 text-2xl font-bold text-white">Welcome back</h1>
          <p className="mt-1 text-sm text-gray-400">Sign in to your account to continue</p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-sm shadow-2xl">
          {/* GitHub Login — Primary */}
          <a
            id="github-login-btn"
            href={githubOAuthUrl()}
            className="flex items-center justify-center gap-3 w-full py-3 px-4 rounded-xl bg-white text-gray-900 font-semibold text-sm hover:bg-gray-100 transition-all duration-200 shadow-lg hover:shadow-xl hover:scale-[1.02] active:scale-[0.98]"
          >
            <Github className="w-5 h-5" />
            Continue with GitHub
            <span className="ml-auto text-xs text-gray-500 font-normal bg-gray-100 px-2 py-0.5 rounded-full">Recommended</span>
          </a>

          {/* Divider */}
          <div className="flex items-center my-6 gap-3">
            <div className="flex-1 h-px bg-white/10" />
            <span className="text-xs text-gray-500 uppercase tracking-wider">or sign in with email</span>
            <div className="flex-1 h-px bg-white/10" />
          </div>

          {/* Email/Password Form */}
          <form onSubmit={handleEmailLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Email address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  autoComplete="email"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 transition-all"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-sm font-medium text-gray-300">Password</label>
                <Link
                  to="/forgot-password"
                  className="text-xs text-purple-400 hover:text-purple-300 transition-colors"
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                  className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              id="login-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-semibold text-sm hover:from-purple-500 hover:to-cyan-500 transition-all duration-200 shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40 disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-[0.98]"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-gray-500">
            Don't have an account?{" "}
            <Link to="/register" className="text-purple-400 hover:text-purple-300 font-medium transition-colors">
              Create one free
            </Link>
          </p>

          {/* Try Without Login toggle */}
          <div className="mt-4 text-center">
            <button
              id="try-without-login-btn"
              onClick={() => setShowQuickScan(v => !v)}
              className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-cyan-400 transition-colors"
            >
              <Zap className="w-3.5 h-3.5" />
              {showQuickScan ? "Hide quick scanner" : "Try scanning code without signing in"}
              <ExternalLink className="w-3 h-3 opacity-60" />
            </button>
          </div>
        </div>

        {/* Quick Scan Panel */}
        {showQuickScan && <QuickScanPanel />}

        <p className="mt-6 text-center text-xs text-gray-600">
          By signing in, you agree to our{" "}
          <span className="text-gray-500 hover:text-gray-400 cursor-pointer">Terms of Service</span>
          {" "}and{" "}
          <span className="text-gray-500 hover:text-gray-400 cursor-pointer">Privacy Policy</span>
        </p>
      </div>
    </div>
  );
}
