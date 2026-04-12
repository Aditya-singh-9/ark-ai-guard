import { useState, useRef, useCallback } from "react";
import { Upload, Code2, FileArchive, X, Play, Shield, AlertTriangle, CheckCircle, Loader2, ChevronDown } from "lucide-react";
import { toast } from "sonner";

const configUrl = import.meta.env.VITE_API_URL;
const API_BASE = configUrl 
  ? (configUrl.endsWith("/api/v1") ? configUrl : `${configUrl.replace(/\/$/, "")}/api/v1`)
  : "http://localhost:8000/api/v1";

type ScanMode = "zip" | "snippet";
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

const SNIPPET_EXAMPLES: Record<Language, string> = {
  python: `import sqlite3\n\n# ⚠️ SQL injection vulnerability\ndef get_user(username: str):\n    conn = sqlite3.connect('users.db')\n    cursor = conn.cursor()\n    query = f"SELECT * FROM users WHERE username = '{username}'"\n    cursor.execute(query)\n    return cursor.fetchall()\n\n# ⚠️ Hardcoded secret\nAPI_KEY = "sk-1234567890abcdef"\n`,
  javascript: `// ⚠️ XSS vulnerability\nfunction renderUser(input) {\n  document.getElementById('output').innerHTML = input;\n}\n\n// ⚠️ Hardcoded credentials\nconst dbPassword = "admin123";\nconst apiKey = "AIzaSy1234567890";\n`,
  typescript: `// ⚠️ Eval injection\nfunction calculate(expr: string): number {\n  return eval(expr);\n}\n\n// ⚠️ Prototype pollution\nfunction merge(target: any, source: any) {\n  for (const key of Object.keys(source)) {\n    target[key] = source[key];\n  }\n}\n`,
  java: `// ⚠️ Weak password hashing\nimport java.security.MessageDigest;\n\npublic class Auth {\n  public String hashPassword(String password) throws Exception {\n    MessageDigest md = MessageDigest.getInstance("MD5");\n    return new String(md.digest(password.getBytes()));\n  }\n}\n`,
  go: `// ⚠️ Command injection\npackage main\n\nimport (\n  "fmt"\n  "os/exec"\n)\n\nfunc runCommand(userInput string) {\n  cmd := exec.Command("sh", "-c", userInput)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}\n`,
  rust: `// ⚠️ Potential integer overflow\nfn add(a: i32, b: i32) -> i32 {\n    a + b  // Use checked_add() or saturating_add()\n}\n\n// ⚠️ Unwrap on potential error\nuse std::fs;\nfn read_file(path: &str) -> String {\n    fs::read_to_string(path).unwrap()\n}\n`,
  php: `<?php\n// ⚠️ SQL injection\n$user = $_GET['user'];\n$query = "SELECT * FROM users WHERE name = '$user'";\nmysql_query($query);\n\n// ⚠️ Remote file inclusion\n$page = $_GET['page'];\ninclude($page . '.php');\n`,
  ruby: `# ⚠️ System command injection\ndef run_report(filename)\n  system("cat #{filename}")\nend\n\n# ⚠️ Hardcoded secret\nSECRET_KEY = "my-super-secret-key-123"\n`,
};

export default function ManualScanPage() {
  const [mode, setMode] = useState<ScanMode>("snippet");
  const [language, setLanguage] = useState<Language>("python");
  const [code, setCode] = useState(SNIPPET_EXAMPLES.python);
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<null | { score: number; vulnerabilities: { severity: string; title: string; description: string; line?: number }[] }>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith(".zip")) {
      setZipFile(file);
    } else {
      toast.error("Please upload a .zip file");
    }
  }, []);

  const handleScan = async () => {
    setScanning(true);
    setResults(null);
    try {
      const token = localStorage.getItem("ark_jwt");
      if (mode === "snippet") {
        const res = await fetch(`${API_BASE}/scan/snippet`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify({ code, language }),
        });
        if (!res.ok) {
          // Fallback: simulate client-side basic scan
          const mockResults = simulateScan(code, language);
          setResults(mockResults);
          toast.info("Using local scan engine (backend endpoint not yet available)");
          return;
        }
        const data = await res.json();
        setResults(data);
      } else if (zipFile) {
        const formData = new FormData();
        formData.append("file", zipFile);
        const res = await fetch(`${API_BASE}/scan/upload`, {
          method: "POST",
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          body: formData,
        });
        if (!res.ok) {
          toast.error("Zip scanning requires a connected repository. Use the snippet scanner instead.");
          return;
        }
        const data = await res.json();
        setResults(data);
      }
    } catch {
      const mockResults = simulateScan(code, language);
      setResults(mockResults);
      toast.info("Showing demo results — connect backend to get real AI-powered scans");
    } finally {
      setScanning(false);
    }
  };

  // Client-side basic pattern scanner (demo fallback)
  const simulateScan = (src: string, lang: Language) => {
    const vulns = [];
    const patterns = [
      { re: /eval\s*\(/, title: "Code Injection via eval()", severity: "critical", desc: "Use of eval() can execute arbitrary code. Replace with safe alternatives." },
      { re: /innerHTML\s*=/, title: "XSS via innerHTML", severity: "high", desc: "Setting innerHTML with user data enables XSS attacks. Use textContent instead." },
      { re: /(password|secret|api_key|token)\s*=\s*['"][^'"]{8,}/i, title: "Hardcoded Secret Detected", severity: "critical", desc: "Secrets must be stored in environment variables, not in source code." },
      { re: /MD5|SHA1|md5\(|sha1\(/i, title: "Weak Cryptographic Hash", severity: "high", desc: "MD5/SHA1 are cryptographically broken. Use SHA-256 or bcrypt for passwords." },
      { re: /SELECT\s+\*?\s+FROM.*\$\{|SELECT.*\+\s*[a-z]/i, title: "SQL Injection Risk", severity: "critical", desc: "String concatenation in SQL queries allows injection. Use parameterized queries." },
      { re: /exec\s*\(|system\s*\(|shell_exec|subprocess\.call.*shell=True/i, title: "Command Injection Risk", severity: "critical", desc: "Unvalidated input in shell commands allows command injection attacks." },
      { re: /\.unwrap\(\)/, title: "Unhandled Error (unwrap)", severity: "medium", desc: "unwrap() panics on None/Err. Use proper error handling with match or ?." },
      { re: /pickle\.loads|yaml\.load\s*\([^,]+\)/, title: "Deserialization Vulnerability", severity: "high", desc: "Unsafe deserialization can lead to RCE. Use safe loaders." },
    ];

    const lines = src.split("\n");
    patterns.forEach(p => {
      lines.forEach((line, i) => {
        if (p.re.test(line)) {
          vulns.push({ severity: p.severity as "critical" | "high" | "medium" | "low", title: p.title, description: p.desc, line: i + 1 });
        }
      });
    });

    const critical = vulns.filter(v => v.severity === "critical").length;
    const high = vulns.filter(v => v.severity === "high").length;
    const score = Math.max(0, 100 - (critical * 20) - (high * 10) - (vulns.length * 3));
    return { score, vulnerabilities: vulns, language: lang };
  };

  const severityColors = { critical: "text-red-400 bg-red-500/10 border-red-500/20", high: "text-orange-400 bg-orange-500/10 border-orange-500/20", medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20", low: "text-blue-400 bg-blue-500/10 border-blue-500/20" };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-purple-500/30 flex items-center justify-center">
              <Code2 className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Manual Code Scanner</h1>
              <p className="text-sm text-gray-400">Paste code or upload a zip file — no GitHub required</p>
            </div>
          </div>
          <div className="inline-flex items-center gap-2 mt-3 px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-xs text-amber-400">
            <Shield className="w-3.5 h-3.5" /> Connect GitHub for deep AI-powered scanning with full repo context
          </div>
        </div>

        {/* Mode Tabs */}
        <div className="flex gap-2 mb-6 p-1 bg-white/5 rounded-xl w-fit">
          {[{ id: "snippet", icon: Code2, label: "Code Snippet" }, { id: "zip", icon: FileArchive, label: "Upload ZIP" }].map(tab => (
            <button
              key={tab.id}
              onClick={() => setMode(tab.id as ScanMode)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${mode === tab.id ? "bg-purple-600 text-white shadow-lg shadow-purple-500/20" : "text-gray-400 hover:text-white"}`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Panel */}
          <div className="space-y-4">
            {mode === "snippet" ? (
              <>
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-gray-300">Language</label>
                  <div className="relative">
                    <select
                      value={language}
                      onChange={e => {
                        const lang = e.target.value as Language;
                        setLanguage(lang);
                        setCode(SNIPPET_EXAMPLES[lang]);
                      }}
                      className="appearance-none pl-3 pr-8 py-1.5 rounded-lg bg-white/5 border border-white/10 text-sm text-white focus:outline-none focus:border-purple-500 cursor-pointer"
                    >
                      {LANGUAGES.map(l => <option key={l.value} value={l.value} className="bg-gray-900">{l.label}</option>)}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
                  </div>
                </div>
                <div className="relative">
                  <textarea
                    value={code}
                    onChange={e => setCode(e.target.value)}
                    className="w-full h-80 font-mono text-xs bg-[#0d0d16] border border-white/10 rounded-xl p-4 text-green-300 placeholder-gray-600 focus:outline-none focus:border-purple-500 resize-none leading-relaxed"
                    placeholder="Paste your code here..."
                    spellCheck={false}
                  />
                  <div className="absolute bottom-3 right-3 flex gap-2">
                    <button onClick={() => setCode("")} className="p-1.5 rounded-lg hover:bg-white/10 text-gray-500 hover:text-white transition-all" title="Clear">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-600">{code.split("\n").length} lines · {code.length} characters</p>
              </>
            ) : (
              <div
                onDrop={handleDrop}
                onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onClick={() => fileInputRef.current?.click()}
                className={`flex flex-col items-center justify-center h-80 border-2 border-dashed rounded-xl cursor-pointer transition-all ${isDragging ? "border-purple-400 bg-purple-500/10" : "border-white/10 hover:border-purple-500/50 hover:bg-white/5"}`}
              >
                <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) setZipFile(f); }} />
                {zipFile ? (
                  <div className="text-center">
                    <FileArchive className="w-12 h-12 text-purple-400 mx-auto mb-3" />
                    <p className="font-medium text-white">{zipFile.name}</p>
                    <p className="text-sm text-gray-400 mt-1">{(zipFile.size / 1024 / 1024).toFixed(2)} MB</p>
                    <button onClick={e => { e.stopPropagation(); setZipFile(null); }} className="mt-3 text-xs text-red-400 hover:text-red-300">Remove file</button>
                  </div>
                ) : (
                  <div className="text-center">
                    <Upload className="w-12 h-12 text-gray-500 mx-auto mb-3" />
                    <p className="font-medium text-gray-300">Drop your .zip file here</p>
                    <p className="text-sm text-gray-500 mt-1">or click to browse</p>
                    <p className="text-xs text-gray-600 mt-3">Supports zip archives up to 50MB</p>
                  </div>
                )}
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={scanning || (mode === "zip" && !zipFile) || (mode === "snippet" && !code.trim())}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-semibold hover:from-purple-500 hover:to-cyan-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-purple-500/20 hover:scale-[1.01]"
            >
              {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</> : <><Play className="w-4 h-4" /> Run Security Scan</>}
            </button>
          </div>

          {/* Results Panel */}
          <div>
            {!results && !scanning && (
              <div className="flex flex-col items-center justify-center h-80 bg-white/3 border border-white/5 rounded-xl text-center">
                <Shield className="w-12 h-12 text-gray-600 mb-3" />
                <p className="text-gray-400 font-medium">Results will appear here</p>
                <p className="text-sm text-gray-600 mt-1">Paste code and click "Run Security Scan"</p>
              </div>
            )}

            {scanning && (
              <div className="flex flex-col items-center justify-center h-80 bg-white/3 border border-purple-500/20 rounded-xl">
                <Loader2 className="w-10 h-10 text-purple-400 animate-spin mb-4" />
                <p className="text-gray-300 font-medium">Analyzing code...</p>
                <p className="text-sm text-gray-500 mt-1">Running pattern detection + AI analysis</p>
              </div>
            )}

            {results && (
              <div className="space-y-4">
                {/* Score */}
                <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-medium text-gray-300">Security Score</span>
                    <span className={`text-2xl font-bold ${results.score >= 80 ? "text-green-400" : results.score >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                      {results.score}/100
                    </span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-1000 ${results.score >= 80 ? "bg-green-500" : results.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                      style={{ width: `${results.score}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-2 mt-3 text-sm">
                    {results.vulnerabilities.length === 0 ? (
                      <span className="flex items-center gap-1.5 text-green-400"><CheckCircle className="w-4 h-4" /> No issues detected</span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-orange-400"><AlertTriangle className="w-4 h-4" /> {results.vulnerabilities.length} issue{results.vulnerabilities.length !== 1 ? "s" : ""} found</span>
                    )}
                  </div>
                </div>

                {/* Vulnerabilities */}
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {results.vulnerabilities.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                      <p>Clean scan — no vulnerabilities found!</p>
                    </div>
                  ) : (
                    results.vulnerabilities.map((v, i) => (
                      <div key={i} className={`border rounded-xl p-3.5 ${severityColors[v.severity as keyof typeof severityColors]}`}>
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <span className="font-medium text-sm">{v.title}</span>
                          <div className="flex items-center gap-2 shrink-0">
                            {v.line && <span className="text-xs opacity-60">Line {v.line}</span>}
                            <span className={`text-xs uppercase font-bold tracking-wide px-2 py-0.5 rounded-full border ${severityColors[v.severity as keyof typeof severityColors]}`}>{v.severity}</span>
                          </div>
                        </div>
                        <p className="text-xs opacity-70 leading-relaxed">{v.description}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
