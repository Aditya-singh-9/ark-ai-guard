import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Search, RefreshCw, CheckCircle, XCircle, Clock,
  AlertTriangle, Play, GitBranch, X, Zap, ChevronRight,
  TrendingDown, Activity, Lock, Download, Upload, Code2,
  FileArchive, Github, ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState, useEffect, useRef, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  getRepositories, scanRepository, getScanStatus, getDashboardStats,
  getReportDownloadUrl, downloadSecureFile, API_BASE
} from "@/lib/api";
import { toast } from "sonner";
import { Link } from "react-router-dom";

type ScanModalTab = "github" | "zip" | "snippet";
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

// ── Status config ──────────────────────────────────────────────────────────────

const statusConfig = {
  completed: { icon: CheckCircle, color: "text-neon-green", bg: "bg-neon-green/10 border-neon-green/30", label: "Completed" },
  failed: { icon: XCircle, color: "text-critical", bg: "bg-critical/10 border-critical/30", label: "Failed" },
  running: { icon: RefreshCw, color: "text-neon-cyan", bg: "bg-neon-cyan/10 border-neon-cyan/30", label: "Scanning…" },
  pending: { icon: RefreshCw, color: "text-warning", bg: "bg-warning/10 border-warning/30", label: "Queued" },
  never_scanned: { icon: GitBranch, color: "text-muted-foreground", bg: "bg-muted/10 border-border/30", label: "Never Scanned" },
};

// ── Status metadata mapped from real backend events ─────────────────────────

const getStatusMeta = (status: string | null | undefined): { progress: number; label: string; isRunning: boolean } => {
  switch (status) {
    case "pending": return { progress: 5, label: "Queued…", isRunning: true };
    case "cloning": return { progress: 20, label: "Cloning repository…", isRunning: true };
    case "scanning": return { progress: 50, label: "Running security scanners…", isRunning: true };
    case "analysing": return { progress: 80, label: "AI vulnerability analysis…", isRunning: true };
    case "finalising": return { progress: 95, label: "Finalising report…", isRunning: true };
    case "running": return { progress: 50, label: "Scanning…", isRunning: true }; // fallback
    case "completed": return { progress: 100, label: "Completed", isRunning: false };
    case "failed": return { progress: 100, label: "Failed", isRunning: false };
    default: return { progress: 0, label: "Never Scanned", isRunning: false };
  }
};

// ── ScanRow ────────────────────────────────────────────────────────────────────

const ScanRow = ({
  repo,
  index,
  initialScanId,
}: {
  repo: {
    id: number;
    name: string;
    url: string;
    language: string | null;
    last_scanned_at: string | null;
    security_score: number | null;
    total_vulnerabilities: number;
    scan_status: string;
    latest_scan_id?: number | null;
  };
  index: number;
  initialScanId?: number;
}) => {
  const queryClient = useQueryClient();
  const [activeScanId, setActiveScanId] = useState<number | null>(initialScanId ?? null);
  const [justCompleted, setJustCompleted] = useState(false);

  // Sync when the parent passes down a newly started scan id
  useEffect(() => {
    if (initialScanId && initialScanId !== activeScanId) {
      setActiveScanId(initialScanId);
    }
  }, [initialScanId]);

  // Poll scan status
  const { data: scanStatus } = useQuery({
    queryKey: ["scan-status", activeScanId],
    queryFn: () => getScanStatus(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d || !["completed", "failed"].includes(d.status)) return 2000;
      return false;
    },
  });

  // Derive state from API or local fallback
  const rawStatus = activeScanId ? (scanStatus?.status ?? repo.scan_status) : repo.scan_status;
  const meta = getStatusMeta(rawStatus);
  const isRunning = meta.isRunning || (activeScanId !== null);
  const progress = justCompleted ? 100 : meta.progress;

  // Handle completion
  useEffect(() => {
    if (scanStatus?.status === "completed" || scanStatus?.status === "failed") {
      setJustCompleted(true);
      setTimeout(() => {
        setActiveScanId(null);
        setJustCompleted(false);
        queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
        queryClient.invalidateQueries({ queryKey: ["repositories"] });
      }, 800); // let bar fill to 100% before clearing
      if (scanStatus.status === "completed") {
        toast.success(`✅ Scan completed! ${scanStatus.total_vulnerabilities} issues found.`);
      } else {
        toast.error("Scan failed. Check the repository and try again.");
      }
    }
  }, [scanStatus?.status, queryClient]);

  const scanMutation = useMutation({
    mutationFn: () => scanRepository(repo.id),
    onSuccess: (data) => {
      setActiveScanId(data.scan_id);
      toast.info(`🔍 Scan #${data.scan_id} started for ${repo.name}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const effectiveStatus = activeScanId
    ? (scanStatus?.status ?? "running")
    : repo.scan_status;

  const status = (isRunning ? "running" : effectiveStatus) as keyof typeof statusConfig;
  const cfg = statusConfig[status] ?? statusConfig.never_scanned;
  const score = repo.security_score;

  const scanStepLabel = isRunning
    ? activeScanId
      ? meta.label
      : "⏳ Starting scan…"
    : "";

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="px-5 py-4 hover:bg-muted/20 transition-colors"
    >
      <div className="flex items-center gap-4">
        {/* Status icon */}
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${cfg.bg} border flex-shrink-0`}>
          <cfg.icon className={`w-4 h-4 ${cfg.color} ${isRunning && !justCompleted ? "animate-spin" : ""}`} />
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm font-medium">{repo.name}</span>
            {repo.language && (
              <span className="text-[11px] text-muted-foreground font-mono bg-muted px-1.5 py-0.5 rounded">
                {repo.language}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleString() : "Never scanned"}
            </span>
            {repo.total_vulnerabilities > 0 && !isRunning && (
              <Link
                to={`/dashboard/vulns?repoId=${repo.id}`}
                className="text-xs text-warning flex items-center gap-1 hover:underline"
              >
                <AlertTriangle className="w-3 h-3" />
                {repo.total_vulnerabilities} vulns
              </Link>
            )}
          </div>

          {/* Live progress bar with step label */}
          <AnimatePresence>
            {(isRunning || justCompleted) && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.3 }}
                className="mt-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-neon-cyan font-mono truncate max-w-[200px]">
                    {justCompleted ? "✅ Complete!" : scanStepLabel}
                  </span>
                  <div className="flex gap-2 items-center">
                    {activeScanId && (
                      <Link 
                        to={`/dashboard/scans/${activeScanId}/deep`}
                        className="text-[10px] bg-violet-500/20 text-violet-400 px-2 py-0.5 rounded-full hover:bg-violet-500/30 transition-colors"
                      >
                        Watch Deep Scan →
                      </Link>
                    )}
                    <span className="text-[10px] text-muted-foreground font-mono">{progress.toFixed(0)}%</span>
                  </div>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <motion.div
                    className={`h-full rounded-full bg-gradient-to-r ${
                      justCompleted ? "from-neon-green to-neon-green/70" : "from-neon-cyan to-primary"
                    }`}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                  />
                </div>

                {/* Step indicators */}
                {!justCompleted && (
                  <div className="flex gap-1 mt-1.5">
                    {[20, 50, 80, 95].map((threshold, i) => (
                      <div
                        key={i}
                        className={`flex-1 h-0.5 rounded-full transition-colors duration-500 ${
                          progress >= threshold
                            ? "bg-neon-cyan"
                            : "bg-muted"
                        }`}
                      />
                    ))}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right side */}
        <div className="flex items-center gap-3 flex-shrink-0">
          {score !== null && !isRunning ? (
            <div className="text-right">
              <div className={`text-base font-bold ${score >= 80 ? "text-neon-green" : score >= 50 ? "text-warning" : "text-critical"}`}>
                {score.toFixed(0)}%
              </div>
              <div className="text-[10px] text-muted-foreground">score</div>
            </div>
          ) : null}
          <Badge variant="outline" className={`text-[10px] font-mono ${cfg.bg} hidden sm:flex`}>
            {cfg.label}
          </Badge>
          {!isRunning && (
            <button
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending}
              className="p-1.5 hover:bg-primary/10 hover:text-primary rounded-lg transition-colors text-muted-foreground"
              title="Scan now"
            >
              <Play className="w-3.5 h-3.5" />
            </button>
          )}
          {!isRunning && (
            <>
              <Link to={`/dashboard/vulns?repoId=${repo.id}`}>
                <button className="p-1.5 hover:bg-muted rounded-lg transition-colors text-muted-foreground" title="View report">
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </Link>
              <Link to={`/dashboard/scans/${scanStatus?.scan_id || repo.latest_scan_id}/deep`}>
                <button
                  className="p-1.5 hover:bg-violet-500/10 hover:text-violet-400 rounded-lg transition-colors text-muted-foreground ml-1"
                  title="Deep Scan Visualization"
                >
                  <Activity className="w-3.5 h-3.5" />
                </button>
              </Link>
            </>
          )}

          {!isRunning && effectiveStatus === "completed" && activeScanId === null && (
            <button
              onClick={async () => {
                const id = scanStatus?.scan_id || repo.latest_scan_id;
                if (id) {
                  try {
                    await downloadSecureFile(getReportDownloadUrl(id), `security-report-${repo.name}.html`);
                    toast.success("Downloaded HTML report!");
                  } catch (err: any) {
                    toast.error("Download failed: " + err.message);
                  }
                } else {
                  toast.info("Run a scan first to download the report.");
                }
              }}
              className="p-1.5 hover:bg-primary/10 hover:text-primary rounded-lg transition-colors text-muted-foreground"
              title="Download HTML report"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
};

// ── Custom modal select ────────────────────────────────────────────────────────

const ModalSelect = ({
  options, value, onChange,
}: {
  options: { label: string; value: number }[];
  value: number | null;
  onChange: (v: number | null) => void;
}) => (
  <div className="w-full glass border border-border/60 rounded-xl overflow-hidden mb-4 max-h-48 overflow-y-auto">
    {options.length === 0 ? (
      <div className="px-4 py-3 text-sm text-muted-foreground text-center">
        No repositories connected. Add one first.
      </div>
    ) : (
      options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value === value ? null : opt.value)}
          className={`w-full text-left px-4 py-3 text-sm font-mono transition-colors flex items-center justify-between ${
            value === opt.value ? "bg-primary/15 text-primary" : "hover:bg-muted/40 text-foreground/90"
          }`}
        >
          {opt.label}
          {value === opt.value && <CheckCircle className="w-3.5 h-3.5 text-primary flex-shrink-0" />}
        </button>
      ))
    )}
  </div>
);

// ── Security Posture Health Banner ─────────────────────────────────────────────

const HealthBanner = ({
  repos,
  isLoading,
}: {
  repos: { name: string; security_score: number | null; total_vulnerabilities: number; scan_status: string }[];
  isLoading: boolean;
}) => {
  if (isLoading || repos.length === 0) return null;

  const scanned = repos.filter((r) => r.security_score !== null);
  if (scanned.length === 0) return null;

  const avg = scanned.reduce((sum, r) => sum + (r.security_score ?? 0), 0) / scanned.length;
  const worstRepo = [...scanned].sort((a, b) => (a.security_score ?? 0) - (b.security_score ?? 0))[0];
  const totalCriticalVulns = repos.reduce((sum, r) => sum + (r.total_vulnerabilities ?? 0), 0);
  const goodCount = repos.filter((r) => (r.security_score ?? 0) >= 80).length;

  const posture = avg >= 80 ? "good" : avg >= 50 ? "warning" : "critical";
  const postureCfg = {
    good: { gradient: "from-neon-green/10 to-transparent", border: "border-neon-green/20", text: "text-neon-green", icon: Shield, label: "Healthy Posture" },
    warning: { gradient: "from-warning/10 to-transparent", border: "border-warning/20", text: "text-warning", icon: AlertTriangle, label: "Needs Attention" },
    critical: { gradient: "from-critical/10 to-transparent", border: "border-critical/20", text: "text-critical", icon: Lock, label: "Critical Risk" },
  }[posture];

  const PostureIcon = postureCfg.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass rounded-xl border ${postureCfg.border} bg-gradient-to-r ${postureCfg.gradient} p-4`}
    >
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl ${postureCfg.border} border flex items-center justify-center bg-black/20`}>
            <PostureIcon className={`w-5 h-5 ${postureCfg.text}`} />
          </div>
          <div>
            <p className={`text-sm font-bold ${postureCfg.text}`}>{postureCfg.label}</p>
            <p className="text-xs text-muted-foreground">Your security posture across {scanned.length} scanned repos</p>
          </div>
        </div>

        <div className="flex gap-6 ml-auto flex-wrap">
          <div className="text-center">
            <p className={`text-xl font-bold font-mono ${postureCfg.text}`}>{avg.toFixed(0)}%</p>
            <p className="text-[10px] text-muted-foreground">Avg Score</p>
          </div>
          <div className="text-center">
            <p className="text-xl font-bold font-mono text-critical">{totalCriticalVulns}</p>
            <p className="text-[10px] text-muted-foreground">Total Vulns</p>
          </div>
          <div className="text-center">
            <p className="text-xl font-bold font-mono text-neon-green">{goodCount}</p>
            <p className="text-[10px] text-muted-foreground">Secure Repos</p>
          </div>
          {worstRepo && (
            <div className="text-center">
              <p className="text-sm font-bold font-mono text-critical truncate max-w-24">{worstRepo.name}</p>
              <p className="text-[10px] text-muted-foreground">Weakest Repo</p>
            </div>
          )}
        </div>

        {posture !== "good" && (
          <div className="flex items-center gap-1 text-xs text-muted-foreground ml-auto">
            <TrendingDown className="w-3.5 h-3.5 text-critical" />
            <Link to="/dashboard/vulns" className="text-primary hover:underline">
              View vulnerabilities →
            </Link>
          </div>
        )}
      </div>
    </motion.div>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────────

const SecurityScansPage = () => {
  const [search, setSearch] = useState("");
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState<number | null>(null);
  const [hasActiveScans, setHasActiveScans] = useState(false);
  const [modalScanIds, setModalScanIds] = useState<Record<number, number>>({});
  const queryClient = useQueryClient();

  // ── Modal multi-mode state ─────────────────────────────────────────────────
  const [modalTab, setModalTab] = useState<ScanModalTab>("github");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [snippetCode, setSnippetCode] = useState("");
  const [snippetLang, setSnippetLang] = useState<Language>("python");
  const [quickScanLoading, setQuickScanLoading] = useState(false);
  const [quickScanResult, setQuickScanResult] = useState<null | { score: number; vulnerabilities: { severity: string; title: string; description: string; line?: number }[] }>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith(".zip")) {
      setZipFile(file);
    } else {
      toast.error("Please drop a .zip file");
    }
  }, []);

  const simulateSnippetScan = (src: string) => {
    const patterns = [
      { re: /eval\s*\(/, title: "Code Injection via eval()", severity: "critical", desc: "Use of eval() can execute arbitrary code." },
      { re: /innerHTML\s*=/, title: "XSS via innerHTML", severity: "high", desc: "Setting innerHTML with user data enables XSS attacks." },
      { re: /(password|secret|api_key|token)\s*=\s*['"][^'"]{8,}/i, title: "Hardcoded Secret", severity: "critical", desc: "Secrets must be stored in environment variables." },
      { re: /MD5|SHA1|md5\(|sha1\(/i, title: "Weak Hash Algorithm", severity: "high", desc: "MD5/SHA1 are broken. Use SHA-256 or bcrypt." },
      { re: /SELECT\s.*WHERE.*\$\{|SELECT.*\+\s*[a-z]/i, title: "SQL Injection Risk", severity: "critical", desc: "Use parameterized queries." },
      { re: /exec\s*\(|system\s*\(|shell_exec|subprocess\.call.*shell=True/i, title: "Command Injection", severity: "critical", desc: "Unvalidated shell input allows command injection." },
      { re: /\.unwrap\(\)/, title: "Unhandled Error (unwrap)", severity: "medium", desc: "unwrap() panics on None/Err. Use proper error handling." },
      { re: /pickle\.loads|yaml\.load\s*\([^,]+\)/, title: "Unsafe Deserialization", severity: "high", desc: "Unsafe deserialization can lead to RCE." },
    ];
    const vulns: { severity: string; title: string; description: string; line?: number }[] = [];
    src.split("\n").forEach((line, i) => {
      patterns.forEach(p => {
        if (p.re.test(line)) vulns.push({ severity: p.severity, title: p.title, description: p.desc, line: i + 1 });
      });
    });
    const critical = vulns.filter(v => v.severity === "critical").length;
    const high = vulns.filter(v => v.severity === "high").length;
    const score = Math.max(0, 100 - (critical * 20) - (high * 10) - (vulns.length * 3));
    return { score, vulnerabilities: vulns };
  };

  const handleQuickScan = async () => {
    setQuickScanLoading(true);
    setQuickScanResult(null);
    try {
      const token = localStorage.getItem("ark_jwt");
      if (modalTab === "snippet") {
        if (!snippetCode.trim()) { toast.error("Please paste some code first."); return; }
        try {
          const res = await fetch(`${API_BASE}/scan/snippet`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
            body: JSON.stringify({ code: snippetCode, language: snippetLang }),
          });
          if (res.ok) { setQuickScanResult(await res.json()); return; }
        } catch { /* fall through to local */ }
        setQuickScanResult(simulateSnippetScan(snippetCode));
        toast.info("Using local scan engine — connect backend for full AI analysis");
      } else if (modalTab === "zip") {
        if (!zipFile) { toast.error("Please select a ZIP file first."); return; }
        const formData = new FormData();
        formData.append("file", zipFile);
        try {
          const res = await fetch(`${API_BASE}/scan/upload`, {
            method: "POST",
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            body: formData,
          });
          if (res.ok) { setQuickScanResult(await res.json()); return; }
        } catch { /* fall through */ }
        toast.error("ZIP scan requires backend /scan/upload endpoint. Try snippet mode.");
      }
    } finally {
      setQuickScanLoading(false);
    }
  };

  const closeModal = () => {
    setShowScanModal(false);
    setModalTab("github");
    setZipFile(null);
    setSnippetCode("");
    setQuickScanResult(null);
  };

  const { data: stats, isLoading } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
    // Poll faster when scans are running, slower otherwise
    refetchInterval: hasActiveScans ? 5000 : 15000,
    staleTime: 4000,
  });

  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
    staleTime: 10000,  // Repo list rarely changes — don't refetch more than every 10s
  });


  const scanMutation = useMutation({
    mutationFn: (repoId: number) => scanRepository(repoId),
    onSuccess: (data, repoId) => {
      toast.success(`🔍 Scan #${data.scan_id} started!`);
      setModalScanIds((prev) => ({ ...prev, [repoId]: data.scan_id }));
      setShowScanModal(false);
      setHasActiveScans(true);
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const repoScans = stats?.repositories ?? [];
  const filtered = repoScans.filter((r) =>
    r.name.toLowerCase().includes(search.toLowerCase())
  );

  const totalScans = repoScans.length;
  const passed = repoScans.filter((r) => (r.security_score ?? 0) >= 70).length;
  const failed = repoScans.filter(
    (r) => r.scan_status === "failed" || (r.security_score !== null && r.security_score < 50)
  ).length;
  const hasRunning = repoScans.some(
    (r) => r.scan_status === "running" || r.scan_status === "pending"
  );

  // Sync hasActiveScans state from real data
  // eslint-disable-next-line react-hooks/exhaustive-deps
  if (hasRunning !== hasActiveScans) setHasActiveScans(hasRunning);


  return (
    <>
      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold mb-1">Security Scans</h1>
            <p className="text-sm text-muted-foreground flex items-center gap-2">
              Scan history and live status across all repositories.
              {hasRunning && (
                <span className="text-neon-cyan font-medium animate-pulse flex items-center gap-1">
                  <Activity className="w-3 h-3" /> Scan in progress…
                </span>
              )}
            </p>
          </div>
          <Button
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            onClick={() => setShowScanModal(true)}
          >
            <Zap className="w-4 h-4" />
            Run Scan
          </Button>
        </div>

        {/* Health Banner */}
        <HealthBanner repos={repoScans} isLoading={isLoading} />

        {/* Summary cards */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total Repos", value: totalScans, color: "text-foreground" },
            { label: "Passed (≥70%)", value: passed, color: "text-neon-green" },
            { label: "At Risk (<50%)", value: failed, color: "text-critical" },
          ].map((s) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl p-4 text-center"
            >
              <div className={`text-2xl font-bold ${s.color}`}>{isLoading ? "—" : s.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </motion.div>
          ))}
        </div>

        {/* Scan list */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass rounded-xl overflow-hidden"
        >
          <div className="p-4 border-b border-border/50 flex items-center justify-between">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              Repository Scan Status
              {hasRunning && (
                <span className="flex h-2 w-2 relative">
                  <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-neon-cyan opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-cyan" />
                </span>
              )}
            </h3>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                placeholder="Filter repos..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="bg-muted rounded-lg pl-8 pr-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-primary/60 w-44 font-mono"
              />
            </div>
          </div>

          {isLoading ? (
            <div className="p-6 space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-muted/30 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No repositories found.</p>
              <Link to="/dashboard/repos" className="text-xs text-primary hover:underline mt-1 inline-block">
                Add a repository →
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-border/30">
              {filtered.map((repo, i) => (
                <ScanRow
                  key={repo.id}
                  repo={repo}
                  index={i}
                  initialScanId={modalScanIds[repo.id]}
                />
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Run Scan Modal — 3 tabs */}
      <AnimatePresence>
        {showScanModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 12 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="glass rounded-2xl w-full max-w-lg border border-border/80 shadow-2xl overflow-hidden"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between px-5 pt-5 pb-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-primary/15 rounded-xl flex items-center justify-center">
                    <Zap className="w-4 h-4 text-primary" />
                  </div>
                  <h3 className="font-semibold text-base">Run Security Scan</h3>
                </div>
                <button onClick={closeModal} className="p-1.5 hover:bg-muted rounded-lg transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Tab Switcher */}
              <div className="flex gap-1 mx-5 mb-4 p-1 bg-black/30 rounded-xl">
                {([
                  { id: "github" as ScanModalTab, icon: Github, label: "GitHub Repo" },
                  { id: "zip" as ScanModalTab, icon: FileArchive, label: "Upload ZIP" },
                  { id: "snippet" as ScanModalTab, icon: Code2, label: "Paste Code" },
                ] as const).map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => { setModalTab(tab.id); setQuickScanResult(null); }}
                    className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      modalTab === tab.id ? "bg-primary text-white shadow-lg shadow-primary/20" : "text-muted-foreground hover:text-white"
                    }`}
                  >
                    <tab.icon className="w-3.5 h-3.5" />
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="px-5 pb-5">
                <AnimatePresence mode="wait">

                  {/* ── GitHub Repo Tab ─────────────────────────────────────── */}
                  {modalTab === "github" && (
                    <motion.div key="github" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }}>
                      <p className="text-sm text-muted-foreground mb-3">
                        Select a connected repository for a full 7-layer deep scan with AI-powered analysis.
                      </p>
                      <div className="text-xs text-muted-foreground font-mono mb-3">⏱ Estimated time: 1–3 minutes</div>
                      <ModalSelect
                        options={repos.map((r) => ({ label: r.full_name, value: r.id }))}
                        value={selectedRepo}
                        onChange={setSelectedRepo}
                      />
                      <div className="flex gap-2 justify-end mt-2">
                        <Button variant="outline" size="sm" onClick={closeModal}>Cancel</Button>
                        <Button
                          size="sm"
                          className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                          onClick={() => selectedRepo && scanMutation.mutate(selectedRepo)}
                          disabled={!selectedRepo || scanMutation.isPending}
                        >
                          {scanMutation.isPending ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                          {scanMutation.isPending ? "Starting…" : "Start Deep Scan"}
                        </Button>
                      </div>
                    </motion.div>
                  )}

                  {/* ── ZIP Upload Tab ─────────────────────────────────────── */}
                  {modalTab === "zip" && (
                    <motion.div key="zip" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }}>
                      <p className="text-sm text-muted-foreground mb-3">
                        Upload a <code className="text-primary">.zip</code> archive of your project — no GitHub connection needed.
                      </p>
                      <input ref={zipInputRef} type="file" accept=".zip" className="hidden"
                        onChange={e => { const f = e.target.files?.[0]; if (f) setZipFile(f); }} />
                      <div
                        onDrop={handleDrop}
                        onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                        onDragLeave={() => setIsDragging(false)}
                        onClick={() => zipInputRef.current?.click()}
                        className={`flex flex-col items-center justify-center h-36 border-2 border-dashed rounded-xl cursor-pointer transition-all mb-3 ${
                          isDragging ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/50 hover:bg-white/5"
                        }`}
                      >
                        {zipFile ? (
                          <div className="text-center">
                            <FileArchive className="w-8 h-8 text-primary mx-auto mb-2" />
                            <p className="text-sm font-medium text-white">{zipFile.name}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{(zipFile.size / 1024 / 1024).toFixed(2)} MB</p>
                            <button onClick={e => { e.stopPropagation(); setZipFile(null); }}
                              className="mt-1.5 text-xs text-red-400 hover:text-red-300">Remove</button>
                          </div>
                        ) : (
                          <div className="text-center">
                            <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                            <p className="text-sm text-muted-foreground">Drop .zip here or <span className="text-primary">browse</span></p>
                            <p className="text-xs text-muted-foreground/60 mt-1">Up to 50 MB</p>
                          </div>
                        )}
                      </div>

                      {/* ZIP Scan Result */}
                      {quickScanResult && <QuickScanResult result={quickScanResult} />}

                      <div className="flex gap-2 justify-end mt-2">
                        <Button variant="outline" size="sm" onClick={closeModal}>Close</Button>
                        <Button size="sm"
                          className="bg-gradient-to-r from-purple-600 to-cyan-600 text-white hover:opacity-90 gap-1.5"
                          onClick={handleQuickScan}
                          disabled={!zipFile || quickScanLoading}
                        >
                          {quickScanLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                          {quickScanLoading ? "Scanning…" : "Scan ZIP"}
                        </Button>
                      </div>
                    </motion.div>
                  )}

                  {/* ── Code Snippet Tab ───────────────────────────────────── */}
                  {modalTab === "snippet" && (
                    <motion.div key="snippet" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }}>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-sm text-muted-foreground">Paste code for instant security analysis.</p>
                        <div className="relative">
                          <select
                            value={snippetLang}
                            onChange={e => setSnippetLang(e.target.value as Language)}
                            className="appearance-none pl-2.5 pr-7 py-1 rounded-lg bg-muted/60 border border-border/60 text-xs text-white focus:outline-none focus:border-primary cursor-pointer"
                          >
                            {LANGUAGES.map(l => <option key={l.value} value={l.value} className="bg-gray-900">{l.label}</option>)}
                          </select>
                          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground pointer-events-none" />
                        </div>
                      </div>
                      <textarea
                        value={snippetCode}
                        onChange={e => setSnippetCode(e.target.value)}
                        placeholder="Paste your code here..."
                        spellCheck={false}
                        className="w-full h-44 font-mono text-xs bg-black/40 border border-border/50 rounded-xl p-3 text-green-300 placeholder-gray-600 focus:outline-none focus:border-primary resize-none leading-relaxed mb-1"
                      />
                      <p className="text-[10px] text-muted-foreground mb-3">
                        {snippetCode.split("\n").length} lines · {snippetCode.length} chars
                      </p>

                      {/* Snippet Scan Result */}
                      {quickScanResult && <QuickScanResult result={quickScanResult} />}

                      <div className="flex gap-2 justify-end">
                        <Button variant="outline" size="sm" onClick={closeModal}>Close</Button>
                        <Button size="sm"
                          className="bg-gradient-to-r from-purple-600 to-cyan-600 text-white hover:opacity-90 gap-1.5"
                          onClick={handleQuickScan}
                          disabled={!snippetCode.trim() || quickScanLoading}
                        >
                          {quickScanLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                          {quickScanLoading ? "Scanning…" : "Run Quick Scan"}
                        </Button>
                      </div>
                    </motion.div>
                  )}

                </AnimatePresence>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

// ── Quick Scan Result ─────────────────────────────────────────────────────────

function QuickScanResult({ result }: { result: { score: number; vulnerabilities: { severity: string; title: string; description: string; line?: number }[] } }) {
  const sevColors: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  };
  return (
    <div className="mb-3 space-y-2">
      <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/5 border border-white/10">
        <span className="text-xs text-muted-foreground font-medium">Security Score</span>
        <span className={`text-base font-bold ${
          result.score >= 80 ? "text-green-400" : result.score >= 60 ? "text-yellow-400" : "text-red-400"
        }`}>{result.score}/100</span>
      </div>
      {result.vulnerabilities.length === 0 ? (
        <p className="text-xs text-green-400 text-center py-2">✅ No issues detected!</p>
      ) : (
        <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
          {result.vulnerabilities.map((v, i) => (
            <div key={i} className={`border rounded-lg px-2.5 py-2 ${sevColors[v.severity] ?? sevColors.low}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold">{v.title}</span>
                <div className="flex items-center gap-1.5 shrink-0">
                  {v.line && <span className="text-[10px] opacity-60">L{v.line}</span>}
                  <span className="text-[10px] uppercase font-bold">{v.severity}</span>
                </div>
              </div>
              <p className="text-[10px] opacity-70 mt-0.5 leading-relaxed">{v.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default SecurityScansPage;
