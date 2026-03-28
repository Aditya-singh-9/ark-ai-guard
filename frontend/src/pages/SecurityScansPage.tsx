import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Search, RefreshCw, CheckCircle, XCircle, Clock,
  AlertTriangle, Play, GitBranch, X, Zap, ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState, useEffect, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getDashboardStats, getRepositories, scanRepository,
  getScanStatus, getLatestScanResult,
} from "@/lib/api";
import { toast } from "sonner";
import { Link } from "react-router-dom";

const statusConfig = {
  completed: { icon: CheckCircle, color: "text-neon-green", bg: "bg-neon-green/10 border-neon-green/30", label: "Completed" },
  failed: { icon: XCircle, color: "text-critical", bg: "bg-critical/10 border-critical/30", label: "Failed" },
  running: { icon: RefreshCw, color: "text-neon-cyan", bg: "bg-neon-cyan/10 border-neon-cyan/30", label: "Scanning…" },
  pending: { icon: RefreshCw, color: "text-warning", bg: "bg-warning/10 border-warning/30", label: "Pending" },
  never_scanned: { icon: GitBranch, color: "text-muted-foreground", bg: "bg-muted/10 border-border/30", label: "Never Scanned" },
};

// Fake progress that climbs to ~90% while scan is running (resets on completion)
const useFakeProgress = (isActive: boolean) => {
  const [progress, setProgress] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!isActive) {
      setProgress(0);
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }
    setProgress(5);
    intervalRef.current = setInterval(() => {
      setProgress((p) => {
        if (p >= 88) return p + 0.1; // very slow near end
        if (p >= 70) return p + 0.5;
        if (p >= 40) return p + 1.2;
        return p + 2.5;
      });
    }, 600);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isActive]);

  return Math.min(progress, 90);
};

// Component for a single repo row with live scan polling
const ScanRow = ({
  repo,
  index,
  onScanStarted,
}: {
  repo: { id: number; name: string; url: string; language: string | null; last_scanned_at: string | null; security_score: number | null; total_vulnerabilities: number; scan_status: string };
  index: number;
  onScanStarted: (scanId: number, repoId: number) => void;
}) => {
  const queryClient = useQueryClient();
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const isRunning = repo.scan_status === "running" || repo.scan_status === "pending" || activeScanId !== null;
  const progress = useFakeProgress(isRunning);

  // Poll the scan status while running
  const { data: scanStatus } = useQuery({
    queryKey: ["scan-status", activeScanId],
    queryFn: () => getScanStatus(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d || d.status === "running" || d.status === "pending") return 3000;
      return false;
    },
  });

  // When scan completes, refresh dashboard
  useEffect(() => {
    if (scanStatus?.status === "completed" || scanStatus?.status === "failed") {
      setActiveScanId(null);
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      queryClient.invalidateQueries({ queryKey: ["repositories"] });
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
      onScanStarted(data.scan_id, repo.id);
      toast.info(`Scan #${data.scan_id} started for ${repo.name}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const status = (activeScanId ? "running" : repo.scan_status) as keyof typeof statusConfig;
  const cfg = statusConfig[status] ?? statusConfig.never_scanned;
  const score = repo.security_score;

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
          <cfg.icon className={`w-4 h-4 ${cfg.color} ${isRunning ? "animate-spin" : ""}`} />
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

          {/* Live progress bar */}
          <AnimatePresence>
            {isRunning && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-neon-cyan font-mono">
                    {activeScanId ? (
                      scanStatus?.status === "running" ? "🔍 Running deep scan…" :
                      scanStatus?.status === "pending" ? "⏳ Queued…" : "🔍 Scanning…"
                    ) : "⏳ Starting scan…"}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-mono">{progress.toFixed(0)}%</span>
                </div>
                <div className="h-1 bg-muted rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-gradient-to-r from-neon-cyan to-primary rounded-full"
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.6, ease: "easeOut" }}
                  />
                </div>
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
            <Link to={`/dashboard/vulns?repoId=${repo.id}`}>
              <button className="p-1.5 hover:bg-muted rounded-lg transition-colors text-muted-foreground" title="View report">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </Link>
          )}
        </div>
      </div>
    </motion.div>
  );
};

// Custom dark select for scan modal
const ModalSelect = ({
  options, value, onChange,
}: {
  options: { label: string; value: number }[];
  value: number | null;
  onChange: (v: number | null) => void;
}) => (
  <div className="w-full glass border border-border/60 rounded-xl overflow-hidden mb-4">
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

const SecurityScansPage = () => {
  const [search, setSearch] = useState("");
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const { data: stats, isLoading } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
    refetchInterval: 15000, // background refresh every 15s
  });

  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
  });

  const scanMutation = useMutation({
    mutationFn: (repoId: number) => scanRepository(repoId),
    onSuccess: (data) => {
      toast.success(`Scan #${data.scan_id} started! Watching progress…`);
      setShowScanModal(false);
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

  return (
    <>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold mb-1">Security Scans</h1>
            <p className="text-sm text-muted-foreground">
              Scan history and live status across all repositories.
              {hasRunning && (
                <span className="ml-2 text-neon-cyan font-medium animate-pulse">
                  🔍 Scan in progress…
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
                <span className="flex h-2 w-2">
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
                  onScanStarted={() => {
                    setTimeout(() => {
                      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
                    }, 5000);
                  }}
                />
              ))}
            </div>
          )}
        </motion.div>
      </div>

      {/* Run Scan Modal */}
      <AnimatePresence>
        {showScanModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="glass rounded-2xl p-6 w-full max-w-md mx-4 border border-border/80 shadow-2xl"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-primary/15 rounded-xl flex items-center justify-center">
                    <Zap className="w-4 h-4 text-primary" />
                  </div>
                  <h3 className="font-semibold text-base">Run Security Scan</h3>
                </div>
                <button onClick={() => setShowScanModal(false)} className="p-1 hover:bg-muted rounded-lg">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <p className="text-sm text-muted-foreground mb-4">
                Select a repository to run a full security scan. The scanner will analyze your code for vulnerabilities and generate an AI-powered report.
              </p>

              <ModalSelect
                options={repos.map((r) => ({ label: r.full_name, value: r.id }))}
                value={selectedRepo}
                onChange={setSelectedRepo}
              />

              <div className="flex gap-2 justify-end">
                <Button variant="outline" size="sm" onClick={() => setShowScanModal(false)}>
                  Cancel
                </Button>
                <Button
                  size="sm"
                  className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                  onClick={() => selectedRepo && scanMutation.mutate(selectedRepo)}
                  disabled={!selectedRepo || scanMutation.isPending}
                >
                  {scanMutation.isPending ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Zap className="w-3.5 h-3.5" />
                  )}
                  {scanMutation.isPending ? "Starting…" : "Start Scan"}
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

export default SecurityScansPage;
