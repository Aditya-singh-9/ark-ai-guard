import { useState, useEffect, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, Play, Eye, GitBranch, RefreshCw, Plus, Trash2, X,
  ExternalLink, Github, Lock, Globe, ChevronDown, Download,
  CheckCircle, AlertTriangle, Shield,
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getRepositories, connectRepository, deleteRepository, scanRepository,
  getScanStatus, listGithubRepos, Repository, GithubRepoItem,
} from "@/lib/api";
import { toast } from "sonner";
import { Link } from "react-router-dom";

// ── Score helpers ──────────────────────────────────────────────────────────────

const scoreColor = (s: number | null) =>
  s === null ? "text-muted-foreground" : s >= 80 ? "text-neon-green" : s >= 50 ? "text-warning" : "text-critical";

const statusBadge = (repo: Repository) => {
  if (!repo.last_scanned_at || repo.scan_status === "never_scanned")
    return { cls: "bg-muted/10 text-muted-foreground border-border/30", dot: "bg-muted-foreground", label: "Never Scanned" };
  if (repo.scan_status === "running" || repo.scan_status === "pending")
    return { cls: "bg-neon-cyan/10 text-neon-cyan border-neon-cyan/30", dot: "bg-neon-cyan animate-pulse", label: "Scanning…" };
  if (repo.scan_status === "failed")
    return { cls: "bg-critical/10 text-critical border-critical/30", dot: "bg-critical", label: "Failed" };
  const score = repo.security_score;
  if (score !== null && score >= 80) return { cls: "bg-neon-green/10 text-neon-green border-neon-green/30", dot: "bg-neon-green", label: "Secure" };
  if (score !== null && score >= 50) return { cls: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning", label: "Warning" };
  if (score !== null) return { cls: "bg-critical/10 text-critical border-critical/30", dot: "bg-critical", label: "Critical" };
  return { cls: "bg-neon-green/10 text-neon-green border-neon-green/30", dot: "bg-neon-green", label: "Scanned" };
};

// ── Status metadata mapped from real backend events ─────────────────────────

const getStatusMeta = (status: string | null | undefined): { progress: number; label: string; isRunning: boolean } => {
  switch (status?.toLowerCase()) {
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

// ── Row-level scan tracker ─────────────────────────────────────────────────────

const RepoRow = ({
  repo, index, onDeleteClick,
}: {
  repo: Repository;
  index: number;
  onDeleteClick: (id: number) => void;
}) => {
  const queryClient = useQueryClient();
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const { data: scanStatus } = useQuery({
    queryKey: ["scan-status", activeScanId],
    queryFn: () => getScanStatus(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d || !["completed", "failed"].includes(d.status?.toLowerCase())) return 2000;
      return false;
    },
  });

  const rawStatus = activeScanId ? (scanStatus?.status ?? repo.scan_status) : repo.scan_status;
  const meta = getStatusMeta(rawStatus);
  const isRunning = meta.isRunning || (activeScanId !== null);
  const progress = meta.progress;
  const stepLabel = meta.label;

  useEffect(() => {
    const s = scanStatus?.status?.toLowerCase();
    if (s === "completed" || s === "failed") {
      setTimeout(() => {
        setActiveScanId(null);
        queryClient.invalidateQueries({ queryKey: ["repositories"] });
        queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      }, 800);
      if (scanStatus.status === "completed") {
        toast.success(`✅ Scan done! ${scanStatus.total_vulnerabilities} issues found in ${repo.name}.`);
      } else {
        toast.error(`Scan failed for ${repo.name}. Check logs.`);
      }
    }
  }, [scanStatus?.status, queryClient, repo.name, scanStatus?.total_vulnerabilities]);

  const scanMutation = useMutation({
    mutationFn: () => scanRepository(repo.id),
    onSuccess: (data) => {
      setActiveScanId(data.scan_id);
      toast.info(`🔍 Scan #${data.scan_id} started for ${repo.name}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const badge = statusBadge({ ...repo, scan_status: isRunning ? "running" : repo.scan_status });

  return (
    <motion.tr
      key={repo.id}
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className="border-b border-border/30 hover:bg-muted/20 transition-colors group"
    >
      {/* Repository name */}
      <td className="p-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
            <GitBranch className="w-4 h-4 text-primary" />
          </div>
          <div className="min-w-0">
            <a
              href={repo.url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-sm font-medium hover:text-primary flex items-center gap-1 truncate"
            >
              {repo.full_name}
              <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-70 flex-shrink-0" />
            </a>
            <p className="text-xs text-muted-foreground">{repo.language ?? "Unknown"}</p>
          </div>
        </div>
      </td>

      {/* Security score */}
      <td className="p-4">
        {isRunning ? (
          <div className="w-28">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-neon-cyan font-mono truncate">{stepLabel}…</span>
              <span className="text-[10px] text-muted-foreground font-mono ml-1">{progress.toFixed(0)}%</span>
            </div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-neon-cyan to-primary rounded-full"
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.5, ease: "easeOut" }}
              />
            </div>
          </div>
        ) : repo.security_score !== null ? (
          <span className={`text-sm font-bold font-mono ${scoreColor(repo.security_score)}`}>
            {repo.security_score.toFixed(0)}%
          </span>
        ) : (
          <span className="text-xs text-muted-foreground font-mono">—</span>
        )}
      </td>

      {/* Last scan */}
      <td className="p-4 text-muted-foreground text-xs font-mono">
        {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleDateString() : "Never"}
      </td>

      {/* Scan count */}
      <td className="p-4 text-foreground text-sm">{repo.total_scans}</td>

      {/* Status badge */}
      <td className="p-4">
        <Badge variant="outline" className={`inline-flex items-center gap-1.5 text-xs ${badge.cls}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
          {badge.label}
        </Badge>
      </td>

      {/* Actions */}
      <td className="p-4">
        <div className="flex gap-1.5 opacity-60 group-hover:opacity-100 transition-opacity">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-xs gap-1.5"
            onClick={() => scanMutation.mutate()}
            disabled={isRunning || scanMutation.isPending}
          >
            {isRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            {isRunning ? "Scanning" : "Scan"}
          </Button>
          <Link to={`/dashboard/vulns?repoId=${repo.id}`}>
            <Button variant="ghost" size="sm" className="h-8 text-xs gap-1.5">
              <Eye className="w-3.5 h-3.5" /> Report
            </Button>
          </Link>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-xs gap-1.5 text-critical hover:text-critical hover:bg-critical/10"
            onClick={() => onDeleteClick(repo.id)}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </td>
    </motion.tr>
  );
};

// ── GitHub Auto-Import Panel ───────────────────────────────────────────────────

const GithubImportPanel = ({ onImported }: { onImported: () => void }) => {
  const [open, setOpen] = useState(false);
  const [ghSearch, setGhSearch] = useState("");
  const queryClient = useQueryClient();

  const { data: ghRepos = [], isLoading: ghLoading, error: ghError, refetch } = useQuery({
    queryKey: ["github-repos"],
    queryFn: listGithubRepos,
    enabled: open,
    staleTime: 60_000,
  });

  const addMutation = useMutation({
    mutationFn: (url: string) => connectRepository(url),
    onSuccess: (repo) => {
      toast.success(`✅ ${repo.full_name} connected!`);
      queryClient.invalidateQueries({ queryKey: ["repositories"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      onImported();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const filtered = ghRepos.filter((r) =>
    r.full_name.toLowerCase().includes(ghSearch.toLowerCase())
  );

  return (
    <div className="relative">
      <Button
        size="sm"
        variant="outline"
        className="gap-1.5 border-border/60"
        onClick={() => setOpen((v) => !v)}
      >
        <Github className="w-4 h-4" />
        Import from GitHub
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </Button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.97 }}
            transition={{ duration: 0.15 }}
            className="absolute right-0 top-10 z-50 w-80 glass rounded-xl border border-border/80 shadow-2xl overflow-hidden"
          >
            <div className="p-3 border-b border-border/50 flex items-center justify-between">
              <span className="text-sm font-semibold flex items-center gap-2">
                <Github className="w-4 h-4" /> Your GitHub Repositories
              </span>
              <button onClick={() => setOpen(false)} className="p-1 hover:bg-muted rounded-lg">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="p-2 border-b border-border/40">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <input
                  placeholder="Search repos..."
                  value={ghSearch}
                  onChange={(e) => setGhSearch(e.target.value)}
                  className="w-full bg-muted rounded-lg pl-8 pr-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-primary/60 font-mono"
                  autoFocus
                />
              </div>
            </div>

            <div className="max-h-64 overflow-y-auto">
              {ghLoading ? (
                <div className="p-4 space-y-2">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-10 bg-muted/30 rounded-lg animate-pulse" />
                  ))}
                </div>
              ) : ghError ? (
                <div className="p-4 text-center text-xs text-muted-foreground">
                  <p>Could not load repositories.</p>
                  <button
                    onClick={() => refetch()}
                    className="text-primary hover:underline mt-1"
                  >
                    Retry
                  </button>
                </div>
              ) : filtered.length === 0 ? (
                <div className="p-4 text-center text-xs text-muted-foreground">
                  {ghRepos.length === 0 ? "No repositories found." : "No matches."}
                </div>
              ) : (
                filtered.map((r) => (
                  <button
                    key={r.id}
                    onClick={() => addMutation.mutate(r.html_url)}
                    disabled={addMutation.isPending}
                    className="w-full text-left px-3 py-2.5 hover:bg-muted/40 transition-colors flex items-center justify-between gap-2 group/item"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        {r.is_private ? (
                          <Lock className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                        ) : (
                          <Globe className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                        )}
                        <span className="text-xs font-mono font-medium truncate">{r.full_name}</span>
                      </div>
                      {r.language && (
                        <span className="text-[10px] text-muted-foreground ml-5">{r.language}</span>
                      )}
                    </div>
                    <Download className="w-3.5 h-3.5 text-primary opacity-0 group-hover/item:opacity-100 flex-shrink-0 transition-opacity" />
                  </button>
                ))
              )}
            </div>

            {filtered.length > 0 && (
              <div className="p-2 border-t border-border/40 text-center">
                <p className="text-[10px] text-muted-foreground">{filtered.length} repos available</p>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ── Main Component ─────────────────────────────────────────────────────────────

const RepositoryTable = () => {
  const [search, setSearch] = useState("");
  const [showAddModal, setShowAddModal] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const { data: repos = [], isLoading } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
    refetchInterval: 10000, // always poll — catches scan status changes
    staleTime: 0,
  });

  const addMutation = useMutation({
    mutationFn: (url: string) => connectRepository(url),
    onSuccess: (repo) => {
      toast.success(`Repository "${repo.full_name}" connected!`);
      queryClient.invalidateQueries({ queryKey: ["repositories"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      setShowAddModal(false);
      setRepoUrl("");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRepository(id),
    onSuccess: () => {
      toast.success("Repository removed.");
      queryClient.invalidateQueries({ queryKey: ["repositories"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      setDeleteConfirm(null);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const filtered = repos.filter((r) =>
    r.full_name.toLowerCase().includes(search.toLowerCase())
  );

  const avgScore = repos.length > 0
    ? repos.filter(r => r.security_score !== null).reduce((acc, r) => acc + (r.security_score ?? 0), 0) /
      (repos.filter(r => r.security_score !== null).length || 1)
    : null;

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="glass rounded-xl overflow-hidden"
      >
        {/* Header */}
        <div className="p-5 flex flex-wrap items-center justify-between gap-3 border-b border-border/50">
          <div>
            <h3 className="font-semibold flex items-center gap-2">
              Repositories
              {avgScore !== null && (
                <span className={`text-xs font-mono font-bold ${scoreColor(avgScore)}`}>
                  avg {avgScore.toFixed(0)}%
                </span>
              )}
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">{repos.length} repositories connected</p>
          </div>
          <div className="flex gap-2 flex-wrap items-center">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                id="repo-search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search repos..."
                className="bg-muted rounded-lg pl-8 pr-3 py-2 text-xs outline-none focus:ring-1 focus:ring-primary/60 w-44 font-mono"
              />
            </div>
            <GithubImportPanel onImported={() => {}} />
            <Button
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
              onClick={() => setShowAddModal(true)}
            >
              <Plus className="w-4 h-4" /> Add URL
            </Button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-muted/30 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <GitBranch className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">{repos.length === 0 ? "No repositories connected yet." : "No repos match your search."}</p>
              {repos.length === 0 && (
                <Button size="sm" className="mt-4 gap-1.5" onClick={() => setShowAddModal(true)}>
                  <Plus className="w-4 h-4" /> Add your first repository
                </Button>
              )}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50 text-muted-foreground">
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Repository</th>
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Score</th>
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Last Scan</th>
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Total Scans</th>
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Status</th>
                  <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, i) => (
                  <RepoRow key={r.id} repo={r} index={i} onDeleteClick={setDeleteConfirm} />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {filtered.length > 0 && (
          <div className="p-4 flex items-center justify-between border-t border-border/30 text-xs text-muted-foreground">
            <span>Showing {filtered.length} of {repos.length} repositories</span>
            <div className="flex gap-3">
              <span className="flex items-center gap-1"><CheckCircle className="w-3 h-3 text-neon-green" />{repos.filter(r => (r.security_score ?? 0) >= 80).length} secure</span>
              <span className="flex items-center gap-1"><AlertTriangle className="w-3 h-3 text-warning" />{repos.filter(r => r.security_score !== null && r.security_score < 50).length} critical</span>
            </div>
          </div>
        )}
      </motion.div>

      {/* Delete Confirm Modal */}
      <AnimatePresence>
        {deleteConfirm !== null && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="glass rounded-xl p-6 w-full max-w-sm mx-4 border border-border/80 shadow-2xl"
            >
              <Shield className="w-8 h-8 text-critical mx-auto mb-3" />
              <h3 className="font-semibold text-base text-center mb-1">Remove Repository?</h3>
              <p className="text-sm text-muted-foreground text-center mb-5">
                This will remove the repository and all associated scan history. This cannot be undone.
              </p>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="flex-1" onClick={() => setDeleteConfirm(null)}>
                  Cancel
                </Button>
                <Button
                  size="sm"
                  className="flex-1 bg-critical hover:bg-critical/90 text-white"
                  onClick={() => deleteMutation.mutate(deleteConfirm!)}
                  disabled={deleteMutation.isPending}
                >
                  {deleteMutation.isPending ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                  Remove
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Add by URL Modal */}
      <AnimatePresence>
        {showAddModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="glass rounded-xl p-6 w-full max-w-md mx-4 border border-border/80 shadow-2xl"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-primary/15 rounded-xl flex items-center justify-center">
                    <Plus className="w-4 h-4 text-primary" />
                  </div>
                  <h3 className="font-semibold text-base">Connect Repository by URL</h3>
                </div>
                <button onClick={() => setShowAddModal(false)} className="p-1 hover:bg-muted rounded-lg">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <p className="text-sm text-muted-foreground mb-4">
                Enter a GitHub repository URL to connect it for security scanning.
              </p>
              <input
                type="url"
                placeholder="https://github.com/owner/repository"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && repoUrl && addMutation.mutate(repoUrl)}
                className="w-full bg-muted rounded-lg px-3 py-2.5 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono mb-4"
                autoFocus
              />
              <div className="flex gap-2 justify-end">
                <Button variant="outline" size="sm" onClick={() => setShowAddModal(false)}>Cancel</Button>
                <Button
                  size="sm"
                  className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                  onClick={() => repoUrl && addMutation.mutate(repoUrl)}
                  disabled={!repoUrl || addMutation.isPending}
                >
                  {addMutation.isPending ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  {addMutation.isPending ? "Connecting..." : "Connect"}
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

export default RepositoryTable;
