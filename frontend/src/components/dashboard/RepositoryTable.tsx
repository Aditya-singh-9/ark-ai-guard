import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Play, Eye, GitBranch, RefreshCw, Filter, Plus, Trash2, X, ExternalLink } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getRepositories, connectRepository, deleteRepository, scanRepository, Repository } from "@/lib/api";
import { toast } from "sonner";
import { Link } from "react-router-dom";

const statusConfig = (score: number | null) => {
  if (score === null) return { cls: "bg-muted/10 text-muted-foreground border-border/30", dot: "bg-muted-foreground", label: "Never Scanned" };
  if (score >= 80) return { cls: "bg-neon-green/10 text-neon-green border-neon-green/30", dot: "bg-neon-green", label: "Secure" };
  if (score >= 50) return { cls: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning", label: "Warning" };
  return { cls: "bg-critical/10 text-critical border-critical/30", dot: "bg-critical", label: "Critical" };
};

const scoreColor = (s: number) =>
  s >= 80 ? "text-neon-green" : s >= 50 ? "text-warning" : "text-critical";

const RepositoryTable = () => {
  const [search, setSearch] = useState("");
  const [scanning, setScanning] = useState<number | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const queryClient = useQueryClient();

  const { data: repos = [], isLoading } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
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
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleScan = async (repo: Repository) => {
    setScanning(repo.id);
    try {
      const { scan_id } = await scanRepository(repo.id);
      toast.success(`Scan started for ${repo.full_name}! Scan #${scan_id}`);
      // Refresh after a moment
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["repositories"] });
        queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
        setScanning(null);
      }, 3000);
    } catch (err: unknown) {
      toast.error((err as Error).message);
      setScanning(null);
    }
  };

  const filtered = repos.filter((r) =>
    r.full_name.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="glass rounded-xl overflow-hidden"
      >
        {/* Header */}
        <div className="p-5 flex flex-wrap items-center justify-between gap-3 border-b border-border/50">
          <div>
            <h3 className="font-semibold">Repositories</h3>
            <p className="text-xs text-muted-foreground mt-0.5">{repos.length} repositories connected</p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                id="repo-search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search repos..."
                className="bg-muted rounded-lg pl-9 pr-4 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 w-48 font-mono placeholder:text-muted-foreground/60"
              />
            </div>
            <Button
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
              onClick={() => setShowAddModal(true)}
            >
              <Plus className="w-4 h-4" /> Add Repository
            </Button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-8 space-y-3">
              {[1,2,3].map(i => (
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
                {filtered.map((r, i) => {
                  const isScanning = scanning === r.id;
                  // We don't have the score here without another query — show last scanned only
                  return (
                    <motion.tr
                      key={r.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.05 }}
                      className="border-b border-border/30 hover:bg-muted/25 transition-colors group"
                    >
                      <td className="p-4">
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                            <GitBranch className="w-4 h-4 text-primary" />
                          </div>
                          <div>
                            <a
                              href={r.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm font-medium hover:text-primary flex items-center gap-1"
                            >
                              {r.full_name}
                              <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-70" />
                            </a>
                            <p className="text-xs text-muted-foreground">{r.language ?? "Unknown language"}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-4 text-muted-foreground text-xs font-mono">—</td>
                      <td className="p-4 text-muted-foreground text-xs font-mono">
                        {r.last_scanned_at ? new Date(r.last_scanned_at).toLocaleDateString() : "Never"}
                      </td>
                      <td className="p-4 text-foreground text-sm">{r.total_scans}</td>
                      <td className="p-4">
                        <Badge variant="outline" className={`inline-flex items-center gap-1.5 text-xs ${r.last_scanned_at ? "bg-neon-green/10 text-neon-green border-neon-green/30" : "bg-muted/10 text-muted-foreground border-border/30"}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${r.last_scanned_at ? "bg-neon-green" : "bg-muted-foreground"}`} />
                          {r.last_scanned_at ? "Scanned" : "Never Scanned"}
                        </Badge>
                      </td>
                      <td className="p-4">
                        <div className="flex gap-1.5 opacity-70 group-hover:opacity-100 transition-opacity">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 text-xs gap-1.5"
                            onClick={() => handleScan(r)}
                            disabled={isScanning}
                          >
                            {isScanning ? (
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Play className="w-3.5 h-3.5" />
                            )}
                            {isScanning ? "Scanning..." : "Scan"}
                          </Button>
                          <Link to={`/dashboard/vulns?repoId=${r.id}`}>
                            <Button variant="ghost" size="sm" className="h-8 text-xs gap-1.5">
                              <Eye className="w-3.5 h-3.5" /> Report
                            </Button>
                          </Link>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 text-xs gap-1.5 text-critical hover:text-critical hover:bg-critical/10"
                            onClick={() => deleteMutation.mutate(r.id)}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        {filtered.length > 0 && (
          <div className="p-4 flex items-center justify-between border-t border-border/30 text-xs text-muted-foreground">
            <span>Showing {filtered.length} of {repos.length} repositories</span>
          </div>
        )}
      </motion.div>

      {/* Add Repository Modal */}
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
                <h3 className="font-semibold text-base">Connect Repository</h3>
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
                <Button variant="outline" size="sm" onClick={() => setShowAddModal(false)}>
                  Cancel
                </Button>
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
