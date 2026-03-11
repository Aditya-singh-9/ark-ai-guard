import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { Search, Play, Eye, GitBranch, RefreshCw, Filter, Plus } from "lucide-react";

const repos = [
  { name: "frontend-app", org: "myorg", score: 92, lastScan: "2h ago", vulns: 2, status: "Secure", branch: "main" },
  { name: "api-gateway", org: "myorg", score: 74, lastScan: "5h ago", vulns: 8, status: "Warning", branch: "develop" },
  { name: "auth-service", org: "myorg", score: 45, lastScan: "1d ago", vulns: 15, status: "Critical", branch: "main" },
  { name: "payment-service", org: "myorg", score: 88, lastScan: "3h ago", vulns: 4, status: "Secure", branch: "main" },
  { name: "data-pipeline", org: "myorg", score: 67, lastScan: "12h ago", vulns: 11, status: "Warning", branch: "feat/etl" },
  { name: "ml-inference", org: "myorg", score: 95, lastScan: "30m ago", vulns: 1, status: "Secure", branch: "main" },
];

const statusConfig = (s: string) => {
  if (s === "Secure") return { cls: "bg-neon-green/10 text-neon-green border-neon-green/30", dot: "bg-neon-green" };
  if (s === "Warning") return { cls: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning" };
  return { cls: "bg-critical/10 text-critical border-critical/30", dot: "bg-critical" };
};

const scoreColor = (s: number) =>
  s >= 80 ? "text-neon-green" : s >= 50 ? "text-warning" : "text-critical";

const RepositoryTable = () => {
  const [search, setSearch] = useState("");
  const [scanning, setScanning] = useState<string | null>(null);

  const filtered = repos.filter((r) =>
    r.name.toLowerCase().includes(search.toLowerCase())
  );

  const handleScan = (name: string) => {
    setScanning(name);
    setTimeout(() => setScanning(null), 2500);
  };

  return (
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
          <p className="text-xs text-muted-foreground mt-0.5">{filtered.length} repositories connected</p>
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
          <Button variant="outline" size="sm" className="border-border gap-1.5">
            <Filter className="w-3.5 h-3.5" /> Filter
          </Button>
          <Button size="sm" className="bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5">
            <Plus className="w-4 h-4" /> Add Repository
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 text-muted-foreground">
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Repository</th>
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Score</th>
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Last Scan</th>
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Vulns</th>
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Status</th>
              <th className="text-left p-4 font-medium text-xs uppercase tracking-wide">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => {
              const { cls, dot } = statusConfig(r.status);
              const isScanning = scanning === r.name;
              return (
                <motion.tr
                  key={r.name}
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
                        <span className="font-mono text-sm font-medium">{r.name}</span>
                        <p className="text-xs text-muted-foreground">{r.org} · {r.branch}</p>
                      </div>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            r.score >= 80 ? "bg-neon-green" : r.score >= 50 ? "bg-warning" : "bg-critical"
                          }`}
                          style={{ width: `${r.score}%` }}
                        />
                      </div>
                      <span className={`font-medium text-sm ${scoreColor(r.score)}`}>{r.score}%</span>
                    </div>
                  </td>
                  <td className="p-4 text-muted-foreground text-xs font-mono">{r.lastScan}</td>
                  <td className="p-4">
                    <span className={r.vulns > 10 ? "text-critical font-semibold" : r.vulns > 4 ? "text-warning font-semibold" : "text-foreground"}>
                      {r.vulns}
                    </span>
                  </td>
                  <td className="p-4">
                    <Badge variant="outline" className={`inline-flex items-center gap-1.5 text-xs ${cls}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
                      {r.status}
                    </Badge>
                  </td>
                  <td className="p-4">
                    <div className="flex gap-1.5 opacity-70 group-hover:opacity-100 transition-opacity">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-xs gap-1.5"
                        onClick={() => handleScan(r.name)}
                        disabled={isScanning}
                      >
                        {isScanning ? (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Play className="w-3.5 h-3.5" />
                        )}
                        {isScanning ? "Scanning..." : "Scan"}
                      </Button>
                      <Button variant="ghost" size="sm" className="h-8 text-xs gap-1.5">
                        <Eye className="w-3.5 h-3.5" /> Report
                      </Button>
                    </div>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="p-4 flex items-center justify-between border-t border-border/30 text-xs text-muted-foreground">
        <span>Showing {filtered.length} of {repos.length} repositories</span>
        <div className="flex gap-1">
          <button className="px-2 py-1 rounded hover:bg-muted transition-colors">← Prev</button>
          <button className="px-2 py-1 rounded bg-primary/10 text-primary">1</button>
          <button className="px-2 py-1 rounded hover:bg-muted transition-colors">Next →</button>
        </div>
      </div>
    </motion.div>
  );
};

export default RepositoryTable;
