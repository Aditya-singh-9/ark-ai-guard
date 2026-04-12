import { motion, AnimatePresence } from "framer-motion";
import {
  TrendingUp, TrendingDown, Shield, AlertTriangle, GitBranch,
  Calendar, Clock, Download, ChevronDown, Check, RefreshCw,
  BarChart3, Award, Activity,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getRepositories, getRepoTrends, getSbomUrl, getReportDownloadUrl, TrendPoint, downloadSecureFile } from "@/lib/api";
import { useState } from "react";
import { toast } from "sonner";

// ── Helpers ───────────────────────────────────────────────────────────────────

const scoreColor = (s: number | null) =>
  s === null ? "text-muted-foreground" :
  s >= 80 ? "text-neon-green" :
  s >= 50 ? "text-warning" : "text-critical";

const scoreBg = (s: number | null) =>
  s === null ? "#4a5568" :
  s >= 80 ? "#22c55e" :
  s >= 50 ? "#f59e0b" : "#ef4444";

// ── Mini Sparkline SVG ────────────────────────────────────────────────────────

const Sparkline = ({ data, color }: { data: number[]; color: string }) => {
  if (data.length < 2) return null;
  const max = Math.max(...data, 100);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const w = 200, h = 48, pad = 4;
  const stepX = (w - pad * 2) / (data.length - 1);

  const points = data
    .map((v, i) => `${pad + i * stepX},${pad + (1 - (v - min) / range) * (h - pad * 2)}`)
    .join(" L ");

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-12" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        d={`M ${points} L ${pad + (data.length - 1) * stepX},${h - pad} L ${pad},${h - pad} Z`}
        fill={`url(#grad-${color})`}
      />
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Latest value dot */}
      <circle
        cx={pad + (data.length - 1) * stepX}
        cy={pad + (1 - (data[data.length - 1] - min) / range) * (h - pad * 2)}
        r="3"
        fill={color}
      />
    </svg>
  );
};

// ── Full Trend Chart ───────────────────────────────────────────────────────────

const TrendChart = ({ trend }: { trend: TrendPoint[] }) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (trend.length === 0) {
    return (
      <div className="py-12 text-center text-muted-foreground">
        <BarChart3 className="w-8 h-8 mx-auto mb-2 opacity-30" />
        <p className="text-sm">No scan history yet. Run a scan to see trends.</p>
      </div>
    );
  }

  const scores = trend.map(p => p.security_score ?? 0);
  const vulns = trend.map(p => p.total_vulnerabilities);
  const maxVulns = Math.max(...vulns, 1);

  return (
    <div className="space-y-4">
      {/* Score trend */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-muted-foreground font-mono uppercase tracking-wide">Security Score Trend</span>
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            {scores.length >= 2 && (
              <>
                {scores[scores.length - 1] > scores[0] ? (
                  <TrendingUp className="w-3 h-3 text-neon-green" />
                ) : (
                  <TrendingDown className="w-3 h-3 text-critical" />
                )}
                <span>{scores[scores.length - 1].toFixed(0)}% now</span>
              </>
            )}
          </div>
        </div>
        <div className="relative">
          <svg viewBox="0 0 600 120" className="w-full h-28" preserveAspectRatio="none">
            {/* Grid lines */}
            {[0, 25, 50, 75, 100].map(v => (
              <g key={v}>
                <line x1="0" y1={120 - v * 1.1} x2="600" y2={120 - v * 1.1} stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
                <text x="4" y={120 - v * 1.1 - 2} fill="rgba(255,255,255,0.3)" fontSize="8">{v}%</text>
              </g>
            ))}
            {/* Score line */}
            <defs>
              <linearGradient id="score-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22c55e" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#22c55e" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path
              d={`M ${scores.map((s, i) => `${(i / (scores.length - 1)) * 590 + 5},${115 - s * 1.05}`).join(" L ")} L ${590 + 5},115 L 5,115 Z`}
              fill="url(#score-grad)"
            />
            <polyline
              points={scores.map((s, i) => `${(i / (scores.length - 1)) * 590 + 5},${115 - s * 1.05}`).join(" ")}
              fill="none"
              stroke="#22c55e"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            {/* Data points */}
            {trend.map((p, i) => (
              <circle
                key={i}
                cx={(i / (scores.length - 1)) * 590 + 5}
                cy={115 - (p.security_score ?? 0) * 1.05}
                r={hoveredIndex === i ? 5 : 3}
                fill={scoreBg(p.security_score)}
                className="cursor-pointer transition-all"
                onMouseEnter={() => setHoveredIndex(i)}
                onMouseLeave={() => setHoveredIndex(null)}
              />
            ))}
          </svg>

          {/* Tooltip */}
          <AnimatePresence>
            {hoveredIndex !== null && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 4 }}
                className="absolute top-0 left-1/2 -translate-x-1/2 glass rounded-lg p-2.5 text-xs font-mono border border-border/60 shadow-xl pointer-events-none z-10"
              >
                <div className={`text-base font-bold ${scoreColor(trend[hoveredIndex].security_score)}`}>
                  {trend[hoveredIndex].security_score?.toFixed(0) ?? "N/A"}%
                </div>
                <div className="text-muted-foreground">{new Date(trend[hoveredIndex].date).toLocaleDateString()}</div>
                <div className="text-warning mt-0.5">{trend[hoveredIndex].total_vulnerabilities} vulns</div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Vuln bar chart */}
      <div>
        <span className="text-xs text-muted-foreground font-mono uppercase tracking-wide">Vulnerability Count per Scan</span>
        <div className="flex items-end gap-1.5 h-16 mt-2">
          {trend.map((p, i) => (
            <div
              key={i}
              className="flex-1 flex flex-col justify-end"
              onMouseEnter={() => setHoveredIndex(i)}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              <div
                className="rounded-sm transition-all cursor-pointer"
                style={{
                  height: `${(p.total_vulnerabilities / maxVulns) * 100}%`,
                  minHeight: "2px",
                  background: hoveredIndex === i
                    ? "#60a5fa"
                    : p.critical_count > 0 ? "#ef4444"
                    : p.high_count > 0 ? "#f59e0b"
                    : "#22c55e",
                }}
              />
            </div>
          ))}
        </div>
        <div className="flex justify-between text-[10px] text-muted-foreground font-mono mt-1">
          <span>{new Date(trend[0]?.date).toLocaleDateString()}</span>
          <span>{new Date(trend[trend.length - 1]?.date).toLocaleDateString()}</span>
        </div>
      </div>

      {/* Summary table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-muted-foreground border-b border-border/30">
              <th className="text-left py-2 pr-4">Scan</th>
              <th className="text-left py-2 pr-4">Date</th>
              <th className="text-left py-2 pr-4">Score</th>
              <th className="text-right py-2 pr-4 text-critical">Crit</th>
              <th className="text-right py-2 pr-4 text-warning">High</th>
              <th className="text-right py-2 pr-4">Med</th>
              <th className="text-right py-2">Low</th>
            </tr>
          </thead>
          <tbody>
            {[...trend].reverse().map((p, i) => (
              <tr key={p.scan_id} className="border-b border-border/10 hover:bg-muted/20 transition-colors">
                <td className="py-1.5 pr-4 text-muted-foreground">#{p.scan_id}</td>
                <td className="py-1.5 pr-4">{new Date(p.date).toLocaleDateString()}</td>
                <td className={`py-1.5 pr-4 font-bold ${scoreColor(p.security_score)}`}>
                  {p.security_score?.toFixed(0) ?? "—"}%
                </td>
                <td className="py-1.5 pr-4 text-right text-critical">{p.critical_count}</td>
                <td className="py-1.5 pr-4 text-right text-warning">{p.high_count}</td>
                <td className="py-1.5 pr-4 text-right">{p.medium_count}</td>
                <td className="py-1.5 text-right text-neon-green">{p.low_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ── Repo select ────────────────────────────────────────────────────────────────

const RepoSelect = ({
  repos,
  value,
  onChange,
}: {
  repos: { id: number; full_name: string; security_score: number | null }[];
  value: number | null;
  onChange: (id: number | null) => void;
}) => {
  const [open, setOpen] = useState(false);
  const selected = repos.find(r => r.id === value);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 glass rounded-xl px-4 py-2.5 text-sm font-mono border border-border/60 hover:border-primary/40 transition-colors min-w-52"
      >
        {selected ? (
          <>
            <div className={`w-2 h-2 rounded-full ${(selected.security_score ?? 0) >= 80 ? "bg-neon-green" : (selected.security_score ?? 0) >= 50 ? "bg-warning" : "bg-critical"}`} />
            <span className="flex-1 text-left truncate">{selected.full_name}</span>
          </>
        ) : (
          <span className="flex-1 text-left text-muted-foreground">Select repository…</span>
        )}
        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="absolute top-12 left-0 z-50 glass rounded-xl border border-border/60 shadow-2xl overflow-hidden w-72"
          >
            {repos.length === 0 ? (
              <div className="px-4 py-3 text-sm text-muted-foreground">No repositories yet.</div>
            ) : repos.map(r => (
              <button
                key={r.id}
                onClick={() => { onChange(r.id); setOpen(false); }}
                className="w-full flex items-center gap-2.5 px-4 py-2.5 hover:bg-primary/10 transition-colors text-sm font-mono"
              >
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${(r.security_score ?? 0) >= 80 ? "bg-neon-green" : (r.security_score ?? 0) >= 50 ? "bg-warning" : "bg-critical"}`} />
                <span className="flex-1 text-left truncate">{r.full_name}</span>
                {value === r.id && <Check className="w-3.5 h-3.5 text-primary" />}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ── Main Page ──────────────────────────────────────────────────────────────────

const TrendsPage = () => {
  const [selectedRepoId, setSelectedRepoId] = useState<number | null>(null);

  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: async () => {
      const { getRepositories } = await import("@/lib/api");
      return getRepositories();
    },
    staleTime: 30_000,
  });

  const { data: trends, isLoading } = useQuery({
    queryKey: ["repo-trends", selectedRepoId],
    queryFn: () => getRepoTrends(selectedRepoId!),
    enabled: !!selectedRepoId,
    staleTime: 0,
  });

  const latestScanId = trends?.trend[trends.trend.length - 1]?.scan_id ?? null;
  const selectedRepo = repos.find(r => r.id === selectedRepoId);
  const firstScore = trends?.trend[0]?.security_score ?? null;
  const lastScore = trends?.trend[trends.trend.length - 1]?.security_score ?? null;
  const delta = firstScore !== null && lastScore !== null ? lastScore - firstScore : null;

  const handleSbomDownload = async (format = "cyclonedx") => {
    if (!selectedRepoId) return;
    try {
      toast.info(`Preparing ${format.toUpperCase()} SBOM...`);
      await downloadSecureFile(getSbomUrl(selectedRepoId, format), `sbom-${selectedRepoId}-${format}.json`);
      toast.success("SBOM downloaded!");
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleReportDownload = async () => {
    if (!latestScanId) return;
    try {
      toast.info("Preparing HTML Report...");
      await downloadSecureFile(getReportDownloadUrl(latestScanId), `scan-report-${latestScanId}.html`);
      toast.success("HTML Report downloaded!");
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold mb-1">Scan Trends & SBOM</h1>
          <p className="text-sm text-muted-foreground">
            Track your security posture over time. Download SBOM and compliance reports.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <RepoSelect
            repos={repos.map(r => ({ id: r.id, full_name: r.full_name, security_score: r.security_score }))}
            value={selectedRepoId}
            onChange={setSelectedRepoId}
          />
            {selectedRepoId && (
              <>
                <button
                  onClick={() => handleSbomDownload()}
                  className="flex items-center gap-1.5 px-3 py-2 glass rounded-lg text-xs font-mono border border-border/60 hover:border-neon-cyan/40 text-neon-cyan transition-colors"
                >
                  <Download className="w-3.5 h-3.5" /> SBOM
                </button>
                {latestScanId && (
                  <button
                    onClick={handleReportDownload}
                    className="flex items-center gap-1.5 px-3 py-2 glass rounded-lg text-xs font-mono border border-border/60 hover:border-primary/40 text-primary transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> HTML Report
                  </button>
                )}
              </>
            )}
        </div>
      </div>

      {!selectedRepoId ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-20 glass rounded-xl"
        >
          <BarChart3 className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm text-muted-foreground">Select a repository to view its scan history and trends.</p>
        </motion.div>
      ) : isLoading ? (
        <div className="grid grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="glass rounded-xl p-4 h-24 animate-pulse bg-muted/20" />
          ))}
        </div>
      ) : (
        <>
          {/* Summary stat cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-primary" />
                <span className="text-xs text-muted-foreground">Total Scans</span>
              </div>
              <div className="text-2xl font-bold">{trends?.total_scans ?? 0}</div>
            </motion.div>
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="glass rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-4 h-4 text-neon-green" />
                <span className="text-xs text-muted-foreground">Current Score</span>
              </div>
              <div className={`text-2xl font-bold ${scoreColor(lastScore)}`}>{lastScore?.toFixed(0) ?? "—"}%</div>
            </motion.div>
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                {delta !== null && delta > 0 ? (
                  <TrendingUp className="w-4 h-4 text-neon-green" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-critical" />
                )}
                <span className="text-xs text-muted-foreground">Score Change</span>
              </div>
              <div className={`text-2xl font-bold ${delta !== null ? (delta >= 0 ? "text-neon-green" : "text-critical") : "text-muted-foreground"}`}>
                {delta !== null ? `${delta >= 0 ? "+" : ""}${delta.toFixed(1)}%` : "—"}
              </div>
            </motion.div>
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="glass rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-warning" />
                <span className="text-xs text-muted-foreground">Latest Vulns</span>
              </div>
              <div className="text-2xl font-bold text-warning">
                {trends?.trend[trends.trend.length - 1]?.total_vulnerabilities ?? "—"}
              </div>
            </motion.div>
          </div>

          {/* Trend chart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass rounded-xl p-5"
          >
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-sm font-semibold">{selectedRepo?.full_name}</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {trends?.total_scans} scans · Last {Math.min(trends?.total_scans ?? 0, 20)} shown
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><div className="w-3 h-0.5 bg-neon-green" /> Score</span>
                <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm bg-warning/60" /> Vulns</span>
              </div>
            </div>
            <TrendChart trend={trends?.trend ?? []} />
          </motion.div>

          {/* SBOM info card */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="glass rounded-xl p-5 border border-neon-cyan/10"
          >
            <div className="flex items-start justify-between flex-wrap gap-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-neon-cyan/10 rounded-xl flex items-center justify-center border border-neon-cyan/20">
                  <Award className="w-5 h-5 text-neon-cyan" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Software Bill of Materials (SBOM)</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    CycloneDX 1.4 format · Required for SOC 2, ISO 27001, and US Executive Order 14028 compliance
                  </p>
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleSbomDownload("cyclonedx")}
                  className="flex items-center gap-1.5 px-4 py-2 bg-neon-cyan/10 hover:bg-neon-cyan/20 text-neon-cyan rounded-lg text-xs font-mono border border-neon-cyan/20 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" /> Download CycloneDX
                </button>
                <button
                  onClick={() => handleSbomDownload("spdx")}
                  className="flex items-center gap-1.5 px-4 py-2 bg-muted/30 hover:bg-muted/50 text-foreground rounded-lg text-xs font-mono border border-border/40 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" /> Download SPDX
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </div>
  );
};

export default TrendsPage;
