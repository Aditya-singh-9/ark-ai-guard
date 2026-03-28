import VulnerabilityCard from "@/components/dashboard/VulnerabilityCard";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, AlertTriangle, Search, RefreshCw, ChevronDown, Check } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { getRepositories, getLatestScanResult, getVulnerabilityReport } from "@/lib/api";
import { useSearchParams } from "react-router-dom";

// Custom dark-themed dropdown — avoids OS white native select on Windows
const DarkSelect = ({
  options,
  value,
  onChange,
  placeholder = "Select…",
}: {
  options: { label: string; value: number | string }[];
  value: number | string | null;
  onChange: (v: number | string | null) => void;
  placeholder?: string;
}) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const selected = options.find((o) => o.value === value);

  return (
    <div ref={ref} className="relative flex-1">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-2 bg-transparent text-sm font-mono outline-none"
      >
        <span className={selected ? "text-foreground" : "text-muted-foreground"}>
          {selected?.label ?? placeholder}
        </span>
        <ChevronDown
          className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${open ? "rotate-180" : ""}`}
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.15 }}
            className="absolute top-[calc(100%+12px)] left-0 right-0 z-50 glass border border-border/60 rounded-xl shadow-2xl overflow-hidden"
          >
            {/* Placeholder option */}
            <button
              onClick={() => { onChange(null); setOpen(false); }}
              className="w-full text-left px-4 py-3 text-sm text-muted-foreground hover:bg-muted/40 transition-colors flex items-center gap-2"
            >
              <span className="flex-1 font-mono">— Select a repository —</span>
              {!value && <Check className="w-3.5 h-3.5 text-primary" />}
            </button>
            <div className="border-t border-border/40" />
            {options.map((opt) => (
              <button
                key={opt.value}
                onClick={() => { onChange(opt.value); setOpen(false); }}
                className="w-full text-left px-4 py-3 text-sm hover:bg-primary/10 transition-colors flex items-center gap-2 group"
              >
                <span className="flex-1 font-mono text-foreground/90 group-hover:text-foreground">
                  {opt.label}
                </span>
                {value === opt.value && <Check className="w-3.5 h-3.5 text-primary flex-shrink-0" />}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const VulnerabilitiesPage = () => {
  const [filter, setFilter] = useState<string>("all");
  const [selectedRepoId, setSelectedRepoId] = useState<number | null>(null);
  const [searchParams] = useSearchParams();

  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
  });

  // Auto-select repo if passed via query param
  useEffect(() => {
    const rid = searchParams.get("repoId");
    if (rid) setSelectedRepoId(Number(rid));
  }, [searchParams]);

  const { data: latestScan, isLoading: loadingScan } = useQuery({
    queryKey: ["latest-scan", selectedRepoId],
    queryFn: () => getLatestScanResult(selectedRepoId!),
    enabled: !!selectedRepoId,
  });

  const { data: report, isLoading: loadingReport } = useQuery({
    queryKey: ["vuln-report", latestScan?.scan_id],
    queryFn: () => getVulnerabilityReport(latestScan!.scan_id),
    enabled: !!latestScan?.scan_id && latestScan.status === "completed",
  });

  const vulns = report?.vulnerabilities ?? [];
  const filtered = filter === "all" ? vulns : vulns.filter((v) => v.severity === filter);

  const counts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };

  const isLoading = loadingScan || loadingReport;

  const repoOptions = repos.map((r) => ({ label: r.full_name, value: r.id }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Vulnerability Reports</h1>
        <p className="text-sm text-muted-foreground">
          {selectedRepoId && report
            ? `${vulns.length} vulnerabilities detected in ${report.repository_name}`
            : "Select a repository to view vulnerability details."}
        </p>
      </div>

      {/* Repository selector */}
      <div className="glass rounded-xl p-4 flex items-center gap-3">
        <Search className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        <DarkSelect
          options={repoOptions}
          value={selectedRepoId}
          onChange={(v) => setSelectedRepoId(v ? Number(v) : null)}
          placeholder="Select a repository to view vulnerabilities"
        />
      </div>

      {selectedRepoId && (
        <>
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
                <div className={`text-2xl font-bold ${item.color}`}>
                  {isLoading ? "—" : item.count}
                </div>
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

          {/* Loading */}
          {isLoading && (
            <div className="flex items-center gap-3 py-12 justify-center text-muted-foreground">
              <RefreshCw className="w-5 h-5 animate-spin" />
              <span className="text-sm">Loading vulnerability data...</span>
            </div>
          )}

          {/* No scan yet / still running */}
          {!isLoading && latestScan && latestScan.status !== "completed" && (
            <div className="text-center py-16 text-muted-foreground glass rounded-xl">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">
                {latestScan.status === "running" || latestScan.status === "pending"
                  ? "Scan is still running. Results will appear when it completes."
                  : "The last scan failed. Try scanning again from the Repositories page."}
              </p>
            </div>
          )}

          {/* No scans at all */}
          {!isLoading && !latestScan && (
            <div className="text-center py-16 text-muted-foreground glass rounded-xl">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No scans found for this repository.</p>
              <p className="text-xs mt-1 text-primary/70">
                Go to Repositories and click "Scan" to start.
              </p>
            </div>
          )}

          {/* Vulnerability cards */}
          {!isLoading && report && (
            <div className="grid gap-4 md:grid-cols-2">
              {filtered.map((v, i) => (
                <VulnerabilityCard
                  key={v.id}
                  file={v.file ?? "unknown"}
                  issue={v.issue}
                  severity={v.severity as "critical" | "high" | "medium" | "low"}
                  fix={v.suggested_fix ?? "Review and remediate this vulnerability."}
                  snippet={v.code_snippet ?? ""}
                  index={i}
                />
              ))}
              {filtered.length === 0 && (
                <div className="col-span-2 text-center py-16 text-muted-foreground glass rounded-xl">
                  <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No vulnerabilities of this severity level.</p>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default VulnerabilitiesPage;
