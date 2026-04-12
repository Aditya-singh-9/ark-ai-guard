/**
 * CompliancePage — connects to GET /scans/{id}/compliance
 * Shows SOC2, PCI DSS, HIPAA, ISO 27001 compliance analysis powered by Mythos AI.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, ChevronDown,
  ChevronRight, FileText, RefreshCw, Lock, Award, GitBranch,
} from "lucide-react";
import { getScanCompliance, getRepositories, getRepoScans } from "@/lib/api";
import { toast } from "sonner";

// ── Framework config ──────────────────────────────────────────────────────────

const FRAMEWORK_CONFIG: Record<string, { color: string; bg: string; border: string; icon: string }> = {
  "SOC 2": { color: "text-neon-blue", bg: "bg-neon-blue/10", border: "border-neon-blue/30", icon: "🛡️" },
  "PCI DSS": { color: "text-warning", bg: "bg-warning/10", border: "border-warning/30", icon: "💳" },
  "HIPAA": { color: "text-neon-green", bg: "bg-neon-green/10", border: "border-neon-green/30", icon: "🏥" },
  "ISO 27001": { color: "text-neon-purple", bg: "bg-neon-purple/10", border: "border-neon-purple/30", icon: "🔒" },
  "GDPR": { color: "text-neon-cyan", bg: "bg-neon-cyan/10", border: "border-neon-cyan/30", icon: "🇪🇺" },
  "NIST": { color: "text-primary", bg: "bg-primary/10", border: "border-primary/30", icon: "🏛️" },
};

const defaultConfig = { color: "text-muted-foreground", bg: "bg-muted/30", border: "border-border/40", icon: "📋" };

// ── ComplianceFrameworkCard ───────────────────────────────────────────────────

const ComplianceFrameworkCard = ({
  framework,
  violations,
  index,
}: {
  framework: string;
  violations: string[];
  index: number;
}) => {
  const [expanded, setExpanded] = useState(false);
  const cfg = FRAMEWORK_CONFIG[framework] ?? defaultConfig;
  const passed = violations.length === 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.07 }}
      className={`glass rounded-xl border ${cfg.border} overflow-hidden`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 p-4 hover:bg-muted/20 transition-colors"
      >
        <div className={`w-10 h-10 rounded-xl ${cfg.bg} border ${cfg.border} flex items-center justify-center text-lg flex-shrink-0`}>
          {cfg.icon}
        </div>
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className={`text-sm font-bold ${cfg.color}`}>{framework}</span>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono border ${
              passed
                ? "bg-neon-green/10 text-neon-green border-neon-green/30"
                : "bg-critical/10 text-critical border-critical/30"
            }`}>
              {passed ? "✓ Compliant" : `${violations.length} violation${violations.length !== 1 ? "s" : ""}`}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            {passed ? "No violations detected in this scan" : "Click to expand violations"}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {passed ? (
            <CheckCircle2 className="w-5 h-5 text-neon-green" />
          ) : (
            <XCircle className="w-5 h-5 text-critical" />
          )}
          {!passed && (
            expanded ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />
          )}
        </div>
      </button>

      <AnimatePresence>
        {expanded && violations.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-border/40 overflow-hidden"
          >
            <div className="p-4 space-y-2">
              {violations.map((v, i) => (
                <div key={i} className="flex items-start gap-2 p-3 bg-critical/5 border border-critical/20 rounded-lg">
                  <AlertTriangle className="w-3.5 h-3.5 text-critical flex-shrink-0 mt-0.5" />
                  <span className="text-xs text-foreground/80">{v}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

const CompliancePage = () => {
  const [selectedRepoId, setSelectedRepoId] = useState<number | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const { data: repos = [], isLoading: reposLoading } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
  });

  const { data: scans = [], isLoading: scansLoading } = useQuery({
    queryKey: ["repo-scans", selectedRepoId],
    queryFn: () => getRepoScans(selectedRepoId!, 5),
    enabled: !!selectedRepoId,
  });

  const { data: compliance, isLoading: compLoading, error } = useQuery({
    queryKey: ["compliance", selectedScanId],
    queryFn: () => getScanCompliance(selectedScanId!),
    enabled: !!selectedScanId,
    retry: 1,
  });

  const completedScans = scans.filter((s: any) => s.status === "completed");

  const frameworkEntries = compliance?.compliance_summary
    ? Object.entries(compliance.compliance_summary as Record<string, string[]>)
    : [];

  const totalViolations = frameworkEntries.reduce((sum, [, v]) => sum + (v as string[]).length, 0);
  const compliantFrameworks = frameworkEntries.filter(([, v]) => (v as string[]).length === 0).length;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Compliance Analysis</h1>
          <p className="text-sm text-muted-foreground">
            SOC 2, PCI DSS, HIPAA, ISO 27001 & GDPR compliance powered by Mythos AI.
          </p>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-purple/10 border border-neon-purple/20 text-xs text-neon-purple font-medium">
          <Award className="w-3.5 h-3.5" />
          Mythos AI
        </div>
      </div>

      {/* Selector row */}
      <div className="glass rounded-xl p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-muted-foreground font-mono mb-1.5 block">Repository</label>
          <select
            className="w-full bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono"
            value={selectedRepoId ?? ""}
            onChange={(e) => {
              const id = e.target.value ? Number(e.target.value) : null;
              setSelectedRepoId(id);
              setSelectedScanId(null);
            }}
          >
            <option value="">Select a repository…</option>
            {repos.map((r: any) => (
              <option key={r.id} value={r.id}>{r.full_name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground font-mono mb-1.5 block">Scan</label>
          <select
            className="w-full bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono disabled:opacity-50"
            value={selectedScanId ?? ""}
            onChange={(e) => setSelectedScanId(e.target.value ? Number(e.target.value) : null)}
            disabled={!selectedRepoId || scansLoading}
          >
            <option value="">Select a scan…</option>
            {completedScans.map((s: any) => (
              <option key={s.scan_id} value={s.scan_id}>
                Scan #{s.scan_id} — {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : "Unknown date"}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Loading */}
      {compLoading && (
        <div className="glass rounded-xl p-12 flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 text-neon-purple animate-spin" />
          <p className="text-sm text-muted-foreground">Mythos AI analyzing compliance…</p>
        </div>
      )}

      {/* Error */}
      {error && !compLoading && (
        <div className="glass rounded-xl p-6 border border-critical/20 text-center">
          <XCircle className="w-8 h-8 text-critical mx-auto mb-2" />
          <p className="text-sm text-critical">This scan has no compliance data. Re-run the scan to generate it.</p>
        </div>
      )}

      {/* No selection */}
      {!selectedScanId && !compLoading && (
        <div className="glass rounded-xl p-12 text-center text-muted-foreground">
          <Lock className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select a repository and a completed scan to view compliance analysis.</p>
        </div>
      )}

      {/* Summary row */}
      {compliance && !compLoading && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Frameworks", value: frameworkEntries.length, color: "text-foreground" },
              { label: "Compliant", value: compliantFrameworks, color: "text-neon-green" },
              { label: "Violations", value: totalViolations, color: "text-critical" },
              { label: "Risk Level", value: compliance.risk_level ?? "N/A", color: "text-warning" },
            ].map((m) => (
              <motion.div
                key={m.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass rounded-xl p-4 text-center"
              >
                <div className={`text-2xl font-bold font-mono ${m.color}`}>{m.value}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{m.label}</div>
              </motion.div>
            ))}
          </div>

          {/* Framework cards */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <FileText className="w-4 h-4 text-primary" />
              Framework-by-Framework Breakdown
            </h2>
            {frameworkEntries.length === 0 ? (
              <div className="glass rounded-xl p-6 text-center text-muted-foreground text-sm">
                No compliance framework data for this scan.
              </div>
            ) : (
              frameworkEntries.map(([framework, violations], i) => (
                <ComplianceFrameworkCard
                  key={framework}
                  framework={framework}
                  violations={violations as string[]}
                  index={i}
                />
              ))
            )}
          </div>

          {/* AI Summary */}
          {compliance.executive_summary && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl border border-neon-purple/20 p-5"
            >
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-neon-purple" />
                Mythos AI Executive Summary
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{compliance.executive_summary}</p>
            </motion.div>
          )}
        </>
      )}
    </div>
  );
};

export default CompliancePage;
