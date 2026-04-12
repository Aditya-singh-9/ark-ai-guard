/**
 * ThreatAnalysisPage — connects to GET /scans/{id}/threat-analysis
 * Shows STRIDE threat model, attack surface score, risk level, and MITRE ATT&CK mappings.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle, Shield, Zap, RefreshCw, Target, Activity,
  Lock, Eye, Server, Database, Globe, ChevronRight, XCircle,
} from "lucide-react";
import { getScanThreatAnalysis, getRepositories, getRepoScans } from "@/lib/api";

// ── STRIDE config ─────────────────────────────────────────────────────────────

const STRIDE_CONFIG: Record<string, { label: string; icon: React.ElementType; color: string; bg: string; border: string; desc: string }> = {
  spoofing: {
    label: "Spoofing", icon: Eye, color: "text-neon-purple", bg: "bg-neon-purple/10", border: "border-neon-purple/30",
    desc: "Identity impersonation and authentication bypass",
  },
  tampering: {
    label: "Tampering", icon: Database, color: "text-warning", bg: "bg-warning/10", border: "border-warning/30",
    desc: "Unauthorized data modification",
  },
  repudiation: {
    label: "Repudiation", icon: FileX, color: "text-neon-blue", bg: "bg-neon-blue/10", border: "border-neon-blue/30",
    desc: "Denial of actions without trace",
  },
  information_disclosure: {
    label: "Info Disclosure", icon: Globe, color: "text-critical", bg: "bg-critical/10", border: "border-critical/30",
    desc: "Exposure of sensitive data",
  },
  denial_of_service: {
    label: "Denial of Service", icon: Server, color: "text-warning", bg: "bg-warning/10", border: "border-warning/30",
    desc: "Making system unavailable",
  },
  elevation_of_privilege: {
    label: "Elevation of Privilege", icon: Zap, color: "text-critical", bg: "bg-critical/10", border: "border-critical/30",
    desc: "Gaining unauthorized access levels",
  },
};

// FileX icon fallback
function FileX({ className }: { className?: string }) {
  return <Lock className={className} />;
}

// ── Risk Badge ────────────────────────────────────────────────────────────────

const RiskBadge = ({ level }: { level: string }) => {
  const cfg: Record<string, string> = {
    CRITICAL: "bg-critical/10 text-critical border-critical/30",
    HIGH: "bg-warning/10 text-warning border-warning/30",
    MEDIUM: "bg-neon-blue/10 text-neon-blue border-neon-blue/30",
    LOW: "bg-neon-green/10 text-neon-green border-neon-green/30",
    INFO: "bg-muted/30 text-muted-foreground border-border/40",
  };
  return (
    <span className={`text-xs px-3 py-1 rounded-full font-bold border font-mono ${cfg[level] ?? cfg.INFO}`}>
      {level}
    </span>
  );
};

// ── AttackSurfaceMeter ────────────────────────────────────────────────────────

const AttackSurfaceMeter = ({ score }: { score: number }) => {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 70 ? "from-critical to-critical/70" : pct >= 40 ? "from-warning to-warning/70" : "from-neon-green to-neon-green/70";

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <span className="text-xs text-muted-foreground font-mono">Attack Surface Score</span>
        <span className="text-sm font-bold font-mono">{pct.toFixed(0)}/100</span>
      </div>
      <div className="h-3 bg-muted rounded-full overflow-hidden">
        <motion.div
          className={`h-full rounded-full bg-gradient-to-r ${color}`}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        {pct >= 70 ? "🔴 High exposure — prioritize remediation" :
         pct >= 40 ? "🟡 Moderate exposure — review findings" :
         "🟢 Low exposure — good security posture"}
      </p>
    </div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

const ThreatAnalysisPage = () => {
  const [selectedRepoId, setSelectedRepoId] = useState<number | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
  });

  const { data: scans = [], isLoading: scansLoading } = useQuery({
    queryKey: ["repo-scans", selectedRepoId],
    queryFn: () => getRepoScans(selectedRepoId!, 5),
    enabled: !!selectedRepoId,
  });

  const { data: threat, isLoading: threatLoading, error } = useQuery({
    queryKey: ["threat-analysis", selectedScanId],
    queryFn: () => getScanThreatAnalysis(selectedScanId!),
    enabled: !!selectedScanId,
    retry: 1,
  });

  const completedScans = scans.filter((s: any) => s.status === "completed");
  const strideEntries = threat?.stride_model ? Object.entries(threat.stride_model) : [];
  const analyses = threat?.analyses ?? [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Threat Analysis</h1>
          <p className="text-sm text-muted-foreground">
            STRIDE threat modeling and MITRE ATT&CK mappings powered by Mythos AI.
          </p>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-critical/10 border border-critical/20 text-xs text-critical font-medium">
          <Target className="w-3.5 h-3.5" />
          Threat Model
        </div>
      </div>

      {/* Selector */}
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
            {(repos as any[]).map((r) => (
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
                Scan #{s.scan_id} — {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : "—"}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Loading */}
      {threatLoading && (
        <div className="glass rounded-xl p-12 flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 text-critical animate-spin" />
          <p className="text-sm text-muted-foreground">Mythos AI building threat model…</p>
        </div>
      )}

      {/* Error */}
      {error && !threatLoading && (
        <div className="glass rounded-xl p-6 border border-critical/20 text-center">
          <XCircle className="w-8 h-8 text-critical mx-auto mb-2" />
          <p className="text-sm text-critical">Threat data unavailable. Re-run the scan to generate it.</p>
        </div>
      )}

      {/* No selection */}
      {!selectedScanId && !threatLoading && (
        <div className="glass rounded-xl p-12 text-center text-muted-foreground">
          <Target className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select a repository and completed scan to view threat analysis.</p>
        </div>
      )}

      {/* Results */}
      {threat && !threatLoading && (
        <>
          {/* Summary row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Risk Level", value: <RiskBadge level={threat.overall_risk_level ?? "N/A"} />, bg: "" },
              { label: "Findings Analyzed", value: analyses.length, color: "text-foreground" },
              { label: "STRIDE Threats", value: strideEntries.filter(([, v]: any) => (v as any[]).length > 0).length, color: "text-critical" },
              { label: "Attack Surface", value: `${(threat.attack_surface_score ?? 0).toFixed(0)}/100`, color: "text-warning" },
            ].map((m: any) => (
              <motion.div
                key={m.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass rounded-xl p-4 text-center"
              >
                <div className={`text-xl font-bold font-mono ${m.color ?? ""} flex justify-center`}>{m.value}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{m.label}</div>
              </motion.div>
            ))}
          </div>

          {/* Attack surface meter */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass rounded-xl p-5 border border-warning/20"
          >
            <AttackSurfaceMeter score={threat.attack_surface_score ?? 0} />
          </motion.div>

          {/* STRIDE threat grid */}
          {strideEntries.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-primary" />
                STRIDE Threat Model
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {strideEntries.map(([threat_type, items]: [string, any], i) => {
                  const cfg = STRIDE_CONFIG[threat_type] ?? {
                    label: threat_type, icon: AlertTriangle,
                    color: "text-muted-foreground", bg: "bg-muted/20", border: "border-border/40",
                    desc: "",
                  };
                  const Icon = cfg.icon;
                  const count = Array.isArray(items) ? items.length : 0;
                  return (
                    <motion.div
                      key={threat_type}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.06 }}
                      className={`glass rounded-xl border ${cfg.border} p-4`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <div className={`w-9 h-9 rounded-xl ${cfg.bg} border ${cfg.border} flex items-center justify-center`}>
                          <Icon className={`w-4 h-4 ${cfg.color}`} />
                        </div>
                        <div>
                          <p className={`text-sm font-semibold ${cfg.color}`}>{cfg.label}</p>
                          <p className="text-[10px] text-muted-foreground">{count} threat{count !== 1 ? "s" : ""} detected</p>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">{cfg.desc}</p>
                      {count > 0 && Array.isArray(items) && (
                        <div className="mt-2 space-y-1">
                          {(items as string[]).slice(0, 2).map((item, j) => (
                            <div key={j} className="flex items-start gap-1.5">
                              <ChevronRight className={`w-3 h-3 ${cfg.color} flex-shrink-0 mt-0.5`} />
                              <span className="text-xs text-foreground/70 truncate">{item}</span>
                            </div>
                          ))}
                          {count > 2 && (
                            <p className="text-[10px] text-muted-foreground pl-4">+{count - 2} more…</p>
                          )}
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Threat model summary */}
          {threat.threat_model_summary && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl border border-critical/20 p-5"
            >
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-critical" />
                Mythos Threat Intelligence Summary
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{threat.threat_model_summary}</p>
            </motion.div>
          )}

          {/* Executive brief */}
          {threat.executive_brief && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl border border-neon-purple/20 p-5"
            >
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-neon-purple" />
                Executive Brief
              </h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{threat.executive_brief}</p>
            </motion.div>
          )}
        </>
      )}
    </div>
  );
};

export default ThreatAnalysisPage;
