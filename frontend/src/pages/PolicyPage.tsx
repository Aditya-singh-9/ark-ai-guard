/**
 * PolicyPage — connects to GET /scans/{id}/policy
 * Shows policy-as-code gate status: PASS / FAIL / WARN with per-rule breakdown.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  CheckCircle2, XCircle, AlertTriangle, Shield, RefreshCw,
  GitBranch, Lock, ChevronRight, Gavel,
} from "lucide-react";
import { getScanPolicy, getRepositories, getRepoScans } from "@/lib/api";

// ── Gate Status badge ─────────────────────────────────────────────────────────

const GateBadge = ({ status }: { status: string }) => {
  const cfgMap: Record<string, { label: string; cls: string; icon: React.ElementType }> = {
    PASS: { label: "Gate PASSED", cls: "bg-neon-green/10 text-neon-green border-neon-green/30", icon: CheckCircle2 },
    WARN: { label: "Gate WARNING", cls: "bg-warning/10 text-warning border-warning/30", icon: AlertTriangle },
    FAIL: { label: "Gate FAILED", cls: "bg-critical/10 text-critical border-critical/30", icon: XCircle },
  };
  const cfg = cfgMap[status] ?? cfgMap.WARN;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 text-sm px-4 py-1.5 rounded-full font-bold border ${cfg.cls}`}>
      <Icon className="w-4 h-4" />
      {cfg.label}
    </span>
  );
};

// ── ViolationCard ─────────────────────────────────────────────────────────────

const ViolationCard = ({
  violation,
  index,
}: {
  violation: { rule: string; action: string; message: string };
  index: number;
}) => {
  const actionCfg: Record<string, { color: string; bg: string; border: string; icon: React.ElementType }> = {
    block: { color: "text-critical", bg: "bg-critical/10", border: "border-critical/30", icon: XCircle },
    warn: { color: "text-warning", bg: "bg-warning/10", border: "border-warning/30", icon: AlertTriangle },
    notify: { color: "text-neon-blue", bg: "bg-neon-blue/10", border: "border-neon-blue/30", icon: Shield },
  };
  const cfg = actionCfg[violation.action.toLowerCase()] ?? actionCfg.notify;
  const Icon = cfg.icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className={`glass rounded-xl border ${cfg.border} p-4 flex items-start gap-4`}
    >
      <div className={`w-9 h-9 rounded-xl ${cfg.bg} border ${cfg.border} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 ${cfg.color}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="text-sm font-semibold font-mono">{violation.rule}</span>
          <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border ${cfg.bg} ${cfg.color} ${cfg.border}`}>
            {violation.action}
          </span>
        </div>
        <p className="text-xs text-muted-foreground">{violation.message}</p>
      </div>
    </motion.div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

const PolicyPage = () => {
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

  const { data: policy, isLoading: policyLoading, error } = useQuery({
    queryKey: ["policy", selectedScanId],
    queryFn: () => getScanPolicy(selectedScanId!),
    enabled: !!selectedScanId,
    retry: 1,
  });

  const completedScans = scans.filter((s: any) => s.status === "completed");
  const violations: Array<{ rule: string; action: string; message: string }> = policy?.violations ?? [];
  const blockViolations = violations.filter((v) => v.action.toLowerCase() === "block");
  const warnViolations = violations.filter((v) => v.action.toLowerCase() === "warn");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Policy Gate</h1>
          <p className="text-sm text-muted-foreground">
            Policy-as-Code enforcement — automated security gates for your CI/CD pipeline.
          </p>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
          <Gavel className="w-3.5 h-3.5" />
          Policy Engine
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
      {policyLoading && (
        <div className="glass rounded-xl p-12 flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 text-neon-green animate-spin" />
          <p className="text-sm text-muted-foreground">Evaluating policy gates…</p>
        </div>
      )}

      {/* Error */}
      {error && !policyLoading && (
        <div className="glass rounded-xl p-6 border border-critical/20 text-center">
          <XCircle className="w-8 h-8 text-critical mx-auto mb-2" />
          <p className="text-sm text-critical">Policy data unavailable for this scan.</p>
        </div>
      )}

      {/* Empty state */}
      {!selectedScanId && !policyLoading && (
        <div className="glass rounded-xl p-12 text-center text-muted-foreground">
          <Lock className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select a repository and completed scan to view policy gate results.</p>
        </div>
      )}

      {/* Results */}
      {policy && !policyLoading && (
        <>
          {/* Gate status banner */}
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className={`glass rounded-xl p-5 border flex flex-col sm:flex-row items-start sm:items-center gap-4 ${
              policy.gate_status === "PASS"
                ? "border-neon-green/30 bg-neon-green/5"
                : policy.gate_status === "FAIL"
                ? "border-critical/30 bg-critical/5"
                : "border-warning/30 bg-warning/5"
            }`}
          >
            <div className="flex-1">
              <GateBadge status={policy.gate_status ?? "WARN"} />
              <p className="text-sm text-muted-foreground mt-2">
                {policy.gate_status === "PASS"
                  ? "All policy rules passed. This build is cleared for deployment."
                  : policy.gate_status === "FAIL"
                  ? "Critical violations found. This build is blocked from deployment."
                  : "Non-blocking warnings found. Review before deploying."}
              </p>
            </div>
            <div className="flex gap-6 text-center">
              <div>
                <p className="text-2xl font-bold font-mono text-critical">{blockViolations.length}</p>
                <p className="text-[10px] text-muted-foreground">Blocking</p>
              </div>
              <div>
                <p className="text-2xl font-bold font-mono text-warning">{warnViolations.length}</p>
                <p className="text-[10px] text-muted-foreground">Warnings</p>
              </div>
              <div>
                <p className="text-2xl font-bold font-mono text-neon-green">{violations.length === 0 ? "All" : violations.length}</p>
                <p className="text-[10px] text-muted-foreground">{violations.length === 0 ? "Rules Passed" : "Total Issues"}</p>
              </div>
            </div>
          </motion.div>

          {/* Violations */}
          {violations.length > 0 ? (
            <div>
              <h2 className="text-sm font-semibold flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-warning" />
                Policy Violations ({violations.length})
              </h2>
              <div className="space-y-3">
                {violations.map((v, i) => (
                  <ViolationCard key={`${v.rule}-${i}`} violation={v} index={i} />
                ))}
              </div>
            </div>
          ) : (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass rounded-xl p-8 text-center border border-neon-green/20"
            >
              <CheckCircle2 className="w-12 h-12 text-neon-green mx-auto mb-3" />
              <h3 className="text-base font-semibold text-neon-green mb-1">All Gates Passed!</h3>
              <p className="text-sm text-muted-foreground">
                Zero policy violations detected. This scan meets all configured security policies.
              </p>
            </motion.div>
          )}

          {/* CI/CD integration hint */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass rounded-xl border border-border/40 p-5"
          >
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-3">
              <GitBranch className="w-4 h-4 text-primary" />
              Integrate with CI/CD
            </h3>
            <p className="text-xs text-muted-foreground mb-3">
              Use the ARK webhook to automatically block merges when the policy gate fails.
              The GitHub webhook at <code className="bg-muted px-1.5 py-0.5 rounded font-mono text-primary">/api/v1/webhooks/github</code> receives push events and triggers this gate automatically.
            </p>
            <div className="bg-muted/60 rounded-lg p-3 font-mono text-xs text-neon-green overflow-x-auto">
              <span className="text-muted-foreground"># Result from API:</span><br />
              {'{'} "gate_status": "{policy.gate_status}", "violations": {violations.length} {'}'}
            </div>
          </motion.div>
        </>
      )}
    </div>
  );
};

export default PolicyPage;
