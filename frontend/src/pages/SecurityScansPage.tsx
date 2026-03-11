import { motion } from "framer-motion";
import { Shield, Search, RefreshCw, CheckCircle, XCircle, Clock, AlertTriangle, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";

const scans = [
  { id: "scan-001", repo: "frontend-app", score: 92, status: "completed", duration: "2m 14s", vulns: 2, time: "2 hours ago" },
  { id: "scan-002", repo: "api-gateway", score: 74, status: "completed", duration: "3m 40s", vulns: 8, time: "5 hours ago" },
  { id: "scan-003", repo: "auth-service", score: 45, status: "failed", duration: "1m 05s", vulns: 0, time: "1 day ago" },
  { id: "scan-004", repo: "payment-service", score: 88, status: "completed", duration: "4m 01s", vulns: 4, time: "3 hours ago" },
  { id: "scan-005", repo: "data-pipeline", score: 67, status: "completed", duration: "5m 22s", vulns: 11, time: "12 hours ago" },
  { id: "scan-006", repo: "ml-inference", score: 95, status: "running", duration: "—", vulns: 0, time: "running now" },
];

const statusConfig = {
  completed: { icon: CheckCircle, color: "text-neon-green", bg: "bg-neon-green/10 border-neon-green/30", label: "Completed" },
  failed: { icon: XCircle, color: "text-critical", bg: "bg-critical/10 border-critical/30", label: "Failed" },
  running: { icon: RefreshCw, color: "text-neon-cyan", bg: "bg-neon-cyan/10 border-neon-cyan/30", label: "Running" },
};

const SecurityScansPage = () => {
  const [running, setRunning] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Security Scans</h1>
          <p className="text-sm text-muted-foreground">Scan history and status across all repositories.</p>
        </div>
        <Button
          className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
          onClick={() => { setRunning(true); setTimeout(() => setRunning(false), 3000); }}
          disabled={running}
        >
          {running ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {running ? "Scanning..." : "Run Full Scan"}
        </Button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total Scans", value: scans.length, color: "text-foreground" },
          { label: "Passed", value: scans.filter(s => s.score >= 70).length, color: "text-neon-green" },
          { label: "Failed / Critical", value: scans.filter(s => s.status === "failed" || s.score < 50).length, color: "text-critical" },
        ].map((s) => (
          <div key={s.label} className="glass rounded-xl p-4 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Scan list */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-xl overflow-hidden"
      >
        <div className="p-4 border-b border-border/50 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Scan History</h3>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <input placeholder="Filter scans..." className="bg-muted rounded-lg pl-8 pr-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-primary/60 w-40 font-mono" />
          </div>
        </div>
        <div className="divide-y divide-border/30">
          {scans.map((scan, i) => {
            const cfg = statusConfig[scan.status as keyof typeof statusConfig];
            const isRunning = scan.status === "running";
            return (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.05 }}
                className="flex items-center gap-4 px-5 py-4 hover:bg-muted/20 transition-colors"
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${cfg.bg} border`}>
                  <cfg.icon className={`w-4 h-4 ${cfg.color} ${isRunning ? "animate-spin" : ""}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{scan.repo}</span>
                    <span className="text-xs text-muted-foreground font-mono">#{scan.id}</span>
                  </div>
                  <div className="flex items-center gap-3 mt-0.5">
                    <span className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="w-3 h-3" />{scan.time}</span>
                    <span className="text-xs text-muted-foreground">⏱ {scan.duration}</span>
                    {scan.vulns > 0 && (
                      <span className="text-xs text-warning flex items-center gap-1"><AlertTriangle className="w-3 h-3" />{scan.vulns} vulns</span>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  {!isRunning && (
                    <div className={`text-lg font-bold ${scan.score >= 80 ? "text-neon-green" : scan.score >= 50 ? "text-warning" : "text-critical"}`}>
                      {scan.score}%
                    </div>
                  )}
                  <Badge variant="outline" className={`text-[10px] font-mono ${cfg.bg}`}>
                    {cfg.label}
                  </Badge>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>
    </div>
  );
};

export default SecurityScansPage;
