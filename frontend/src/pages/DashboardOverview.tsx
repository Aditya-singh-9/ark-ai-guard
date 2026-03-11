import { GitBranch, Shield, AlertTriangle, Workflow, TrendingUp, Clock, CheckCircle2 } from "lucide-react";
import MetricCard from "@/components/dashboard/MetricCard";
import ActivityChart from "@/components/dashboard/ActivityChart";
import VulnerabilityChart from "@/components/dashboard/VulnerabilityChart";
import SecurityScoreGauge from "@/components/dashboard/SecurityScoreGauge";
import { motion } from "framer-motion";

const recentScans = [
  { name: "frontend-app", time: "2 hours ago", status: "Completed", vulns: 2 },
  { name: "api-gateway", time: "5 hours ago", status: "Completed", vulns: 8 },
  { name: "auth-service", time: "1 day ago", status: "Failed", vulns: 0 },
  { name: "ml-inference", time: "30 min ago", status: "Completed", vulns: 1 },
];

const DashboardOverview = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold mb-1">Dashboard Overview</h1>
      <p className="text-sm text-muted-foreground">Your security posture at a glance.</p>
    </div>

    {/* Metric cards */}
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <MetricCard
        title="Total Repositories"
        value={24}
        icon={GitBranch}
        trend="12% this week"
        trendUp
        color="cyan"
        delay={0}
      />
      <MetricCard
        title="Security Score"
        value="87%"
        icon={Shield}
        trend="3% improvement"
        trendUp
        color="green"
        delay={0.08}
      />
      <MetricCard
        title="Vulnerabilities"
        value={36}
        icon={AlertTriangle}
        trend="8 resolved"
        trendUp
        color="orange"
        delay={0.16}
      />
      <MetricCard
        title="Pipelines Generated"
        value={18}
        icon={Workflow}
        trend="2 new today"
        trendUp
        color="purple"
        delay={0.24}
      />
    </div>

    {/* Charts row */}
    <div className="grid lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2">
        <ActivityChart />
      </div>
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="glass rounded-xl p-5 flex flex-col items-center justify-center"
      >
        <SecurityScoreGauge score={87} />
      </motion.div>
    </div>

    {/* Second charts row */}
    <div className="grid lg:grid-cols-2 gap-4">
      <VulnerabilityChart />

      {/* Recent Scans */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.45 }}
        className="glass rounded-xl p-5"
      >
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-sm font-semibold">Recent Scans</h3>
            <p className="text-xs text-muted-foreground mt-0.5">Latest repository scans</p>
          </div>
          <button className="text-xs text-primary hover:underline">View all</button>
        </div>
        <div className="space-y-3">
          {recentScans.map((s, i) => (
            <div
              key={s.name}
              className="flex items-center justify-between py-2.5 px-3 rounded-lg hover:bg-muted/30 transition-colors group cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                  s.status === "Completed" ? "bg-neon-green/10" : "bg-critical/10"
                }`}>
                  {s.status === "Completed" ? (
                    <CheckCircle2 className="w-4 h-4 text-neon-green" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-critical" />
                  )}
                </div>
                <div>
                  <span className="text-sm font-mono font-medium">{s.name}</span>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Clock className="w-3 h-3 text-muted-foreground" />
                    <p className="text-xs text-muted-foreground">{s.time}</p>
                  </div>
                </div>
              </div>
              <div className="text-right">
                <span className={`text-xs font-medium ${
                  s.status === "Completed" ? "text-neon-green" : "text-critical"
                }`}>
                  {s.status}
                </span>
                {s.vulns > 0 && (
                  <p className="text-xs text-muted-foreground mt-0.5">{s.vulns} vulns</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  </div>
);

export default DashboardOverview;
