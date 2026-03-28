import { GitBranch, Shield, AlertTriangle, Workflow, Clock, CheckCircle2 } from "lucide-react";
import MetricCard from "@/components/dashboard/MetricCard";
import ActivityChart from "@/components/dashboard/ActivityChart";
import VulnerabilityChart from "@/components/dashboard/VulnerabilityChart";
import SecurityScoreGauge from "@/components/dashboard/SecurityScoreGauge";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats } from "@/lib/api";
import { Link } from "react-router-dom";

const DashboardOverview = () => {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
  });

  const score = stats?.average_security_score ?? 0;
  const recentRepos = stats?.repositories?.slice(0, 4) ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Dashboard Overview</h1>
        <p className="text-sm text-muted-foreground">Your security posture at a glance.</p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Repositories"
          value={isLoading ? "—" : stats?.total_repositories ?? 0}
          icon={GitBranch}
          trend="connected repos"
          trendUp
          color="cyan"
          delay={0}
        />
        <MetricCard
          title="Security Score"
          value={isLoading ? "—" : score ? `${score}%` : "N/A"}
          icon={Shield}
          trend="avg across scanned repos"
          trendUp={score >= 70}
          color="green"
          delay={0.08}
        />
        <MetricCard
          title="Vulnerabilities"
          value={isLoading ? "—" : stats?.total_vulnerabilities ?? 0}
          icon={AlertTriangle}
          trend={stats ? `${stats.critical_count} critical` : "—"}
          trendUp={false}
          color="orange"
          delay={0.16}
        />
        <MetricCard
          title="Total Scans"
          value={isLoading ? "—" : stats?.total_scans ?? 0}
          icon={Workflow}
          trend="all time"
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
          <SecurityScoreGauge score={score} />
        </motion.div>
      </div>

      {/* Second charts row */}
      <div className="grid lg:grid-cols-2 gap-4">
        <VulnerabilityChart
          critical={stats?.critical_count ?? 0}
          high={stats?.high_count ?? 0}
          medium={stats?.medium_count ?? 0}
          low={stats?.low_count ?? 0}
        />

        {/* Recent Repos */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.45 }}
          className="glass rounded-xl p-5"
        >
          <div className="flex items-center justify-between mb-5">
            <div>
              <h3 className="text-sm font-semibold">Recent Repository Scans</h3>
              <p className="text-xs text-muted-foreground mt-0.5">Latest scan results per repo</p>
            </div>
            <Link to="/dashboard/scans" className="text-xs text-primary hover:underline">View all</Link>
          </div>

          {isLoading ? (
            <div className="space-y-3">
              {[1,2,3,4].map(i => (
                <div key={i} className="h-14 bg-muted/30 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : recentRepos.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <GitBranch className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No repositories connected yet.</p>
              <Link to="/dashboard/repos" className="text-xs text-primary hover:underline mt-1 inline-block">
                Add a repository →
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentRepos.map((repo) => (
                <div
                  key={repo.id}
                  className="flex items-center justify-between py-2.5 px-3 rounded-lg hover:bg-muted/30 transition-colors group cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      repo.scan_status === "completed" ? "bg-neon-green/10" : "bg-critical/10"
                    }`}>
                      {repo.scan_status === "completed" ? (
                        <CheckCircle2 className="w-4 h-4 text-neon-green" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-critical" />
                      )}
                    </div>
                    <div>
                      <span className="text-sm font-mono font-medium">{repo.name}</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <Clock className="w-3 h-3 text-muted-foreground" />
                        <p className="text-xs text-muted-foreground">
                          {repo.last_scanned_at
                            ? new Date(repo.last_scanned_at).toLocaleDateString()
                            : "Never scanned"}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`text-xs font-medium ${
                      repo.scan_status === "completed" ? "text-neon-green" : "text-critical"
                    }`}>
                      {repo.scan_status === "never_scanned" ? "Not scanned" : repo.scan_status}
                    </span>
                    {repo.total_vulnerabilities > 0 && (
                      <p className="text-xs text-muted-foreground mt-0.5">{repo.total_vulnerabilities} vulns</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
};

export default DashboardOverview;
