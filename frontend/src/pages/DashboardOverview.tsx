import {
  GitBranch, Shield, AlertTriangle, Workflow, Clock, CheckCircle2,
  Rocket, Zap, ArrowRight, Github, Lock,
} from "lucide-react";
import MetricCard from "@/components/dashboard/MetricCard";
import ActivityChart from "@/components/dashboard/ActivityChart";
import VulnerabilityChart from "@/components/dashboard/VulnerabilityChart";
import SecurityScoreGauge from "@/components/dashboard/SecurityScoreGauge";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats } from "@/lib/api";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

// ── Onboarding card shown when user has 0 repos ──────────────────────────────

const OnboardingCard = () => (
  <motion.div
    initial={{ opacity: 0, y: 16 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5 }}
    className="glass rounded-2xl border border-primary/20 bg-gradient-to-br from-primary/5 via-transparent to-neon-cyan/5 p-8 text-center relative overflow-hidden"
  >
    {/* Decorative glow */}
    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
    <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/10 rounded-full blur-3xl" />
    <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-neon-cyan/10 rounded-full blur-3xl" />

    <div className="relative z-10">
      <div className="w-16 h-16 bg-primary/15 rounded-2xl flex items-center justify-center mx-auto mb-5 border border-primary/20">
        <Rocket className="w-8 h-8 text-primary" />
      </div>

      <h2 className="text-xl font-bold mb-2">Welcome to DevScops Guard</h2>
      <p className="text-sm text-muted-foreground max-w-md mx-auto mb-8">
        Connect your first GitHub repository to start scanning for vulnerabilities,
        get AI-powered security recommendations, and auto-generate hardened CI/CD pipelines.
      </p>

      {/* Steps */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8 text-left">
        {[
          {
            step: "01",
            icon: Github,
            title: "Connect a Repo",
            desc: "Import directly from GitHub or paste a URL",
            color: "text-primary",
            bg: "bg-primary/10",
            border: "border-primary/20",
          },
          {
            step: "02",
            icon: Zap,
            title: "Run a Scan",
            desc: "Semgrep, Bandit, Trivy + AI analysis in one click",
            color: "text-neon-cyan",
            bg: "bg-neon-cyan/10",
            border: "border-neon-cyan/20",
          },
          {
            step: "03",
            icon: Shield,
            title: "Fix & Harden",
            desc: "Get a prioritised fix list and auto-generated CI/CD YAML",
            color: "text-neon-green",
            bg: "bg-neon-green/10",
            border: "border-neon-green/20",
          },
        ].map(({ step, icon: Icon, title, desc, color, bg, border }) => (
          <div key={step} className={`glass rounded-xl p-4 border ${border} text-left`}>
            <div className={`w-9 h-9 ${bg} rounded-xl flex items-center justify-center mb-3 border ${border}`}>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">STEP {step}</div>
            <p className="text-sm font-semibold mb-1">{title}</p>
            <p className="text-xs text-muted-foreground">{desc}</p>
          </div>
        ))}
      </div>

      {/* CTAs */}
      <div className="flex flex-wrap gap-3 justify-center">
        <Link to="/dashboard/repos">
          <Button className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2">
            <Github className="w-4 h-4" />
            Connect First Repository
            <ArrowRight className="w-4 h-4" />
          </Button>
        </Link>
        <Link to="/dashboard/scans">
          <Button variant="outline" className="gap-2 border-border/60">
            <Zap className="w-4 h-4" />
            View Scan Demo
          </Button>
        </Link>
      </div>

      {/* Real-world problem callout */}
      <div className="mt-8 pt-6 border-t border-border/30">
        <p className="text-xs text-muted-foreground font-medium mb-3">Problems we solve for developers every day:</p>
        <div className="flex flex-wrap gap-2 justify-center">
          {[
            "🔐 Secret exposure in commits",
            "📦 Vulnerable dependencies",
            "🔓 OWASP Top 10 violations",
            "🏗️ Insecure CI/CD pipelines",
            "⚠️ Hardcoded credentials",
            "🛡️ Missing auth guards",
          ].map((tag) => (
            <span
              key={tag}
              className="text-[11px] px-2.5 py-1 bg-muted/50 rounded-full text-muted-foreground border border-border/40"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  </motion.div>
);

// ── Main dashboard ────────────────────────────────────────────────────────────

const DashboardOverview = () => {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
    refetchInterval: 15000,
  });

  const score = stats?.average_security_score ?? 0;
  const recentRepos = stats?.repositories?.slice(0, 4) ?? [];
  const hasRepos = (stats?.total_repositories ?? 0) > 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Dashboard Overview</h1>
        <p className="text-sm text-muted-foreground">Your security posture at a glance.</p>
      </div>

      {/* Onboarding (zero-state) */}
      {!isLoading && !hasRepos && <OnboardingCard />}

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
          value={isLoading ? "—" : score ? `${score.toFixed(0)}%` : "N/A"}
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

      {/* Charts row (only show when data exists) */}
      {(isLoading || hasRepos) && (
        <>
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
                  {[1, 2, 3, 4].map((i) => (
                    <div key={i} className="h-14 bg-muted/30 rounded-lg animate-pulse" />
                  ))}
                </div>
              ) : recentRepos.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Lock className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No scans yet.</p>
                  <Link to="/dashboard/repos" className="text-xs text-primary hover:underline mt-1 inline-block">
                    Add a repository →
                  </Link>
                </div>
              ) : (
                <div className="space-y-3">
                  {recentRepos.map((repo) => (
                    <div
                      key={repo.id}
                      className="flex items-center justify-between py-2.5 px-3 rounded-lg hover:bg-muted/30 transition-colors cursor-pointer"
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
                        {repo.security_score !== null && (
                          <p className={`text-sm font-bold font-mono ${
                            (repo.security_score ?? 0) >= 80 ? "text-neon-green" :
                            (repo.security_score ?? 0) >= 50 ? "text-warning" : "text-critical"
                          }`}>
                            {repo.security_score?.toFixed(0)}%
                          </p>
                        )}
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
        </>
      )}
    </div>
  );
};

export default DashboardOverview;
