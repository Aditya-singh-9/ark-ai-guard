import { GitBranch, Shield, AlertTriangle, Workflow } from "lucide-react";
import MetricCard from "@/components/dashboard/MetricCard";
import ActivityChart from "@/components/dashboard/ActivityChart";
import VulnerabilityChart from "@/components/dashboard/VulnerabilityChart";
import SecurityScoreGauge from "@/components/dashboard/SecurityScoreGauge";

const DashboardOverview = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold mb-1">Dashboard</h1>
      <p className="text-sm text-muted-foreground">Overview of your security posture.</p>
    </div>

    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <MetricCard title="Total Repositories" value={24} icon={GitBranch} trend="12% this week" trendUp />
      <MetricCard title="Security Score" value="87%" icon={Shield} trend="3% improvement" trendUp />
      <MetricCard title="Vulnerabilities" value={36} icon={AlertTriangle} trend="8 resolved" trendUp />
      <MetricCard title="CI/CD Pipelines" value={18} icon={Workflow} trend="2 new" trendUp />
    </div>

    <div className="grid lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2">
        <ActivityChart />
      </div>
      <div className="glass rounded-xl p-5 flex items-center justify-center relative">
        <SecurityScoreGauge score={87} />
      </div>
    </div>

    <div className="grid lg:grid-cols-2 gap-4">
      <VulnerabilityChart />
      <div className="glass rounded-xl p-5">
        <h3 className="text-sm font-semibold mb-4">Recent Scans</h3>
        <div className="space-y-3">
          {[
            { name: "frontend-app", time: "2 hours ago", status: "Completed" },
            { name: "api-gateway", time: "5 hours ago", status: "Completed" },
            { name: "auth-service", time: "1 day ago", status: "Failed" },
          ].map((s) => (
            <div key={s.name} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
              <div>
                <span className="text-sm font-mono">{s.name}</span>
                <p className="text-xs text-muted-foreground">{s.time}</p>
              </div>
              <span className={`text-xs ${s.status === 'Completed' ? 'text-neon-green' : 'text-critical'}`}>
                {s.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

export default DashboardOverview;
