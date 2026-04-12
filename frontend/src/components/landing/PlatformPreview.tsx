import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle, GitBranch, Workflow, TrendingUp, Lock } from "lucide-react";
import { Link } from "react-router-dom";

const PlatformPreview = () => {
  return (
    <section className="py-28 px-4 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-neon-blue/4 rounded-full blur-[200px] pointer-events-none" />

      <div className="max-w-6xl mx-auto relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="text-xs font-mono text-primary uppercase tracking-widest mb-4 block">Platform</span>
          <h2 className="text-4xl md:text-5xl font-bold mb-5">
            <span className="gradient-text">Dashboard Preview</span>
          </h2>
          <p className="text-muted-foreground text-lg max-w-xl mx-auto">
            A glimpse of your DevSecOps command center.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="relative"
        >
          {/* Browser chrome */}
          <div className="glass rounded-2xl overflow-hidden neon-glow border border-border/50">
            {/* Browser bar */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-border/50 bg-muted/30">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-critical/70" />
                <div className="w-3 h-3 rounded-full bg-warning/70" />
                <div className="w-3 h-3 rounded-full bg-neon-green/70" />
              </div>
              <div className="flex-1 bg-background/50 rounded-lg h-6 flex items-center px-3 text-xs text-muted-foreground/60 font-mono">
                ark-devsecops.ai/dashboard
              </div>
            </div>

            {/* Dashboard mockup */}
            <div className="flex h-[480px] bg-background/60">
              {/* Sidebar mockup */}
              <div className="w-48 border-r border-border/40 p-3 flex-shrink-0" style={{ background: "hsl(var(--sidebar-background))" }}>
                <div className="flex items-center gap-2 mb-5 px-2">
                  <Shield className="w-4 h-4 text-primary" />
                  <span className="text-xs font-bold">DevScops Guard</span>
                </div>
                {[
                  { icon: TrendingUp, label: "Dashboard", active: true },
                  { icon: GitBranch, label: "Repositories" },
                  { icon: Shield, label: "Security Scans" },
                  { icon: AlertTriangle, label: "Vulnerabilities" },
                  { icon: Workflow, label: "CI/CD Generator" },
                ].map((item) => (
                  <div
                    key={item.label}
                    className={`flex items-center gap-2 px-2 py-1.5 rounded-lg mb-0.5 ${
                      item.active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-muted/40"
                    } text-xs`}
                  >
                    <item.icon className="w-3.5 h-3.5 flex-shrink-0" />
                    {item.label}
                  </div>
                ))}
              </div>

              {/* Main content */}
              <div className="flex-1 p-5 overflow-hidden">
                {/* Metric cards */}
                <div className="grid grid-cols-4 gap-3 mb-5">
                  {[
                    { label: "Repositories", value: "24", icon: GitBranch, color: "text-neon-cyan" },
                    { label: "Security Score", value: "87%", icon: Shield, color: "text-neon-green" },
                    { label: "Vulnerabilities", value: "36", icon: AlertTriangle, color: "text-warning" },
                    { label: "Pipelines", value: "18", icon: CheckCircle, color: "text-neon-blue" },
                  ].map((m) => (
                    <div key={m.label} className="bg-card/80 border border-border/40 rounded-xl p-3">
                      <m.icon className={`w-4 h-4 ${m.color} mb-2`} />
                      <div className="text-xl font-bold">{m.value}</div>
                      <div className="text-[10px] text-muted-foreground">{m.label}</div>
                    </div>
                  ))}
                </div>

                {/* Charts row */}
                <div className="grid grid-cols-3 gap-3">
                  {/* Activity chart mockup */}
                  <div className="col-span-2 bg-card/80 border border-border/40 rounded-xl p-4">
                    <p className="text-[10px] text-muted-foreground font-mono mb-3">Scan Activity</p>
                    <div className="flex items-end gap-1.5 h-24">
                      {[40, 65, 45, 70, 55, 80, 60, 75, 50, 85, 45, 90].map((h, i) => (
                        <div
                          key={i}
                          className="flex-1 rounded-t-sm"
                          style={{
                            height: `${h}%`,
                            background: `linear-gradient(to top, hsl(185 100% 50% / 0.7), hsl(185 100% 50% / 0.2))`,
                          }}
                        />
                      ))}
                    </div>
                  </div>

                  {/* Gauge mockup */}
                  <div className="bg-card/80 border border-border/40 rounded-xl p-4 flex flex-col items-center justify-center">
                    <div className="relative">
                      <svg width="80" height="80" className="-rotate-90">
                        <circle cx="40" cy="40" r="30" fill="none" stroke="hsl(var(--muted))" strokeWidth="7" />
                        <circle
                          cx="40" cy="40" r="30"
                          fill="none"
                          stroke="hsl(150 100% 50%)"
                          strokeWidth="7"
                          strokeLinecap="round"
                          strokeDasharray={`${2 * Math.PI * 30}`}
                          strokeDashoffset={`${2 * Math.PI * 30 * (1 - 0.87)}`}
                          style={{ filter: "drop-shadow(0 0 6px hsl(150 100% 50% / 0.6))" }}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-sm font-bold">87</span>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-2">Security Score</p>
                  </div>
                </div>

                {/* Vuln table snippet */}
                <div className="mt-3 bg-card/80 border border-border/40 rounded-xl p-3">
                  <p className="text-[10px] text-muted-foreground font-mono mb-2">Recent Vulnerabilities</p>
                  <div className="space-y-1.5">
                    {[
                      { file: "src/auth/login.ts", sev: "CRITICAL", color: "text-critical bg-critical/10" },
                      { file: "package.json (lodash)", sev: "HIGH", color: "text-warning bg-warning/10" },
                      { file: "src/api/upload.ts", sev: "MEDIUM", color: "text-neon-blue bg-neon-blue/10" },
                    ].map((v) => (
                      <div key={v.file} className="flex items-center justify-between text-[10px]">
                        <span className="font-mono text-muted-foreground">{v.file}</span>
                        <span className={`px-1.5 py-0.5 rounded font-bold ${v.color}`}>{v.sev}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* CTA overlay */}
          <div className="absolute inset-0 flex items-end justify-center pb-8 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.5 }}
              className="pointer-events-auto"
            >
              <Link to="/dashboard">
                <button className="bg-primary text-primary-foreground font-semibold px-8 py-3 rounded-xl neon-glow hover:bg-primary/90 transition-all flex items-center gap-2 text-sm">
                  <Lock className="w-4 h-4" />
                  Launch Full Dashboard →
                </button>
              </Link>
            </motion.div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default PlatformPreview;
