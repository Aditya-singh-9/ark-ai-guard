import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle, GitBranch } from "lucide-react";

const PlatformPreview = () => {
  return (
    <section className="py-24 px-4 relative">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            Platform <span className="gradient-text">Preview</span>
          </h2>
          <p className="text-muted-foreground text-lg">A glimpse of the DevSecOps dashboard.</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="glass rounded-2xl p-6 md:p-8 neon-glow"
        >
          {/* Mock dashboard */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              { label: "Repos Scanned", value: "24", icon: GitBranch, color: "text-primary" },
              { label: "Security Score", value: "87%", icon: Shield, color: "text-neon-green" },
              { label: "Vulnerabilities", value: "12", icon: AlertTriangle, color: "text-warning" },
              { label: "Pipelines", value: "18", icon: CheckCircle, color: "text-neon-blue" },
            ].map((m) => (
              <div key={m.label} className="bg-muted/50 rounded-lg p-4">
                <m.icon className={`w-5 h-5 ${m.color} mb-2`} />
                <div className="text-2xl font-bold">{m.value}</div>
                <div className="text-xs text-muted-foreground">{m.label}</div>
              </div>
            ))}
          </div>

          {/* Charts mockup */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-muted/50 rounded-lg p-4 h-48 flex flex-col">
              <span className="text-xs text-muted-foreground font-mono mb-3">Vulnerability Trends</span>
              <div className="flex-1 flex items-end gap-2">
                {[40, 65, 45, 70, 55, 80, 60, 75, 50, 35, 45, 30].map((h, i) => (
                  <div
                    key={i}
                    className="flex-1 rounded-t bg-gradient-to-t from-primary/60 to-primary/20 transition-all"
                    style={{ height: `${h}%` }}
                  />
                ))}
              </div>
            </div>
            <div className="bg-muted/50 rounded-lg p-4 h-48 flex flex-col">
              <span className="text-xs text-muted-foreground font-mono mb-3">Severity Distribution</span>
              <div className="flex-1 flex items-center justify-center gap-6">
                {[
                  { label: "Critical", pct: 8, color: "bg-critical" },
                  { label: "High", pct: 20, color: "bg-warning" },
                  { label: "Medium", pct: 45, color: "bg-neon-blue" },
                  { label: "Low", pct: 27, color: "bg-neon-green" },
                ].map((s) => (
                  <div key={s.label} className="text-center">
                    <div className="w-12 h-12 rounded-full border-4 border-muted flex items-center justify-center mb-1">
                      <div className={`w-6 h-6 rounded-full ${s.color}/80`} />
                    </div>
                    <div className="text-xs font-bold">{s.pct}%</div>
                    <div className="text-[10px] text-muted-foreground">{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default PlatformPreview;
