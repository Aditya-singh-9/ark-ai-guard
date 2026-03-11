import { motion } from "framer-motion";
import { GitBranch, Search, ShieldAlert, Workflow } from "lucide-react";

const steps = [
  {
    icon: GitBranch,
    title: "Connect GitHub Repository",
    desc: "Authenticate with GitHub OAuth and select repositories to monitor.",
    step: 1,
    color: "hsl(185 100% 50%)",
    colorCls: "text-neon-cyan",
  },
  {
    icon: Search,
    title: "Scan Repository",
    desc: "ARK runs deep SAST, dependency, and secret scanning across your codebase.",
    step: 2,
    color: "hsl(220 100% 60%)",
    colorCls: "text-neon-blue",
  },
  {
    icon: ShieldAlert,
    title: "Detect Vulnerabilities",
    desc: "Review AI-prioritized findings with severity scores and remediation guides.",
    step: 3,
    color: "hsl(45 100% 55%)",
    colorCls: "text-warning",
  },
  {
    icon: Workflow,
    title: "Generate Secure CI/CD",
    desc: "Export a hardened GitHub Actions pipeline tailored to your tech stack.",
    step: 4,
    color: "hsl(150 100% 50%)",
    colorCls: "text-neon-green",
  },
];

const HowItWorksSection = () => {
  return (
    <section className="py-28 px-4 relative overflow-hidden" style={{ background: "hsl(var(--card) / 0.3)" }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="text-xs font-mono text-primary uppercase tracking-widest mb-4 block">Workflow</span>
          <h2 className="text-4xl md:text-5xl font-bold mb-5">
            How It <span className="gradient-text">Works</span>
          </h2>
          <p className="text-muted-foreground text-lg max-w-xl mx-auto">
            Four simple steps to go from vulnerable code to secure deployments.
          </p>
        </motion.div>

        {/* Steps */}
        <div className="grid md:grid-cols-4 gap-4 relative">
          {/* Connecting line (desktop) */}
          <div className="absolute hidden md:block top-14 left-[12.5%] right-[12.5%] h-px bg-gradient-to-r from-transparent via-border to-transparent" />

          {steps.map((step, i) => (
            <motion.div
              key={step.step}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15, duration: 0.5 }}
              className="relative flex flex-col items-center text-center"
            >
              {/* Step number bubble */}
              <div className="relative mb-5">
                <div
                  className="w-12 h-12 rounded-full flex items-center justify-center border-2 z-10 relative"
                  style={{
                    borderColor: step.color,
                    background: `hsl(var(--background))`,
                    boxShadow: `0 0 20px -5px ${step.color}60`,
                  }}
                >
                  <step.icon className={`w-5 h-5 ${step.colorCls}`} />
                </div>
                {/* Glow ring */}
                <div
                  className="absolute inset-0 rounded-full blur-md opacity-30"
                  style={{ background: step.color }}
                />
              </div>

              <div
                className="w-full rounded-2xl p-5 border border-border/50 hover:border-opacity-60 transition-all duration-300"
                style={{
                  background: "hsl(var(--card) / 0.6)",
                  backdropFilter: "blur(16px)",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = `${step.color}60`;
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 30px -10px ${step.color}40`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = "";
                  (e.currentTarget as HTMLElement).style.boxShadow = "";
                }}
              >
                <div
                  className="text-xs font-bold font-mono mb-2"
                  style={{ color: step.color }}
                >
                  Step {step.step.toString().padStart(2, "0")}
                </div>
                <h3 className="text-sm font-semibold mb-2 leading-snug">{step.title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">{step.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
