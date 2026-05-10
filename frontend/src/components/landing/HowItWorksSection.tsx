import { motion } from "framer-motion";
import { GitBranch, BrainCircuit, Layers, Zap, FileCode, Sparkles, ArrowRight, Code2, FileArchive } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

const steps = [
  {
    icon: GitBranch,
    title: "Connect Your Codebase",
    desc: "Link your GitHub repo, upload a ZIP archive, or paste code directly. DevScops Guard works with any source — no setup scripts, no config files.",
    step: 1,
    color: "hsl(185 100% 50%)",
    colorCls: "text-neon-cyan",
    badge: "3 Scan Modes",
    sub: "GitHub · ZIP · Paste Code",
  },
  {
    icon: Layers,
    title: "NEXUS™ 7-Layer Analysis",
    desc: "Our proprietary NEXUS engine runs 7 parallel scan layers simultaneously — surface patterns, semantic AST, crypto audit, supply chain, cross-file taint, IaC, and AI fusion.",
    step: 2,
    color: "hsl(220 100% 60%)",
    colorCls: "text-neon-blue",
    badge: "< 5 min",
    sub: "7 layers · Real-time streaming",
  },
  {
    icon: BrainCircuit,
    title: "Mythos™ AI Triages Findings",
    desc: "The Mythos™ AI engine reads your entire codebase context. It eliminates false positives, ranks risks by real exploitability, and generates plain-English remediation for every finding.",
    step: 3,
    color: "hsl(270 100% 65%)",
    colorCls: "text-violet-400",
    badge: "FP < 5%",
    sub: "STRIDE · OWASP · MITRE ATT&CK",
  },
  {
    icon: Zap,
    title: "Ship Fixes Automatically",
    desc: "Mythos™ generates working pull requests with patched code. Click one button and your security fix is ready to review — no manual patching, no guesswork.",
    step: 4,
    color: "hsl(150 100% 50%)",
    colorCls: "text-neon-green",
    badge: "Auto-Fix PR",
    sub: "GitHub PR · CI/CD YAML · Reports",
  },
];

const HowItWorksSection = () => {
  return (
    <section className="py-28 px-4 relative overflow-hidden" style={{ background: "hsl(var(--card) / 0.3)" }}>
      <div className="absolute inset-0 dot-grid opacity-15 pointer-events-none" />

      <div className="max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="inline-flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-widest mb-4 px-3 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full">
            <Sparkles className="w-3.5 h-3.5" /> The DevScops Guard Workflow
          </span>
          <h2 className="text-4xl md:text-5xl font-black mb-5 tracking-tight">
            From Code to <span className="gradient-text">Secure in Minutes.</span>
          </h2>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto leading-relaxed">
            No complex setup. No DevSecOps expertise required. Just connect your code and
            let <strong className="text-violet-400">Mythos™</strong> do the heavy lifting.
          </p>
        </motion.div>

        {/* Scan Mode mini-cards */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="flex flex-wrap justify-center gap-3 mb-14"
        >
          {[
            { icon: GitBranch, label: "GitHub Repo", desc: "OAuth connect · auto-import", color: "text-cyan-400", border: "border-cyan-500/30 bg-cyan-500/5" },
            { icon: FileArchive, label: "ZIP Upload", desc: "Drag & drop any archive", color: "text-purple-400", border: "border-purple-500/30 bg-purple-500/5" },
            { icon: Code2, label: "Paste Code", desc: "8 languages · instant scan", color: "text-green-400", border: "border-green-500/30 bg-green-500/5" },
          ].map(({ icon: Icon, label, desc, color, border }) => (
            <div key={label} className={`flex items-center gap-3 px-5 py-3 rounded-xl border glass ${border}`}>
              <Icon className={`w-5 h-5 ${color}`} />
              <div>
                <p className="text-sm font-semibold text-white">{label}</p>
                <p className="text-xs text-muted-foreground">{desc}</p>
              </div>
            </div>
          ))}
        </motion.div>

        {/* Steps */}
        <div className="grid md:grid-cols-4 gap-5 relative">
          {/* Connecting line (desktop) */}
          <div className="absolute hidden md:block top-14 left-[12.5%] right-[12.5%] h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent" />

          {steps.map((step, i) => (
            <motion.div
              key={step.step}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15, duration: 0.5 }}
              className="relative flex flex-col items-center text-center group"
            >
              {/* Step number bubble */}
              <div className="relative mb-5">
                <div
                  className="w-14 h-14 rounded-full flex items-center justify-center border-2 z-10 relative transition-all duration-300 group-hover:scale-110"
                  style={{
                    borderColor: step.color,
                    background: `hsl(var(--background))`,
                    boxShadow: `0 0 30px -5px ${step.color}50`,
                  }}
                >
                  <step.icon className={`w-6 h-6 ${step.colorCls}`} />
                </div>
                {/* Glow ring */}
                <div
                  className="absolute inset-0 rounded-full blur-md opacity-25 group-hover:opacity-40 transition-opacity"
                  style={{ background: step.color }}
                />
                {/* Step number */}
                <div
                  className="absolute -top-1 -right-1 w-5 h-5 rounded-full text-[9px] font-black flex items-center justify-center border border-background z-20"
                  style={{ background: step.color, color: "#000" }}
                >
                  {step.step}
                </div>
              </div>

              <div
                className="w-full rounded-2xl p-5 border border-border/50 transition-all duration-300 flex flex-col"
                style={{ background: "hsl(var(--card) / 0.6)", backdropFilter: "blur(16px)" }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = `${step.color}50`;
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 30px -10px ${step.color}40`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = "";
                  (e.currentTarget as HTMLElement).style.boxShadow = "";
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs font-black font-mono" style={{ color: step.color }}>
                    Step {step.step.toString().padStart(2, "0")}
                  </div>
                  <span className="text-[9px] font-bold px-2 py-0.5 rounded-full" style={{ color: step.color, background: `${step.color}18` }}>
                    {step.badge}
                  </span>
                </div>
                <h3 className="text-sm font-bold mb-2 leading-snug text-left">{step.title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed text-left flex-1">{step.desc}</p>
                <p className="text-[10px] font-mono text-muted-foreground/50 mt-3 pt-3 border-t border-white/5 text-left">{step.sub}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.4 }}
          className="text-center mt-14"
        >
          <Link to="/login">
            <Button size="lg" className="bg-primary text-primary-foreground hover:bg-primary/90 neon-glow font-semibold px-10 h-12 text-base gap-2">
              Start Your First Scan Free <ArrowRight className="w-4 h-4" />
            </Button>
          </Link>
          <p className="text-xs text-muted-foreground mt-3">No credit card · No setup · Scan in 60 seconds</p>
        </motion.div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
