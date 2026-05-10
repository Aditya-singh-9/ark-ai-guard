import { motion } from "framer-motion";
import {
  BrainCircuit, Zap, ShieldCheck, CheckCircle2,
  ArrowRight, Sparkles, Target, Eye, Lock,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

// Marketing-only: describes WHAT it does, not HOW the engine works internally
const analysisPhases = [
  { id: 1, name: "Codebase Understanding", desc: "Mythos™ maps your project structure and data flows", color: "#22d3ee", done: true },
  { id: 2, name: "Attack Surface Mapping", desc: "Every entry point, dependency, and config analyzed", color: "#60a5fa", done: true },
  { id: 3, name: "Threat Prioritization", desc: "Risks ranked by real-world exploitability, not theory", color: "#f59e0b", done: true },
  { id: 4, name: "Context-Aware Findings", desc: "Results tailored to your stack, framework & patterns", color: "#fb923c", done: true },
  { id: 5, name: "False-Positive Filtering", desc: "AI removes noise so only real issues surface", color: "#a78bfa", done: false },
  { id: 6, name: "Remediation Generation", desc: "Working fix suggestions written for your specific code", color: "#34d399", done: false },
];

const findings = [
  { severity: "CRITICAL", title: "Authentication bypass detected", fp: "1%", fixed: true },
  { severity: "HIGH", title: "Exposed credential in config", fp: "2%", fixed: true },
  { severity: "HIGH", title: "Insecure data handling path", fp: "6%", fixed: false },
  { severity: "MEDIUM", title: "Weak cryptographic practice", fp: "3%", fixed: false },
];

const differentiators = [
  {
    icon: Target,
    title: "Personalized, Not Generic",
    desc: "Mythos™ reads your actual codebase before scanning — so findings are specific to your code, not copy-pasted from a rulebook.",
    color: "text-violet-400",
    border: "border-violet-500/20",
    bg: "bg-violet-500/5",
  },
  {
    icon: Eye,
    title: "Signal Over Noise",
    desc: "Industry scanners average 30–60% false positives. Mythos™ AI filters findings down to under 5% FP rate — so your team fixes real risks, not phantom alerts.",
    color: "text-cyan-400",
    border: "border-cyan-500/20",
    bg: "bg-cyan-500/5",
  },
  {
    icon: Lock,
    title: "Your Code Stays Yours",
    desc: "Scans run in an isolated environment. No code is stored, logged, or used for training. Zero data retention — guaranteed.",
    color: "text-green-400",
    border: "border-green-500/20",
    bg: "bg-green-500/5",
  },
];

const MythosSection = () => (
  <section className="py-28 px-4 relative overflow-hidden">
    <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[700px] bg-violet-500/5 rounded-full blur-[160px] pointer-events-none" />
    <div className="absolute inset-0 dot-grid opacity-15 pointer-events-none" />

    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="text-center mb-16">
        <span className="inline-flex items-center gap-2 text-xs font-mono text-violet-400 uppercase tracking-widest mb-4 px-3 py-1.5 bg-violet-500/10 border border-violet-500/20 rounded-full">
          <BrainCircuit className="w-3.5 h-3.5" /> Mythos™ AI — Security That Knows You
        </span>
        <h2 className="text-4xl md:text-5xl font-black mb-5 tracking-tight">
          The AI That Understands<br />
          <span className="gradient-text">Your Code, Not Just Rules.</span>
        </h2>
        <p className="text-muted-foreground text-lg max-w-2xl mx-auto leading-relaxed">
          Mythos™ is DevScops Guard's proprietary security intelligence engine.
          It doesn't run generic rules — it <strong className="text-white">understands your codebase</strong> and
          delivers findings that are tailored, prioritized, and actionable.
        </p>
      </motion.div>

      <div className="grid lg:grid-cols-2 gap-8 items-start mb-12">
        {/* Left: Analysis phases — marketing view only */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          className="glass rounded-2xl p-6 border border-white/10 relative overflow-hidden"
        >
          <div className="absolute -top-16 -right-16 w-48 h-48 bg-violet-500/10 rounded-full blur-3xl" />
          <div className="flex items-center gap-3 mb-6">
            <div className="w-9 h-9 bg-violet-500/20 rounded-xl flex items-center justify-center">
              <BrainCircuit className="w-5 h-5 text-violet-400" />
            </div>
            <div>
              <p className="text-sm font-bold text-white">Mythos™ Engine — Analyzing</p>
              <p className="text-xs text-muted-foreground font-mono">your-project / main branch</p>
            </div>
            <span className="ml-auto text-xs text-violet-400 font-mono bg-violet-500/10 px-2 py-1 rounded animate-pulse">ACTIVE</span>
          </div>

          <div className="space-y-2.5">
            {analysisPhases.map((phase, i) => (
              <motion.div
                key={phase.id}
                initial={{ opacity: 0, x: -10 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.09 }}
                className="flex items-center gap-3 p-3 rounded-xl bg-white/3 border border-white/5"
              >
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-xs font-black font-mono"
                  style={{ background: `${phase.color}18`, color: phase.color, border: `1px solid ${phase.color}30` }}
                >
                  {phase.id}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-white">{phase.name}</p>
                  <p className="text-[10px] text-muted-foreground">{phase.desc}</p>
                </div>
                {phase.done ? (
                  <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                ) : (
                  <div className="w-4 h-4 rounded-full border-2 border-violet-400 border-t-transparent animate-spin shrink-0" />
                )}
              </motion.div>
            ))}
          </div>

          <div className="mt-4 flex items-center justify-between px-1">
            <span className="text-xs text-muted-foreground font-mono">4 of 6 phases complete</span>
            <span className="text-xs font-bold text-violet-400 flex items-center gap-1">
              <Sparkles className="w-3 h-3" /> Nexus Score™ calculating…
            </span>
          </div>
        </motion.div>

        {/* Right: AI findings output — no algorithm details */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          className="space-y-4"
        >
          {/* Summary card */}
          <div className="glass rounded-2xl p-5 border border-violet-500/20 bg-violet-500/5">
            <div className="flex items-center gap-3 mb-3">
              <ShieldCheck className="w-6 h-6 text-violet-400" />
              <div>
                <p className="text-sm font-bold text-white">Mythos™ Analysis Complete</p>
                <p className="text-xs text-muted-foreground">4 prioritized findings · Remediation ready</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              {[
                { label: "Findings", value: "4", color: "text-orange-400" },
                { label: "False Positives", value: "< 5%", color: "text-green-400" },
                { label: "Nexus Score™", value: "91/100", color: "text-violet-400" },
              ].map(s => (
                <div key={s.label} className="bg-white/5 rounded-lg p-2.5 text-center">
                  <div className={`text-lg font-black ${s.color}`}>{s.value}</div>
                  <div className="text-[10px] text-muted-foreground">{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings list — descriptive but no algo specifics */}
          <div className="space-y-2">
            {findings.map((f, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 8 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className="glass rounded-xl p-4 border border-white/8 hover:border-white/15 transition-all"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    <span className={`text-[10px] font-black px-2 py-0.5 rounded shrink-0 ${
                      f.severity === "CRITICAL" ? "bg-red-500/20 text-red-400" :
                      f.severity === "HIGH" ? "bg-orange-500/20 text-orange-400" :
                      "bg-yellow-500/20 text-yellow-400"
                    }`}>{f.severity}</span>
                    <span className="text-xs text-white truncate">{f.title}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-muted-foreground">FP: {f.fp}</span>
                    {f.fixed ? (
                      <span className="text-[10px] text-green-400 font-bold bg-green-500/10 px-2 py-0.5 rounded">AUTO-FIXED</span>
                    ) : (
                      <span className="text-[10px] text-violet-400 font-bold bg-violet-500/10 px-2 py-0.5 rounded">FIX READY</span>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          <Link to="/login" className="block">
            <Button className="w-full bg-gradient-to-r from-violet-600 to-cyan-600 text-white hover:opacity-90 gap-2 font-semibold h-11">
              <BrainCircuit className="w-4 h-4" /> Run Your Personalized Mythos™ Scan
              <ArrowRight className="w-4 h-4" />
            </Button>
          </Link>
        </motion.div>
      </div>

      {/* Bottom 3-column differentiators */}
      <div className="grid md:grid-cols-3 gap-4">
        {differentiators.map((d, i) => (
          <motion.div
            key={d.title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            className={`glass rounded-2xl p-5 border ${d.border} ${d.bg}`}
          >
            <d.icon className={`w-6 h-6 ${d.color} mb-3`} />
            <h3 className="text-sm font-bold text-white mb-2">{d.title}</h3>
            <p className="text-xs text-muted-foreground leading-relaxed">{d.desc}</p>
          </motion.div>
        ))}
      </div>
    </div>
  </section>
);

export default MythosSection;
