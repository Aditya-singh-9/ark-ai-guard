import { motion } from "framer-motion";
import {
  BrainCircuit, Shield, Layers, GitBranch, Lock, Zap,
  Star, Code2, BarChart3, FileCheck, Network, Fingerprint
} from "lucide-react";

const stats = [
  { value: "7", label: "Scan Layers", color: "text-cyan-400" },
  { value: "< 5%", label: "False Positive Rate", color: "text-green-400" },
  { value: "< 5min", label: "Avg. Scan Time", color: "text-violet-400" },
  { value: "10K+", label: "Vulnerabilities Caught", color: "text-orange-400" },
];

const badges = [
  {
    icon: BrainCircuit,
    label: "Mythos™ AI Engine",
    desc: "Gemini + proprietary model fusion",
    color: "hsl(270 100% 65%)",
    bg: "bg-violet-500/10 border-violet-500/20",
  },
  {
    icon: Layers,
    label: "NEXUS™ 7-Layer Pipeline",
    desc: "Deepest scan coverage available",
    color: "hsl(185 100% 50%)",
    bg: "bg-neon-cyan/10 border-neon-cyan/20",
  },
  {
    icon: Shield,
    label: "OWASP Top 10 Ready",
    desc: "Full MITRE ATT&CK coverage",
    color: "hsl(220 100% 60%)",
    bg: "bg-neon-blue/10 border-neon-blue/20",
  },
  {
    icon: GitBranch,
    label: "Auto-Fix Pull Requests",
    desc: "One-click patched PRs on GitHub",
    color: "hsl(150 100% 50%)",
    bg: "bg-neon-green/10 border-neon-green/20",
  },
  {
    icon: Lock,
    label: "Zero Data Retention",
    desc: "Code never stored on our servers",
    color: "hsl(45 100% 55%)",
    bg: "bg-warning/10 border-warning/20",
  },
  {
    icon: Fingerprint,
    label: "Compliance Mapping",
    desc: "SOC2 · PCI DSS · HIPAA · ISO 27001",
    color: "hsl(0 90% 60%)",
    bg: "bg-red-500/10 border-red-500/20",
  },
  {
    icon: Code2,
    label: "3 Scan Input Modes",
    desc: "GitHub · ZIP Upload · Code Paste",
    color: "hsl(185 100% 50%)",
    bg: "bg-neon-cyan/10 border-neon-cyan/20",
  },
  {
    icon: Star,
    label: "Free Forever Tier",
    desc: "Full features, up to 5 repos",
    color: "hsl(45 100% 55%)",
    bg: "bg-warning/10 border-warning/20",
  },
  {
    icon: BarChart3,
    label: "Nexus Score™",
    desc: "0-100 security posture score",
    color: "hsl(270 100% 65%)",
    bg: "bg-violet-500/10 border-violet-500/20",
  },
  {
    icon: Network,
    label: "Cross-File Taint Tracking",
    desc: "Multi-hop vulnerability chains",
    color: "hsl(220 100% 60%)",
    bg: "bg-neon-blue/10 border-neon-blue/20",
  },
  {
    icon: FileCheck,
    label: "SBOM Generation",
    desc: "Software Bill of Materials export",
    color: "hsl(150 100% 50%)",
    bg: "bg-neon-green/10 border-neon-green/20",
  },
  {
    icon: Zap,
    label: "Real-time Streaming",
    desc: "Live scan progress as it happens",
    color: "hsl(45 100% 55%)",
    bg: "bg-warning/10 border-warning/20",
  },
];

const TrustSection = () => (
  <section className="py-24 px-4 relative overflow-hidden">
    <div className="absolute inset-0 grid-bg opacity-60 pointer-events-none" />
    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[1px] bg-gradient-to-r from-transparent via-violet-500/40 to-transparent" />

    <div className="max-w-6xl mx-auto relative">
      {/* Stats row */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-20"
      >
        {stats.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.08 }}
            className="glass rounded-2xl p-6 text-center border border-white/5 hover:border-white/10 transition-all"
          >
            <div className={`text-4xl font-black mb-1 ${s.color}`}>{s.value}</div>
            <div className="text-xs text-muted-foreground font-mono">{s.label}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* Headline */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="text-center mb-12"
      >
        <span className="inline-flex items-center gap-2 text-xs font-mono text-violet-400 uppercase tracking-widest mb-4 px-3 py-1.5 bg-violet-500/10 border border-violet-500/20 rounded-full">
          <BrainCircuit className="w-3.5 h-3.5" /> The Full Platform
        </span>
        <h2 className="text-3xl md:text-4xl font-black mb-3 tracking-tight">
          Everything Security. <span className="gradient-text">Nothing Compromised.</span>
        </h2>
        <p className="text-muted-foreground max-w-xl mx-auto">
          DevScops Guard is the only platform combining a proprietary AI engine, a 7-layer scanner, and one-click auto-fix
          — built to go from finding to fix in minutes, not days.
        </p>
      </motion.div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {badges.map((b, i) => (
          <motion.div
            key={b.label}
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.05 }}
            whileHover={{ y: -4, scale: 1.02 }}
            className={`glass rounded-xl p-4 border transition-all duration-300 cursor-default ${b.bg}`}
          >
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center mb-3"
              style={{ background: `${b.color}20` }}
            >
              <b.icon className="w-4 h-4" style={{ color: b.color }} />
            </div>
            <p className="text-sm font-semibold mb-0.5 leading-snug">{b.label}</p>
            <p className="text-xs text-muted-foreground leading-snug">{b.desc}</p>
          </motion.div>
        ))}
      </div>
    </div>
  </section>
);

export default TrustSection;
