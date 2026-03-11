import { motion } from "framer-motion";
import { GitBranch, Brain, Shield, Heart, Code2, Lock, Zap, Star } from "lucide-react";

const badges = [
  {
    icon: GitBranch,
    label: "GitHub Integration",
    desc: "OAuth + Webhooks",
    color: "hsl(185 100% 50%)",
    bg: "bg-neon-cyan/10 border-neon-cyan/20",
  },
  {
    icon: Brain,
    label: "AI-Powered Analysis",
    desc: "LLM Security Models",
    color: "hsl(270 100% 65%)",
    bg: "bg-neon-purple/10 border-neon-purple/20",
  },
  {
    icon: Shield,
    label: "Security Scanning",
    desc: "OWASP Top-10 Ready",
    color: "hsl(220 100% 60%)",
    bg: "bg-neon-blue/10 border-neon-blue/20",
  },
  {
    icon: Heart,
    label: "Developer Friendly",
    desc: "5-minute setup",
    color: "hsl(0 90% 60%)",
    bg: "bg-critical/10 border-critical/20",
  },
  {
    icon: Code2,
    label: "Open Source",
    desc: "Apache 2.0 License",
    color: "hsl(150 100% 50%)",
    bg: "bg-neon-green/10 border-neon-green/20",
  },
  {
    icon: Lock,
    label: "Zero Data Retention",
    desc: "Scans never stored",
    color: "hsl(45 100% 55%)",
    bg: "bg-warning/10 border-warning/20",
  },
  {
    icon: Zap,
    label: "Real-time Results",
    desc: "< 5min scan time",
    color: "hsl(185 100% 50%)",
    bg: "bg-neon-cyan/10 border-neon-cyan/20",
  },
  {
    icon: Star,
    label: "Free Forever",
    desc: "Up to 5 repos free",
    color: "hsl(45 100% 55%)",
    bg: "bg-warning/10 border-warning/20",
  },
];

const TrustSection = () => (
  <section className="py-24 px-4" style={{ background: "hsl(var(--card) / 0.3)" }}>
    <div className="max-w-5xl mx-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="text-center mb-12"
      >
        <h2 className="text-3xl md:text-4xl font-bold mb-3">
          Trusted by <span className="gradient-text">Developers Worldwide</span>
        </h2>
        <p className="text-muted-foreground">Built with developer experience at the core.</p>
      </motion.div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {badges.map((b, i) => (
          <motion.div
            key={b.label}
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.07 }}
            whileHover={{ y: -4, scale: 1.02 }}
            className={`glass rounded-xl p-4 border transition-all duration-300 cursor-default ${b.bg}`}
          >
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center mb-3"
              style={{ background: `${b.color}20` }}
            >
              <b.icon className="w-4 h-4" style={{ color: b.color }} />
            </div>
            <p className="text-sm font-semibold mb-0.5">{b.label}</p>
            <p className="text-xs text-muted-foreground">{b.desc}</p>
          </motion.div>
        ))}
      </div>
    </div>
  </section>
);

export default TrustSection;
