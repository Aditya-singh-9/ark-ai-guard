import { motion } from "framer-motion";
import { Shield, Package, Brain, GitBranch, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

const features = [
  {
    icon: Shield,
    title: "Repository Security Scanner",
    description:
      "Automatically scan GitHub repositories for OWASP Top-10 vulnerabilities, misconfigurations, and security risks using static analysis.",
    color: "neon-cyan",
    hsl: "185 100% 50%",
    badge: "SAST",
  },
  {
    icon: Package,
    title: "Dependency Risk Detection",
    description:
      "Detect outdated packages and CVE-tagged dependencies. Get pinned update recommendations with severity scores from NIST NVD.",
    color: "neon-blue",
    hsl: "220 100% 60%",
    badge: "SCA",
  },
  {
    icon: Brain,
    title: "AI Architecture Analysis",
    description:
      "AI models analyze your repository structure, API design, and data flows to surface architectural weaknesses and anti-patterns.",
    color: "neon-purple",
    hsl: "270 100% 65%",
    badge: "AI",
  },
  {
    icon: GitBranch,
    title: "CI/CD Pipeline Generator",
    description:
      "Automatically generate hardened GitHub Actions workflows with security gates, secret scanning, and deployment guardrails.",
    color: "neon-green",
    hsl: "150 100% 50%",
    badge: "DevOps",
  },
];

const FeaturesSection = () => {
  return (
    <section className="py-28 px-4 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 grid-bg opacity-100 pointer-events-none" />

      <div className="max-w-6xl mx-auto relative">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="text-xs font-mono text-primary uppercase tracking-widest mb-4 block">Platform Features</span>
          <h2 className="text-4xl md:text-5xl font-bold mb-5">
            Powerful <span className="gradient-text">Security Features</span>
          </h2>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto leading-relaxed">
            Everything you need to secure your codebase and automate your DevSecOps workflow — in one platform.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
          {features.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1, duration: 0.5 }}
              whileHover={{ y: -6 }}
              className="group cursor-default"
            >
              <div
                className="rounded-2xl p-6 h-full flex flex-col border border-border/50 transition-all duration-300"
                style={{
                  background: `linear-gradient(135deg, hsl(var(--card) / 0.9), hsl(var(--card) / 0.6))`,
                  backdropFilter: "blur(20px)",
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = `hsl(${feature.hsl} / 0.4)`;
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 40px -10px hsl(${feature.hsl} / 0.2)`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = "";
                  (e.currentTarget as HTMLElement).style.boxShadow = "";
                }}
              >
                {/* Icon + Badge row */}
                <div className="flex items-center justify-between mb-5">
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ background: `hsl(${feature.hsl} / 0.12)` }}
                  >
                    <feature.icon
                      className="w-6 h-6"
                      style={{ color: `hsl(${feature.hsl})` }}
                    />
                  </div>
                  <span
                    className="text-[10px] font-bold font-mono px-2 py-1 rounded-md tracking-wider"
                    style={{
                      color: `hsl(${feature.hsl})`,
                      background: `hsl(${feature.hsl} / 0.1)`,
                    }}
                  >
                    {feature.badge}
                  </span>
                </div>

                <h3 className="text-base font-semibold mb-3 leading-snug">{feature.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed flex-1">
                  {feature.description}
                </p>

                <div
                  className="mt-4 flex items-center gap-1.5 text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity"
                  style={{ color: `hsl(${feature.hsl})` }}
                >
                  Learn more <ArrowRight className="w-3 h-3" />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
