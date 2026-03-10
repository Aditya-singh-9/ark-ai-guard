import { motion } from "framer-motion";
import { GitBranch, Brain, Shield, Heart } from "lucide-react";

const badges = [
  { icon: GitBranch, label: "GitHub Integration" },
  { icon: Brain, label: "AI-Powered Analysis" },
  { icon: Shield, label: "Security Scanning" },
  { icon: Heart, label: "Developer Friendly" },
];

const TrustSection = () => (
  <section className="py-20 px-4 bg-muted/20">
    <div className="max-w-4xl mx-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        className="text-center mb-12"
      >
        <h2 className="text-2xl font-bold">
          Trusted by <span className="gradient-text">Developers</span>
        </h2>
      </motion.div>
      <div className="flex flex-wrap justify-center gap-4">
        {badges.map((b, i) => (
          <motion.div
            key={b.label}
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            className="glass rounded-full px-6 py-3 flex items-center gap-3 hover:border-primary/40 transition-colors"
          >
            <b.icon className="w-5 h-5 text-primary" />
            <span className="text-sm font-medium">{b.label}</span>
          </motion.div>
        ))}
      </div>
    </div>
  </section>
);

export default TrustSection;
