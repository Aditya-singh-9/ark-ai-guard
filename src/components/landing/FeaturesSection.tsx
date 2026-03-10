import { motion } from "framer-motion";
import { Shield, Package, Brain, GitBranch } from "lucide-react";

const features = [
  {
    icon: Shield,
    title: "Repository Security Scanner",
    description: "Automatically scan GitHub repositories for vulnerabilities and security risks.",
    color: "neon-cyan",
  },
  {
    icon: Package,
    title: "Dependency Risk Detection",
    description: "Detect outdated packages and vulnerable dependencies.",
    color: "neon-blue",
  },
  {
    icon: Brain,
    title: "AI Architecture Analysis",
    description: "AI analyzes repository structure and recommends improvements.",
    color: "neon-purple",
  },
  {
    icon: GitBranch,
    title: "CI/CD Pipeline Generator",
    description: "Automatically generate GitHub Actions pipelines for secure deployments.",
    color: "neon-green",
  },
];

const colorMap: Record<string, string> = {
  "neon-cyan": "hsl(var(--neon-cyan))",
  "neon-blue": "hsl(var(--neon-blue))",
  "neon-purple": "hsl(var(--neon-purple))",
  "neon-green": "hsl(var(--neon-green))",
};

const FeaturesSection = () => {
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
            Powerful <span className="gradient-text">Security Features</span>
          </h2>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            Everything you need to secure your codebase and automate your DevSecOps workflow.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              whileHover={{ y: -5 }}
              className="glass-hover rounded-xl p-6 group cursor-default"
            >
              <div
                className="w-12 h-12 rounded-lg flex items-center justify-center mb-4 transition-shadow duration-300"
                style={{
                  backgroundColor: `${colorMap[feature.color]}15`,
                  boxShadow: `0 0 0px ${colorMap[feature.color]}`,
                }}
              >
                <feature.icon className="w-6 h-6" style={{ color: colorMap[feature.color] }} />
              </div>
              <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{feature.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
