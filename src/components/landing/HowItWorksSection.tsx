import { motion } from "framer-motion";
import { GitBranch, Search, ShieldAlert, Workflow, ArrowRight } from "lucide-react";

const steps = [
  { icon: GitBranch, title: "Connect GitHub Repository", step: 1 },
  { icon: Search, title: "Scan Repository", step: 2 },
  { icon: ShieldAlert, title: "Detect Security Vulnerabilities", step: 3 },
  { icon: Workflow, title: "Generate Secure CI/CD Pipeline", step: 4 },
];

const HowItWorksSection = () => {
  return (
    <section className="py-24 px-4 relative bg-muted/20">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            How It <span className="gradient-text">Works</span>
          </h2>
          <p className="text-muted-foreground text-lg">Four simple steps to secure your code.</p>
        </motion.div>

        <div className="grid md:grid-cols-4 gap-4 items-center">
          {steps.map((step, i) => (
            <motion.div
              key={step.step}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 }}
              className="relative flex flex-col items-center"
            >
              <div className="glass rounded-xl p-6 text-center w-full group hover:border-primary/30 transition-all duration-300">
                <div className="w-14 h-14 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4 group-hover:bg-primary/20 transition-colors">
                  <step.icon className="w-7 h-7 text-primary" />
                </div>
                <div className="text-xs font-mono text-primary mb-2">Step {step.step}</div>
                <h3 className="text-sm font-semibold">{step.title}</h3>
              </div>
              {i < steps.length - 1 && (
                <ArrowRight className="hidden md:block absolute -right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground z-10" />
              )}
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorksSection;
