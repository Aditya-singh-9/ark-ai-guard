import { motion } from "framer-motion";
import { Shield, GitBranch, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden px-4">
      {/* Background effects */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-background to-muted/20" />
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-neon-cyan/5 rounded-full blur-[120px]" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-neon-purple/5 rounded-full blur-[120px]" />
      
      {/* Grid overlay */}
      <div className="absolute inset-0 opacity-[0.03]" style={{
        backgroundImage: `linear-gradient(hsl(var(--primary) / 0.3) 1px, transparent 1px),
                          linear-gradient(90deg, hsl(var(--primary) / 0.3) 1px, transparent 1px)`,
        backgroundSize: '60px 60px'
      }} />

      <div className="relative z-10 max-w-5xl mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-6"
        >
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass text-sm text-primary font-mono">
            <Zap className="w-3.5 h-3.5" />
            Free Developer Tool
          </span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="text-5xl md:text-7xl font-bold tracking-tight mb-6"
        >
          Automate Security
          <br />
          <span className="gradient-text">for Your Code</span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed"
        >
          Connect your GitHub repository and automatically detect vulnerabilities,
          analyze dependencies, and generate secure CI/CD pipelines.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="flex flex-col sm:flex-row gap-4 justify-center"
        >
          <Button size="lg" className="bg-primary text-primary-foreground hover:bg-primary/90 neon-glow font-semibold px-8 h-12 text-base">
            <GitBranch className="w-5 h-5 mr-2" />
            Connect GitHub
          </Button>
          <Link to="/dashboard">
            <Button size="lg" variant="outline" className="border-border hover:border-primary/50 hover:bg-primary/5 font-semibold px-8 h-12 text-base w-full">
              <Shield className="w-5 h-5 mr-2" />
              Try Repository Scan
            </Button>
          </Link>
        </motion.div>

        {/* Animated scan illustration */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          className="mt-16 relative"
        >
          <div className="glass rounded-xl p-6 max-w-3xl mx-auto relative overflow-hidden">
            <div className="absolute inset-0 scan-line" />
            <div className="flex items-center gap-3 mb-4">
              <div className="w-3 h-3 rounded-full bg-critical/80" />
              <div className="w-3 h-3 rounded-full bg-warning/80" />
              <div className="w-3 h-3 rounded-full bg-neon-green/80" />
              <span className="text-xs text-muted-foreground font-mono ml-2">ark-devsecops-scanner</span>
            </div>
            <div className="font-mono text-sm space-y-2 text-left">
              <p className="text-neon-green">$ ark scan --repo github.com/org/app</p>
              <p className="text-muted-foreground">→ Scanning repository structure...</p>
              <p className="text-muted-foreground">→ Analyzing 142 dependencies...</p>
              <p className="text-primary">→ Found 3 vulnerabilities (1 critical, 2 medium)</p>
              <p className="text-neon-green">→ Generating secure CI/CD pipeline...</p>
              <p className="text-neon-green">✓ Security report generated successfully</p>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default HeroSection;
