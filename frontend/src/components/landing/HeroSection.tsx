import { motion } from "framer-motion";
import { Shield, GitBranch, Zap, ArrowRight, Lock, Server, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { githubOAuthUrl } from "@/lib/api";

const terminalLines = [
  { text: "$ ark scan --repo github.com/myorg/app --deep", color: "text-neon-green" },
  { text: "  ✓ Connecting to GitHub...", color: "text-muted-foreground" },
  { text: "  ✓ Fetching repository manifest...", color: "text-muted-foreground" },
  { text: "  → Scanning 142 dependencies for CVEs...", color: "text-neon-blue" },
  { text: "  → Running SAST on 847 source files...", color: "text-neon-blue" },
  { text: "  → Checking for exposed secrets...", color: "text-neon-blue" },
  { text: "  ⚠ Found 3 vulnerabilities (1 critical, 2 medium)", color: "text-warning" },
  { text: "  ✓ Generating secure CI/CD pipeline...", color: "text-neon-cyan" },
  { text: "  ✓ Report saved: security-report-2026-03-11.pdf", color: "text-neon-green" },
  { text: "  ✓ Security Score: 87/100 [Excellent]", color: "text-neon-green" },
];

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden px-4 pt-16">
      {/* Background orbs */}
      <div className="absolute top-1/4 left-1/5 w-[500px] h-[500px] bg-neon-cyan/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/5 w-[400px] h-[400px] bg-neon-purple/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-neon-blue/3 rounded-full blur-[180px] pointer-events-none" />

      {/* Dot grid background */}
      <div className="absolute inset-0 dot-grid opacity-30 pointer-events-none" />

      <div className="relative z-10 max-w-6xl mx-auto">
        {/* Two-column layout */}
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Left: copy */}
          <div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="mb-6"
            >
              <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-primary/20 text-sm text-primary font-mono">
                <Zap className="w-3.5 h-3.5" />
                Free Developer Tool · Open Source
                <ArrowRight className="w-3 h-3 opacity-50" />
              </span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="text-5xl md:text-6xl font-bold tracking-tight mb-5 leading-[1.1]"
            >
              Automate Security
              <br />
              <span className="gradient-text">for Your Code</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="text-lg text-muted-foreground max-w-xl mb-8 leading-relaxed"
            >
              Connect your GitHub repository and automatically detect vulnerabilities,
              analyze dependencies, and generate secure CI/CD pipelines — powered by AI.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              className="flex flex-col sm:flex-row gap-3"
            >
              <Button
                size="lg"
                className="bg-primary text-primary-foreground hover:bg-primary/90 neon-glow font-semibold px-8 h-12 text-base gap-2"
                onClick={() => { window.location.href = githubOAuthUrl(); }}
              >
                <GitBranch className="w-5 h-5" />
                Connect GitHub
              </Button>
              <Link to="/dashboard">
                <Button
                  size="lg"
                  variant="outline"
                  className="border-border hover:border-primary/50 hover:bg-primary/5 font-semibold px-8 h-12 text-base w-full gap-2"
                >
                  <Shield className="w-5 h-5" />
                  Try Repository Scan
                </Button>
              </Link>
            </motion.div>

            {/* Trust indicators */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="flex flex-wrap items-center gap-4 mt-8 text-xs text-muted-foreground"
            >
              {[
                { icon: Lock, text: "No credentials stored" },
                { icon: Server, text: "Scans run in isolated env" },
                { icon: Activity, text: "Real-time results" },
              ].map(({ icon: Icon, text }) => (
                <span key={text} className="flex items-center gap-1.5">
                  <Icon className="w-3.5 h-3.5 text-primary" />
                  {text}
                </span>
              ))}
            </motion.div>
          </div>

          {/* Right: terminal illustration */}
          <motion.div
            initial={{ opacity: 0, x: 30, scale: 0.97 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="relative animate-float"
          >
            {/* Glow behind terminal */}
            <div className="absolute -inset-4 bg-neon-cyan/10 rounded-2xl blur-2xl" />

            <div className="relative glass rounded-xl overflow-hidden neon-glow">
              {/* Terminal bar */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-border/50 bg-muted/30">
                <div className="w-3 h-3 rounded-full bg-critical/80" />
                <div className="w-3 h-3 rounded-full bg-warning/80" />
                <div className="w-3 h-3 rounded-full bg-neon-green/80" />
                <span className="text-xs text-muted-foreground font-mono ml-2 flex-1">
                  ark-devsecops-scanner — bash
                </span>
              </div>

              {/* Scan animation line */}
              <div className="absolute left-0 right-0 h-8 scan-line pointer-events-none z-10" />

              {/* Terminal content */}
              <div className="p-5 font-mono text-sm space-y-1.5 bg-background/60">
                {terminalLines.map((line, i) => (
                  <motion.p
                    key={i}
                    initial={{ opacity: 0, x: -5 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + i * 0.15, duration: 0.3 }}
                    className={line.color}
                  >
                    {line.text}
                  </motion.p>
                ))}
                <motion.span
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 + terminalLines.length * 0.15 }}
                  className="terminal-cursor text-neon-green"
                >
                </motion.span>
              </div>
            </div>

            {/* Floating badges */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.8 }}
              className="absolute -top-4 -right-4 glass rounded-xl px-3 py-2 border border-neon-green/30 shadow-lg"
            >
              <div className="flex items-center gap-1.5 text-xs text-neon-green font-medium">
                <Shield className="w-3.5 h-3.5" />
                Score: 87/100
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 2 }}
              className="absolute -bottom-4 -left-4 glass rounded-xl px-3 py-2 border border-warning/30 shadow-lg"
            >
              <div className="flex items-center gap-1.5 text-xs text-warning font-medium">
                <Zap className="w-3.5 h-3.5" />
                1 Critical Found
              </div>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
