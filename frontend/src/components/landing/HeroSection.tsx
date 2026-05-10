import { motion } from "framer-motion";
import { Shield, GitBranch, Zap, ArrowRight, Lock, Server, Activity, Brain, Sparkles, FileArchive, Code2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

const terminalLines = [
  { text: "$ ark scan --repo github.com/myorg/backend --mythos", color: "text-neon-green" },
  { text: "  ✓ Mythos™ Engine initialized — 7-layer pipeline active", color: "text-neon-cyan" },
  { text: "  → L1 Surface Scan: regex sweep on 847 files...", color: "text-blue-400" },
  { text: "  → L2 Semantic AST: taint tracking across data flows...", color: "text-blue-400" },
  { text: "  → L3 Crypto Audit: entropy analysis, weak ciphers...", color: "text-blue-400" },
  { text: "  → L4 Dependency DNA: 142 deps, typosquatting check...", color: "text-blue-400" },
  { text: "  ⚠ Found 1 critical — SQL injection in auth/login.py:47", color: "text-orange-400" },
  { text: "  ✓ L7 AI Fusion: false-positive reduced (FP: 4%)", color: "text-neon-cyan" },
  { text: "  ✓ Auto-fix generated — PR #42 ready to merge", color: "text-neon-green" },
  { text: "  ✓ Nexus Score™: 94/100  [Elite]", color: "text-neon-green" },
];

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden px-4 pt-16">
      {/* Background orbs */}
      <div className="absolute top-1/4 left-1/5 w-[600px] h-[600px] bg-neon-cyan/5 rounded-full blur-[160px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/5 w-[500px] h-[500px] bg-neon-purple/6 rounded-full blur-[160px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] bg-neon-blue/3 rounded-full blur-[200px] pointer-events-none" />

      {/* Dot grid background */}
      <div className="absolute inset-0 dot-grid opacity-25 pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto w-full">
        <div className="grid lg:grid-cols-2 gap-14 items-center">
          {/* Left: copy */}
          <div>
            {/* Pill badges */}
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }} className="flex flex-wrap gap-2 mb-7">
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-violet-500/30 text-xs text-violet-300 font-mono">
                <Brain className="w-3.5 h-3.5" /> Mythos™ AI Engine
              </span>
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-cyan-500/30 text-xs text-cyan-300 font-mono">
                <Sparkles className="w-3.5 h-3.5" /> 7-Layer NEXUS Pipeline
              </span>
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-green-500/30 text-xs text-green-300 font-mono">
                <Zap className="w-3.5 h-3.5" /> Free Developer Tool
              </span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="text-5xl md:text-6xl lg:text-7xl font-black tracking-tight mb-5 leading-[1.05]"
            >
              AI Security That
              <br />
              <span className="gradient-text">Thinks Like a</span>
              <br />
              <span className="text-white">Hacker.</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="text-lg text-muted-foreground max-w-xl mb-6 leading-relaxed"
            >
              <strong className="text-white">DevScops Guard</strong> runs a personalized 7-layer deep scan on your codebase —
              powered by <strong className="text-violet-400">Mythos™ AI</strong>. Detect vulnerabilities,
              generate auto-fixes, and ship secure code with confidence.
            </motion.p>

            {/* Scan modes CTA */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.25 }}
              className="flex flex-wrap gap-2 mb-6 text-xs text-muted-foreground"
            >
              <span className="flex items-center gap-1.5 px-2.5 py-1 bg-white/5 border border-white/10 rounded-full">
                <GitBranch className="w-3 h-3 text-cyan-400" /> GitHub Repo
              </span>
              <span className="flex items-center gap-1.5 px-2.5 py-1 bg-white/5 border border-white/10 rounded-full">
                <FileArchive className="w-3 h-3 text-purple-400" /> ZIP Upload
              </span>
              <span className="flex items-center gap-1.5 px-2.5 py-1 bg-white/5 border border-white/10 rounded-full">
                <Code2 className="w-3 h-3 text-green-400" /> Paste Code
              </span>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              className="flex flex-col sm:flex-row gap-3"
            >
              <Link to="/login">
                <Button size="lg" className="bg-primary text-primary-foreground hover:bg-primary/90 neon-glow font-semibold px-8 h-12 text-base gap-2 w-full sm:w-auto">
                  <GitBranch className="w-5 h-5" /> Connect GitHub
                </Button>
              </Link>
              <Link to="/login">
                <Button size="lg" variant="outline" className="border-violet-500/40 hover:border-violet-400 hover:bg-violet-500/10 font-semibold px-8 h-12 text-base gap-2 text-violet-300 w-full sm:w-auto">
                  <Brain className="w-5 h-5" /> Try Mythos™ Free
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </motion.div>

            {/* Trust indicators */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.55 }}
              className="flex flex-wrap items-center gap-5 mt-8 text-xs text-muted-foreground"
            >
              {[
                { icon: Lock, text: "Zero data retention" },
                { icon: Server, text: "Isolated scan environment" },
                { icon: Activity, text: "Real-time streaming results" },
                { icon: Shield, text: "OWASP + MITRE ATT&CK mapped" },
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
            <div className="absolute -inset-6 bg-gradient-to-br from-cyan-500/10 via-violet-500/10 to-transparent rounded-3xl blur-3xl" />

            <div className="relative glass rounded-2xl overflow-hidden border border-white/10" style={{ boxShadow: "0 0 60px -10px rgba(0,255,200,0.15)" }}>
              {/* Terminal bar */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-border/50 bg-black/40">
                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                <div className="w-3 h-3 rounded-full bg-green-500/80" />
                <span className="text-xs text-muted-foreground font-mono ml-2 flex-1">
                  devscops-guard — Mythos™ Engine v2.0
                </span>
                <span className="text-[10px] font-bold text-violet-400 font-mono px-2 py-0.5 bg-violet-500/10 rounded">NEXUS</span>
              </div>

              {/* Scan animation line */}
              <div className="absolute left-0 right-0 h-8 scan-line pointer-events-none z-10" />

              {/* Terminal content */}
              <div className="p-5 font-mono text-sm space-y-1.5 bg-black/50">
                {terminalLines.map((line, i) => (
                  <motion.p
                    key={i}
                    initial={{ opacity: 0, x: -5 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.6 + i * 0.14, duration: 0.3 }}
                    className={`text-xs leading-relaxed ${line.color}`}
                  >
                    {line.text}
                  </motion.p>
                ))}
                <motion.span
                  initial={{ opacity: 0 }}
                  animate={{ opacity: [0, 1, 0] }}
                  transition={{ delay: 0.6 + terminalLines.length * 0.14, repeat: Infinity, duration: 1 }}
                  className="terminal-cursor text-neon-green"
                />
              </div>
            </div>

            {/* Floating badges */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 2 }}
              className="absolute -top-5 -right-3 glass rounded-xl px-3 py-2 border border-green-500/40 shadow-xl">
              <div className="flex items-center gap-1.5 text-xs text-green-400 font-bold">
                <Shield className="w-3.5 h-3.5" /> Nexus Score™: 94/100
              </div>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 2.2 }}
              className="absolute -bottom-5 -left-3 glass rounded-xl px-3 py-2 border border-violet-500/40 shadow-xl">
              <div className="flex items-center gap-1.5 text-xs text-violet-400 font-bold">
                <Brain className="w-3.5 h-3.5" /> Mythos™ AI Active
              </div>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 2.4 }}
              className="absolute top-1/2 -right-6 glass rounded-xl px-3 py-2 border border-orange-500/40 shadow-xl">
              <div className="flex items-center gap-1.5 text-xs text-orange-400 font-bold">
                <Zap className="w-3.5 h-3.5" /> 1 Critical → Auto-Fixed
              </div>
            </motion.div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
