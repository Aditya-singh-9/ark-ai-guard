import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { 
  getLiveScanStatus, 
  getVulnerabilityReport, 
  LiveScanStatus,
  VulnerabilityReport,
  VulnerabilityItem
} from "../lib/api";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Search, 
  Code, 
  Key, 
  PackageSearch,
  Network,
  CloudCog,
  BrainCircuit,
  ArrowLeft,
  Loader2,
  CheckCircle2,
  AlertTriangle
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { 
  createAutofixPr, 
  getScanCompliance, 
  getScanOwasp, 
  getScanPolicy, 
  getScanThreatAnalysis, 
  getScanAutofixes 
} from "../lib/api";

// ── 7-Layer Definitions ───────────────────────────────────────────────────────
const NEXUS_LAYERS = [
  { id: 1, name: "Surface Scan", desc: "Regex patterns across all code", icon: Search, color: "bg-blue-500", shadow: "shadow-blue-500/50" },
  { id: 2, name: "Semantic Data Flow", desc: "AST Taint Tracking", icon: Code, color: "bg-indigo-500", shadow: "shadow-indigo-500/50" },
  { id: 3, name: "Cryptographic Audit", desc: "Shannon Entropy Analysis", icon: Key, color: "bg-amber-500", shadow: "shadow-amber-500/50" },
  { id: 4, name: "Dependency DNA", desc: "Supply Chain & Typosquatting", icon: PackageSearch, color: "bg-orange-500", shadow: "shadow-orange-500/50" },
  { id: 5, name: "Cross-File Taint", desc: "Multi-hop logic flows", icon: Network, color: "bg-rose-500", shadow: "shadow-rose-500/50" },
  { id: 6, name: "IaC Blast Radius", desc: "Config exposure scoring", icon: CloudCog, color: "bg-cyan-500", shadow: "shadow-cyan-500/50" },
  { id: 7, name: "AI Fusion", desc: "Gemini FP Reduction", icon: BrainCircuit, color: "bg-violet-500", shadow: "shadow-violet-500/50" },
];

export default function DeepScanPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

  const [isFinished, setIsFinished] = useState(false);
  const [isCreatingPr, setIsCreatingPr] = useState(false);

  // Poll real-time status every 1.5s until complete
  const { data: rawStatusData, error: statusError } = useQuery<LiveScanStatus>({
    queryKey: ["liveScan", scanId],
    queryFn: () => getLiveScanStatus(Number(scanId)),
    refetchInterval: isFinished ? false : 1500,
  });
  
  const statusData = rawStatusData || {
    scan_id: Number(scanId),
    status: "running",
    scan_phase_detail: "Initializing engine...",
    layers_completed: [] as number[],
    nexus_score: null,
    total_vulnerabilities: 0,
    is_complete: false,
  };

  useEffect(() => {
    if (statusData?.is_complete) {
      setIsFinished(true);
    }
  }, [statusData?.is_complete]);

  // Once finished, fetch the full report
  const { data: report } = useQuery<VulnerabilityReport>({
    queryKey: ["deepReport", scanId],
    queryFn: () => getVulnerabilityReport(Number(scanId)),
    enabled: isFinished,
  });

  if (statusError) {
    return (
      <div className="p-8 text-center mt-20">
        <AlertTriangle className="w-12 h-12 text-destructive mx-auto mb-4" />
        <h2 className="text-xl font-bold">Failed to load scan stream</h2>
        <Button onClick={() => navigate(-1)} className="mt-4">Go Back</Button>
      </div>
    );
  }

  const completedLayers = new Set(statusData.layers_completed || []);
  const score = statusData.nexus_score !== null ? statusData.nexus_score : null;
  
  const [activeTab, setActiveTab] = useState("findings");
  
  const { data: complianceData } = useQuery({
    queryKey: ["compliance", scanId],
    queryFn: () => getScanCompliance(Number(scanId)),
    enabled: isFinished,
  });
  
  const { data: owaspData } = useQuery({
    queryKey: ["owasp", scanId],
    queryFn: () => getScanOwasp(Number(scanId)),
    enabled: isFinished,
  });
  
  const { data: policyData } = useQuery({
    queryKey: ["policy", scanId],
    queryFn: () => getScanPolicy(Number(scanId)),
    enabled: isFinished,
  });
  
  const { data: threatData } = useQuery({
    queryKey: ["threat", scanId],
    queryFn: () => getScanThreatAnalysis(Number(scanId)),
    enabled: isFinished,
  });
  
  const { data: autofixData } = useQuery({
    queryKey: ["autofixes", scanId],
    queryFn: () => getScanAutofixes(Number(scanId)),
    enabled: isFinished,
  });
  
  const handleCreatePr = async () => {
    setIsCreatingPr(true);
    try {
      const resp = await createAutofixPr(Number(scanId));
      toast.success("Auto-Fix PR Created successfully!", {
        description: "Your security patch is now open on GitHub.",
        action: { label: "View PR", onClick: () => window.open(resp.pr_url, "_blank") }
      });
    } catch (err: any) {
      toast.error("Failed to create Auto-Fix PR", { description: err.message });
    } finally {
      setIsCreatingPr(false);
    }
  };
  
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-slate-100 p-8 pt-24 font-sans selection:bg-rose-500/30">
      
      <div className="max-w-6xl mx-auto">
        <Button variant="ghost" onClick={() => navigate("/dashboard/scans")} className="mb-6 hover:bg-white/5">
          <ArrowLeft className="w-4 h-4 mr-2" /> Back to Scans
        </Button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* LEFT: 7-Layer Pipeline Visualization */}
          <div className="lg:col-span-1 border border-white/10 bg-black/40 backdrop-blur-md rounded-2xl p-6 relative overflow-hidden">
            {/* Background glowing orb */}
            <div className={`absolute -top-32 -left-32 w-64 h-64 rounded-full mix-blend-screen filter blur-[100px] opacity-20 transition-colors duration-1000 ${isFinished ? 'bg-emerald-500' : 'bg-indigo-500'}`} />

            <h2 className="text-xl font-bold tracking-tight mb-8">NEXUS PIPELINE</h2>
            
            <div className="relative space-y-6">
              {/* Connecting line */}
              <div className="absolute left-6 top-8 bottom-8 w-[2px] bg-white/5" />

              {NEXUS_LAYERS.map((layer, idx) => {
                const isActive = !completedLayers.has(layer.id) && 
                  (completedLayers.size === layer.id - 1 || (!isFinished && completedLayers.size === 0 && layer.id === 1));
                const isDone = completedLayers.has(layer.id);
                
                return (
                  <div key={layer.id} className="relative z-10 flex items-center gap-4">
                    {/* Icon Node */}
                    <motion.div 
                      layout
                      initial={{ scale: 0.8, opacity: 0.5 }}
                      animate={{ 
                        scale: isActive ? 1.1 : 1, 
                        opacity: isDone ? 1 : isActive ? 1 : 0.3,
                        boxShadow: isActive ? `0 0 20px rgba(255,255,255,0.2)` : 'none'
                      }}
                      className={`w-12 h-12 rounded-xl flex items-center justify-center border border-white/10 transition-colors duration-500 ${
                        isDone ? layer.color : isActive ? 'bg-slate-800' : 'bg-black/50'
                      }`}
                    >
                      <layer.icon className={`w-5 h-5 ${isDone ? 'text-white' : isActive ? 'text-white/80' : 'text-white/30'}`} />
                      
                      {isActive && !isFinished && (
                        <div className="absolute inset-0 rounded-xl border border-white/50 animate-ping opacity-20" />
                      )}
                    </motion.div>

                    {/* Text */}
                    <div className="flex-1">
                      <h4 className={`text-sm font-bold ${isDone ? 'text-slate-100' : isActive ? 'text-slate-200' : 'text-slate-500'}`}>
                        {layer.name}
                      </h4>
                      <p className={`text-xs ${isDone ? 'text-slate-300' : 'text-slate-600'}`}>
                        {layer.desc}
                      </p>
                    </div>

                    {/* Status marker */}
                    <div className="w-8">
                      {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      {isActive && !isFinished && <Loader2 className="w-4 h-4 text-indigo-400 animate-spin" />}
                    </div>
                  </div>
                );
              })}
            </div>
            
            <div className="mt-8 pt-6 border-t border-white/10">
              <p className="text-xs text-slate-400 font-mono flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                {statusData.scan_phase_detail}
              </p>
            </div>
          </div>

          {/* RIGHT: Score & Findings Stream */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Top Bar: Score & Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              
              {/* Nexus Score Box */}
              <div className="col-span-2 border border-white/10 bg-black/40 rounded-2xl p-6 flex items-center justify-between relative overflow-hidden group">
                <div className="absolute inset-0 bg-gradient-to-r from-violet-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                <div>
                  <p className="text-sm font-semibold text-slate-400 tracking-wider">NEXUS SCORE™</p>
                  <motion.h1 
                    key={score === null ? 'null' : score}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`text-6xl font-black tracking-tighter mt-1 ${
                      score === null ? 'text-slate-500' : score >= 90 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-rose-500'
                    }`}
                  >
                    {score !== null ? score.toFixed(1) : "—"}
                  </motion.h1>
                </div>
                {/* Circular Gauge approximation */}
                <div className="relative w-24 h-24 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="8" fill="none" className="text-white/5" />
                    <motion.circle 
                      cx="48" cy="48" r="40" 
                      stroke="currentColor" strokeWidth="8" fill="none" 
                      strokeDasharray="251"
                      animate={{ strokeDashoffset: score !== null ? 251 - (251 * score) / 100 : 251 }}
                      transition={{ duration: 1, ease: "easeOut" }}
                      className={`${
                        score === null ? 'text-slate-700' : score >= 90 ? 'text-emerald-400' : score >= 70 ? 'text-amber-400' : 'text-rose-500'
                      }`}
                    />
                  </svg>
                  <ShieldCheck className="absolute w-8 h-8 opacity-50" />
                </div>
              </div>

              {/* Stats Boxes */}
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 flex flex-col justify-center">
                <p className="text-sm font-medium text-slate-400">Total Findings</p>
                <p className="text-3xl font-bold mt-1 text-white">{statusData.total_vulnerabilities}</p>
              </div>
              
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 flex flex-col justify-center">
                <p className="text-sm font-medium text-slate-400">Status</p>
                <div className="flex items-center gap-2 mt-1">
                  {isFinished ? (
                    <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Complete</span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 animate-pulse">Running</span>
                  )}
                </div>
              </div>
            </div>

            {/* Tabs Navigation */}
            {isFinished && (
              <div className="flex gap-4 border-b border-white/10 pb-2 mb-6 overflow-x-auto">
                {["findings", "threat", "policy", "compliance"].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-2 text-sm font-semibold transition-colors border-b-2 whitespace-nowrap ${
                      activeTab === tab ? "border-emerald-400 text-white" : "border-transparent text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab === "findings" ? "Intelligent Findings" :
                     tab === "threat" ? "Mythos™ Threat Model" :
                     tab === "policy" ? "Policy Gate" : "Compliance & OWASP"}
                  </button>
                ))}
              </div>
            )}

            {/* Findings Tab Content */}
            {(!isFinished || activeTab === "findings") && (
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 min-h-[400px]">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-bold flex items-center">
                    <ActivityIcon className="mr-2 w-5 h-5 text-violet-400" />
                    Intelligent Findings Stream
                  </h3>
                  {isFinished && report && report.vulnerabilities.length > 0 && (
                    <Button 
                      onClick={handleCreatePr} 
                      disabled={isCreatingPr}
                      className="bg-emerald-500 hover:bg-emerald-600 text-white font-semibold transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)] animate-pulse shadow-emerald-500/20 border border-emerald-400"
                    >
                      {isCreatingPr ? (
                        <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Pushing Fix...</>
                      ) : (
                        <><Code className="w-4 h-4 mr-2" /> Push Auto-Fix PR</>
                      )}
                    </Button>
                  )}
                </div>

                {!isFinished && (
                  <div className="space-y-4">
                    {[1, 2, 3].map(i => (
                      <div key={i} className="h-24 rounded-xl bg-white/5 animate-pulse border border-white/5" />
                    ))}
                    <p className="text-center text-sm text-slate-500 mt-6 animate-pulse">Streaming findings in real-time...</p>
                  </div>
                )}

                {isFinished && report && (
                  <div className="space-y-4">
                    <AnimatePresence>
                      {report.vulnerabilities.map((vuln, i) => (
                        <FindingCard key={vuln.id || i} vuln={vuln} index={i} />
                      ))}
                      {report.vulnerabilities.length === 0 && (
                        <div className="py-12 text-center text-emerald-400/80">
                          <ShieldCheck className="w-16 h-16 mx-auto mb-4 opacity-50" />
                          <p className="text-lg">No vulnerabilities found. Perfect score.</p>
                        </div>
                      )}
                    </AnimatePresence>
                  </div>
                )}
              </div>
            )}

            {/* Threat Model Tab Content */}
            {isFinished && activeTab === "threat" && (
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 min-h-[400px]">
                <h3 className="text-lg font-bold flex items-center mb-6">
                  <BrainCircuit className="mr-2 w-5 h-5 text-violet-400" />
                  Mythos™ Threat Model
                </h3>
                {threatData?.threat_model ? (
                  <div className="prose prose-invert max-w-none text-sm text-slate-300">
                    <pre className="whitespace-pre-wrap font-sans bg-white/5 p-4 rounded-xl border border-white/10">
                      {threatData.threat_model}
                    </pre>
                  </div>
                ) : (
                  <p className="text-sm text-slate-500 text-center py-12">No threat analysis generated.</p>
                )}
              </div>
            )}

            {/* Policy Tab Content */}
            {isFinished && activeTab === "policy" && (
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 min-h-[400px]">
                <h3 className="text-lg font-bold flex items-center mb-6">
                  <ShieldAlert className="mr-2 w-5 h-5 text-amber-400" />
                  Policy-as-Code Gate
                </h3>
                 <div className="mb-6 flex items-center gap-4">
                  <div className="px-4 py-2 rounded-lg bg-white/5 border border-white/10">
                    <span className="text-xs text-slate-400 uppercase tracking-widest block mb-1">Gate Status</span>
                    <span className={`font-bold ${policyData?.gate_status === 'block' ? 'text-rose-500' : policyData?.gate_status === 'warn' ? 'text-amber-500' : 'text-emerald-500'}`}>
                      {policyData?.gate_status?.toUpperCase() || "UNKNOWN"}
                    </span>
                  </div>
                </div>
                {policyData?.violations?.length > 0 ? (
                  <div className="space-y-4">
                    {policyData.violations.map((v: any, i: number) => (
                      <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-white/5 border border-white/10">
                        <AlertTriangle className={`w-5 h-5 shrink-0 ${v.action === 'block' ? 'text-rose-500' : 'text-amber-500'}`} />
                        <div>
                          <p className="font-semibold text-slate-200">{v.rule}</p>
                          <p className="text-sm text-slate-400">{v.reason}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500 text-center py-12">No policy violations. Gate passed.</p>
                )}
              </div>
            )}

            {/* Compliance Tab Content */}
            {isFinished && activeTab === "compliance" && (
              <div className="border border-white/10 bg-black/40 rounded-2xl p-6 min-h-[400px]">
                <h3 className="text-lg font-bold flex items-center mb-6">
                  <ShieldCheck className="mr-2 w-5 h-5 text-blue-400" />
                  Compliance & OWASP Mapping
                </h3>
                
                <h4 className="font-semibold text-slate-300 mb-4 border-b border-white/10 pb-2">OWASP Top 10</h4>
                {owaspData?.owasp_top_10 && Object.keys(owaspData.owasp_top_10).length > 0 ? (
                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                     {Object.entries(owaspData.owasp_top_10).map(([cat, count]: [string, any]) => (
                       <div key={cat} className="flex justify-between items-center p-3 rounded-lg bg-white/5 border border-white/10">
                         <span className="text-sm font-medium text-slate-300">{cat}</span>
                         <span className="text-sm font-bold text-rose-400">{count} findings</span>
                       </div>
                     ))}
                   </div>
                ) : (
                  <p className="text-sm text-slate-500 mb-8">No OWASP Top 10 vulnerabilities detected.</p>
                )}

                <h4 className="font-semibold text-slate-300 mb-4 border-b border-white/10 pb-2">Frameworks (SOC2, PCI, HIPAA, ISO)</h4>
                {complianceData?.compliance && Object.keys(complianceData.compliance).length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(complianceData.compliance).map(([framework, info]: [string, any]) => (
                      <div key={framework} className="p-4 rounded-lg bg-white/5 border border-white/10">
                        <div className="flex justify-between items-center mb-2">
                          <span className="font-bold text-slate-200">{framework}</span>
                           <span className={`text-xs font-bold px-2 py-1 rounded border ${info.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                            {info.status}
                           </span>
                        </div>
                        <p className="text-sm text-slate-400">{info.reason}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No compliance data generated.</p>
                )}
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
}

// Subcomponents

function ActivityIcon(props: any) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

function FindingCard({ vuln, index }: { vuln: VulnerabilityItem, index: number }) {
  const sevColors = {
    critical: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    high: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    medium: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    low: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30"
  };

  const layer = NEXUS_LAYERS.find(l => l.id === vuln.layer_id) || NEXUS_LAYERS[0];
  const exploit = vuln.exploitability ? Math.round(vuln.exploitability * 100) : null;
  const fp = vuln.false_positive_probability ? Math.round(vuln.false_positive_probability * 100) : null;

  return (
    <motion.div 
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="group bg-white/[0.02] border border-white/5 hover:border-white/20 hover:bg-white/[0.04] p-5 rounded-xl transition-all"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${sevColors[vuln.severity]}`}>
              {vuln.severity}
            </span>
            <span className="text-xs font-mono text-slate-500 bg-black/50 px-2 py-0.5 rounded border border-white/5 flex items-center gap-1.5">
              <layer.icon className="w-3 h-3" />
              L{layer.id} — {layer.name}
            </span>
            {vuln.cwe_id && (
              <span className="text-xs font-mono text-slate-600">{vuln.cwe_id}</span>
            )}
          </div>
          
          <h4 className="text-base font-medium text-slate-200 group-hover:text-white transition-colors">{vuln.issue}</h4>
          
          <div className="mt-1 flex items-center gap-2 text-xs text-slate-500 font-mono">
            <span>{vuln.file}</span>
            {vuln.line && <span className="opacity-50">L{vuln.line}</span>}
          </div>
        </div>

        {/* AI Scoring block inside finding */}
        {(exploit !== null || fp !== null) && (
          <div className="hidden md:flex gap-4 ml-4">
            {exploit !== null && (
              <div className="text-right">
                <p className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1">Exploitability</p>
                <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div className={`h-full ${exploit > 70 ? 'bg-rose-500' : exploit > 40 ? 'bg-amber-500' : 'bg-blue-500'}`} style={{ width: `${exploit}%` }} />
                </div>
              </div>
            )}
            {fp !== null && (
              <div className="text-right">
                <p className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1">FP Prob.</p>
                <div className="w-16 h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div className={`h-full ${fp < 30 ? 'bg-emerald-500' : fp > 70 ? 'bg-rose-500' : 'bg-slate-500'}`} style={{ width: `${fp}%` }} />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {(vuln.ai_summary || vuln.description) && (
        <div className="mt-4 pt-4 border-t border-white/5 flex gap-3">
          <BrainCircuit className="w-4 h-4 text-violet-400 shrink-0 mt-0.5" />
          <p className="text-sm text-slate-400">
            {vuln.ai_summary || vuln.description}
          </p>
        </div>
      )}
    </motion.div>
  );
}
