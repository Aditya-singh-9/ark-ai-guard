import { useState } from "react";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { Copy, Download, GitBranch, Wand2, RefreshCw, CheckCircle, X } from "lucide-react";
import { toast } from "sonner";
import { useQuery, useMutation } from "@tanstack/react-query";
import { getRepositories, generateCicd, CICDResponse } from "@/lib/api";

const CICDGeneratorPage = () => {
  const [selectedRepoId, setSelectedRepoId] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const [result, setResult] = useState<CICDResponse | null>(null);

  const { data: repos = [], isLoading: loadingRepos } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
  });

  const generateMutation = useMutation({
    mutationFn: (repoId: number) => generateCicd(repoId),
    onSuccess: (data) => {
      setResult(data);
      toast.success("Pipeline generated successfully!");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleGenerate = () => {
    if (!selectedRepoId) { toast.error("Please select a repository first."); return; }
    generateMutation.mutate(selectedRepoId);
  };

  const yamlCode = result?.yaml ?? "";

  const handleCopy = () => {
    navigator.clipboard.writeText(yamlCode);
    setCopied(true);
    toast.success("Pipeline YAML copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([yamlCode], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ark-pipeline.yml";
    a.click();
    toast.success("Pipeline file downloaded!");
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">CI/CD Pipeline Generator</h1>
        <p className="text-sm text-muted-foreground">AI-generated secure GitHub Actions pipeline for your repository.</p>
      </div>

      {/* Config panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-xl p-5"
      >
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <label className="text-xs text-muted-foreground mb-1.5 block">Select Repository</label>
            <select
              value={selectedRepoId ?? ""}
              onChange={(e) => {
                setSelectedRepoId(e.target.value ? Number(e.target.value) : null);
                setResult(null);
              }}
              className="bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono min-w-[200px]"
            >
              <option value="">— Select repository —</option>
              {repos.map((r) => (
                <option key={r.id} value={r.id}>{r.full_name}</option>
              ))}
            </select>
          </div>
          <div className="flex-1" />
          <Button
            onClick={handleGenerate}
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            disabled={generateMutation.isPending || !selectedRepoId}
          >
            {generateMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Wand2 className="w-4 h-4" />
            )}
            {generateMutation.isPending ? "Generating..." : result ? "Regenerate Pipeline" : "Generate Pipeline"}
          </Button>
        </div>

        {result && (
          <div className="mt-4 pt-4 border-t border-border/40 flex gap-4 text-xs text-muted-foreground flex-wrap">
            <span>Language: <span className="text-foreground font-mono">{result.language}</span></span>
            {result.frameworks.length > 0 && (
              <span>Frameworks: <span className="text-foreground font-mono">{result.frameworks.join(", ")}</span></span>
            )}
          </div>
        )}
      </motion.div>

      {!result && !generateMutation.isPending && (
        <div className="text-center py-16 text-muted-foreground glass rounded-xl">
          <Wand2 className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select a repository and click "Generate Pipeline" to create your AI-powered CI/CD configuration.</p>
        </div>
      )}

      {generateMutation.isPending && (
        <div className="text-center py-16 text-muted-foreground glass rounded-xl">
          <RefreshCw className="w-8 h-8 mx-auto mb-3 animate-spin opacity-60" />
          <p className="text-sm">Analyzing repository and generating pipeline with AI...</p>
        </div>
      )}

      {/* Code editor */}
      {result && yamlCode && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass rounded-xl overflow-hidden"
        >
          {/* Editor header */}
          <div className="flex items-center justify-between p-4 border-b border-border/50 bg-muted/30">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-critical/80" />
                <div className="w-3 h-3 rounded-full bg-warning/80" />
                <div className="w-3 h-3 rounded-full bg-neon-green/80" />
              </div>
              <span className="text-xs text-muted-foreground font-mono">.github/workflows/ark-pipeline.yml</span>
            </div>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={handleCopy} className="gap-1.5 text-xs h-8">
                {copied ? (
                  <CheckCircle className="w-3.5 h-3.5 text-neon-green" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                {copied ? "Copied!" : "Copy"}
              </Button>
              <Button variant="ghost" size="sm" onClick={handleDownload} className="gap-1.5 text-xs h-8">
                <Download className="w-3.5 h-3.5" /> Download
              </Button>
            </div>
          </div>

          {/* YAML code with basic syntax highlighting */}
          <div className="overflow-x-auto p-6 bg-background/40 max-h-[500px] overflow-y-auto">
            <pre className="font-mono text-xs leading-relaxed text-foreground/90">
              {yamlCode.split("\n").map((line, i) => {
                const trimmed = line.trimStart();
                let cls = "text-foreground/90";
                if (trimmed.startsWith("#")) cls = "text-muted-foreground/70 italic";
                else if (trimmed.startsWith("name:") || trimmed.startsWith("on:") || trimmed.startsWith("jobs:") || trimmed.startsWith("env:")) cls = "text-neon-purple";
                else if (trimmed.match(/^[a-z-]+:$/) || trimmed.match(/^[a-z-]+\s*:/)) cls = "text-neon-cyan";
                else if (trimmed.startsWith("- ") || trimmed.startsWith("uses:") || trimmed.startsWith("run:")) cls = "text-neon-green";

                return (
                  <span key={i} className="block">
                    <span className="text-muted-foreground/30 select-none mr-4 text-right inline-block w-7 text-[10px]">{i + 1}</span>
                    <span className={cls}>{line}</span>
                  </span>
                );
              })}
            </pre>
          </div>
        </motion.div>
      )}

      {/* Pipeline jobs visualization */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="glass rounded-xl p-5"
        >
          <h3 className="text-sm font-semibold mb-4">Pipeline Structure</h3>
          <div className="flex items-center gap-0 flex-wrap">
            {[
              { name: "Security Scan", icon: "🔒", color: "border-neon-cyan/40 bg-neon-cyan/5" },
              { name: "Build & Test", icon: "🔨", color: "border-neon-blue/40 bg-neon-blue/5" },
              { name: "Deploy", icon: "🚀", color: "border-neon-green/40 bg-neon-green/5" },
            ].map((job, i, arr) => (
              <div key={job.name} className="flex items-center">
                <div className={`rounded-xl border px-5 py-3 ${job.color}`}>
                  <div className="text-lg mb-1">{job.icon}</div>
                  <p className="text-xs font-medium">{job.name}</p>
                </div>
                {i < arr.length - 1 && (
                  <div className="w-8 flex items-center justify-center">
                    <div className="w-full h-0.5 bg-gradient-to-r from-neon-cyan/40 to-neon-blue/40" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default CICDGeneratorPage;
