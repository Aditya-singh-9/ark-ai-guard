import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Copy, Download, GitBranch } from "lucide-react";
import { toast } from "sonner";

const yamlCode = `name: ARK Secure CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        uses: ark-devsecops/scanner@v2
        with:
          severity-threshold: medium
          fail-on-vulnerability: true
      
      - name: Dependency Audit
        run: npm audit --audit-level=high
      
      - name: SAST Analysis
        uses: ark-devsecops/sast@v1
        with:
          language: typescript

  build-and-test:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - run: npm ci
      - run: npm run build
      - run: npm test

  deploy:
    needs: build-and-test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to Production
        run: echo "Deploying securely..."`;

const CICDGeneratorPage = () => {
  const handleCopy = () => {
    navigator.clipboard.writeText(yamlCode);
    toast.success("Pipeline YAML copied to clipboard");
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">CI/CD Pipeline Generator</h1>
        <p className="text-sm text-muted-foreground">AI-generated secure pipeline for your repository.</p>
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-critical/80" />
            <div className="w-3 h-3 rounded-full bg-warning/80" />
            <div className="w-3 h-3 rounded-full bg-neon-green/80" />
            <span className="text-xs text-muted-foreground font-mono ml-2">.github/workflows/ark-pipeline.yml</span>
          </div>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={handleCopy}>
              <Copy className="w-4 h-4 mr-1" /> Copy
            </Button>
            <Button variant="ghost" size="sm">
              <Download className="w-4 h-4 mr-1" /> Download
            </Button>
            <Button size="sm" className="bg-primary text-primary-foreground hover:bg-primary/90">
              <GitBranch className="w-4 h-4 mr-1" /> Apply to Repo
            </Button>
          </div>
        </div>
        <div className="p-6 overflow-x-auto">
          <pre className="font-mono text-sm leading-relaxed">
            <code>{yamlCode}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};

export default CICDGeneratorPage;
