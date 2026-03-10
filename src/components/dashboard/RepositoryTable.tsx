import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Search, Play, Eye } from "lucide-react";

const repos = [
  { name: "frontend-app", score: 92, lastScan: "2h ago", vulns: 2, status: "Secure" },
  { name: "api-gateway", score: 74, lastScan: "5h ago", vulns: 8, status: "Warning" },
  { name: "auth-service", score: 45, lastScan: "1d ago", vulns: 15, status: "Critical" },
  { name: "payment-service", score: 88, lastScan: "3h ago", vulns: 4, status: "Secure" },
  { name: "data-pipeline", score: 67, lastScan: "12h ago", vulns: 11, status: "Warning" },
];

const statusColor = (s: string) =>
  s === "Secure" ? "bg-neon-green/10 text-neon-green border-neon-green/20" :
  s === "Warning" ? "bg-warning/10 text-warning border-warning/20" :
  "bg-critical/10 text-critical border-critical/20";

const RepositoryTable = () => (
  <div className="glass rounded-xl overflow-hidden">
    <div className="p-5 flex items-center justify-between border-b border-border">
      <h3 className="font-semibold">Repositories</h3>
      <div className="flex gap-2">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            placeholder="Search repos..."
            className="bg-muted rounded-lg pl-9 pr-4 py-2 text-sm outline-none focus:ring-1 focus:ring-primary w-48"
          />
        </div>
        <Button size="sm" className="bg-primary text-primary-foreground hover:bg-primary/90">
          <Play className="w-4 h-4 mr-1" /> Scan Repository
        </Button>
      </div>
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th className="text-left p-4 font-medium">Repository</th>
            <th className="text-left p-4 font-medium">Score</th>
            <th className="text-left p-4 font-medium">Last Scan</th>
            <th className="text-left p-4 font-medium">Vulns</th>
            <th className="text-left p-4 font-medium">Status</th>
            <th className="text-left p-4 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {repos.map((r) => (
            <tr key={r.name} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
              <td className="p-4 font-mono text-sm">{r.name}</td>
              <td className="p-4">
                <span className={r.score >= 80 ? 'text-neon-green' : r.score >= 50 ? 'text-warning' : 'text-critical'}>
                  {r.score}%
                </span>
              </td>
              <td className="p-4 text-muted-foreground">{r.lastScan}</td>
              <td className="p-4">{r.vulns}</td>
              <td className="p-4">
                <Badge variant="outline" className={statusColor(r.status)}>{r.status}</Badge>
              </td>
              <td className="p-4">
                <div className="flex gap-2">
                  <Button variant="ghost" size="sm" className="h-8"><Play className="w-3.5 h-3.5" /></Button>
                  <Button variant="ghost" size="sm" className="h-8"><Eye className="w-3.5 h-3.5" /></Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

export default RepositoryTable;
