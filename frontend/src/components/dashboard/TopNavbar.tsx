import { useState } from "react";
import { Search, Bell, GitBranch, CheckCircle, X } from "lucide-react";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { motion, AnimatePresence } from "framer-motion";

const notifications = [
  { id: 1, title: "Scan Complete", body: "frontend-app scan finished — 2 vulns found", time: "2m ago", type: "info" },
  { id: 2, title: "Critical Alert", body: "SQL injection found in auth-service", time: "15m ago", type: "critical" },
  { id: 3, title: "Pipeline Ready", body: "CI/CD pipeline generated for api-gateway", time: "1h ago", type: "success" },
];

const TopNavbar = () => {
  const [showNotif, setShowNotif] = useState(false);

  return (
    <header className="h-14 border-b border-border/60 bg-card/40 backdrop-blur-xl flex items-center justify-between px-6 sticky top-0 z-30">
      {/* Search */}
      <div className="relative w-72">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          id="top-search"
          placeholder="Search repositories, scans..."
          className="w-full bg-muted/60 rounded-lg pl-9 pr-4 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 focus:bg-muted transition-all placeholder:text-muted-foreground/60 font-mono"
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground/50 bg-muted px-1.5 py-0.5 rounded font-mono">⌘K</span>
      </div>

      {/* Right actions */}
      <div className="flex items-center gap-4">
        {/* GitHub Connected indicator */}
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
          </span>
          GitHub Connected
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            id="notifications-btn"
            onClick={() => setShowNotif(!showNotif)}
            className="relative p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <Bell className="w-5 h-5 text-muted-foreground" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-primary rounded-full animate-pulse" />
          </button>

          <AnimatePresence>
            {showNotif && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-12 w-80 glass rounded-xl shadow-2xl border border-border/80 overflow-hidden z-50"
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-border/50">
                  <h4 className="text-sm font-semibold">Notifications</h4>
                  <button onClick={() => setShowNotif(false)} className="p-0.5 hover:text-foreground text-muted-foreground">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="divide-y divide-border/40 max-h-64 overflow-y-auto">
                  {notifications.map((n) => (
                    <div key={n.id} className="px-4 py-3 hover:bg-muted/40 transition-colors cursor-pointer">
                      <div className="flex items-start gap-2">
                        <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${
                          n.type === "critical" ? "bg-critical" :
                          n.type === "success" ? "bg-neon-green" :
                          "bg-neon-blue"
                        }`} />
                        <div>
                          <p className="text-xs font-medium">{n.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{n.body}</p>
                          <p className="text-[10px] text-muted-foreground/60 mt-1 font-mono">{n.time}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="px-4 py-2 border-t border-border/50">
                  <button className="text-xs text-primary hover:underline">View all notifications</button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* User avatar */}
        <Avatar className="w-8 h-8 ring-2 ring-border hover:ring-primary/40 transition-all cursor-pointer">
          <AvatarFallback className="bg-primary/20 text-primary text-xs font-bold">DV</AvatarFallback>
        </Avatar>
      </div>
    </header>
  );
};

export default TopNavbar;
