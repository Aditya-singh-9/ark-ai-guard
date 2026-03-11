import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard, GitBranch, Shield, AlertTriangle,
  Workflow, Settings, User, ChevronLeft, ChevronRight,
  Zap
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard", path: "/dashboard", color: "text-neon-cyan" },
  { icon: GitBranch, label: "Repositories", path: "/dashboard/repos", color: "text-neon-blue" },
  { icon: Shield, label: "Security Scans", path: "/dashboard/scans", color: "text-neon-purple" },
  { icon: AlertTriangle, label: "Vulnerabilities", path: "/dashboard/vulns", color: "text-warning" },
  { icon: Workflow, label: "CI/CD Generator", path: "/dashboard/cicd", color: "text-neon-green" },
];

const bottomItems = [
  { icon: Settings, label: "Settings", path: "/dashboard/settings", color: "text-muted-foreground" },
  { icon: User, label: "Profile", path: "/dashboard/profile", color: "text-muted-foreground" },
];

const DashboardSidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside
      className={`${collapsed ? "w-16" : "w-64"} min-h-screen border-r border-border/60 flex flex-col transition-all duration-300 ease-in-out flex-shrink-0`}
      style={{ background: "hsl(var(--sidebar-background))" }}
    >
      {/* Logo */}
      <div className="h-14 px-4 flex items-center justify-between border-b border-border/40">
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
              className="flex items-center gap-2 min-w-0"
            >
              <div className="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center flex-shrink-0">
                <Shield className="w-4 h-4 text-primary" />
              </div>
              <div className="truncate">
                <p className="text-sm font-bold tracking-tight leading-tight">ARK DevSecOps</p>
                <p className="text-[10px] text-muted-foreground font-mono leading-tight">AI Platform</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 hover:bg-sidebar-accent rounded-lg transition-colors text-muted-foreground hover:text-foreground flex-shrink-0"
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Main nav */}
      <nav className="flex-1 p-2 space-y-0.5">
        {!collapsed && (
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground/50 px-3 py-2 font-medium">
            Navigation
          </p>
        )}
        {navItems.map((item) => {
          const active = location.pathname === item.path ||
            (item.path !== "/dashboard" && location.pathname.startsWith(item.path));
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group relative ${
                active
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              }`}
            >
              {active && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-primary rounded-full" />
              )}
              <item.icon
                className={`w-5 h-5 shrink-0 transition-colors ${
                  active ? "text-primary" : `${item.color} opacity-70 group-hover:opacity-100`
                }`}
              />
              <AnimatePresence>
                {!collapsed && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.15 }}
                  >
                    {item.label}
                  </motion.span>
                )}
              </AnimatePresence>
            </Link>
          );
        })}
      </nav>

      {/* Bottom section */}
      <div className="p-2 border-t border-border/40 space-y-0.5">
        {!collapsed && (
          <div className="mx-1 mb-2 p-2.5 rounded-lg bg-primary/5 border border-primary/10">
            <div className="flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-primary flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-xs font-medium text-primary truncate">PRO Plan Active</p>
                <p className="text-[10px] text-muted-foreground">All features unlocked</p>
              </div>
            </div>
          </div>
        )}
        {bottomItems.map((item) => {
          const active = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 ${
                active
                  ? "bg-primary/10 text-primary"
                  : "text-sidebar-foreground hover:bg-sidebar-accent"
              }`}
            >
              <item.icon className="w-5 h-5 shrink-0" />
              <AnimatePresence>
                {!collapsed && (
                  <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    {item.label}
                  </motion.span>
                )}
              </AnimatePresence>
            </Link>
          );
        })}
      </div>
    </aside>
  );
};

export default DashboardSidebar;
