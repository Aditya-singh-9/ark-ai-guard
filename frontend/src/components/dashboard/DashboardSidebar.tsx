/**
 * DashboardSidebar — enterprise-grade collapsible navigation.
 * Features:
 *  - Grouped navigation sections
 *  - Live active route highlighting with animated indicator
 *  - Backend health status pill
 *  - Scan-in-progress live indicator
 *  - Collapsed mode with tooltips
 */
import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard, GitBranch, Shield, AlertTriangle,
  Workflow, Settings, User, ChevronLeft, ChevronRight,
  Zap, TrendingUp, Target, Award, Gavel, Activity,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats } from "@/lib/api";

// ── Navigation structure ──────────────────────────────────────────────────────

const NAV_GROUPS = [
  {
    label: "Overview",
    items: [
      { icon: LayoutDashboard, label: "Dashboard", path: "/dashboard", color: "text-neon-cyan", exact: true },
    ],
  },
  {
    label: "Security",
    items: [
      { icon: GitBranch,     label: "Repositories",    path: "/dashboard/repos",    color: "text-neon-blue" },
      { icon: Shield,        label: "Security Scans",  path: "/dashboard/scans",    color: "text-neon-purple" },
      { icon: AlertTriangle, label: "Vulnerabilities", path: "/dashboard/vulns",    color: "text-warning" },
      { icon: Target,        label: "Threat Analysis", path: "/dashboard/threats",  color: "text-critical" },
    ],
  },
  {
    label: "Compliance & Policy",
    items: [
      { icon: Award,   label: "Compliance",  path: "/dashboard/compliance", color: "text-neon-purple" },
      { icon: Gavel,   label: "Policy Gate", path: "/dashboard/policy",     color: "text-neon-green" },
    ],
  },
  {
    label: "Tools",
    items: [
      { icon: TrendingUp, label: "Trends & SBOM",  path: "/dashboard/trends", color: "text-neon-cyan" },
      { icon: Workflow,   label: "CI/CD Generator", path: "/dashboard/cicd",   color: "text-neon-green" },
    ],
  },
];

const BOTTOM_ITEMS = [
  { icon: Settings, label: "Settings", path: "/dashboard/settings", color: "text-muted-foreground" },
  { icon: User,     label: "Profile",  path: "/dashboard/profile",  color: "text-muted-foreground" },
];

// ── NavItem ───────────────────────────────────────────────────────────────────

const NavItem = ({
  item,
  collapsed,
  active,
}: {
  item: { icon: React.ElementType; label: string; path: string; color: string; exact?: boolean };
  collapsed: boolean;
  active: boolean;
}) => {
  const Icon = item.icon;

  return (
    <Link
      to={item.path}
      title={collapsed ? item.label : undefined}
      className={`relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group ${
        active
          ? "bg-primary/10 text-primary font-medium"
          : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
      }`}
    >
      {active && (
        <motion.span
          layoutId="active-pill"
          className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-primary rounded-full"
        />
      )}
      <Icon
        className={`w-5 h-5 shrink-0 transition-colors ${
          active ? "text-primary" : `${item.color} opacity-70 group-hover:opacity-100`
        }`}
      />
      <AnimatePresence>
        {!collapsed && (
          <motion.span
            initial={{ opacity: 0, width: 0 }}
            animate={{ opacity: 1, width: "auto" }}
            exit={{ opacity: 0, width: 0 }}
            transition={{ duration: 0.15 }}
            className="truncate overflow-hidden whitespace-nowrap"
          >
            {item.label}
          </motion.span>
        )}
      </AnimatePresence>
    </Link>
  );
};

// ── Main sidebar ──────────────────────────────────────────────────────────────

const DashboardSidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  // Live scan indicator
  const { data: stats } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
    refetchInterval: 10000,
    staleTime: 8000,
  });

  const hasRunning = (stats?.repositories ?? []).some(
    (r: any) => r.scan_status === "running" || r.scan_status === "pending" || r.scan_status === "cloning"
  );

  const isActive = (path: string, exact?: boolean) => {
    if (exact) return location.pathname === path;
    return location.pathname === path || (path !== "/dashboard" && location.pathname.startsWith(path));
  };

  return (
    <aside
      className={`${collapsed ? "w-16" : "w-64"} min-h-screen border-r border-border/60 flex flex-col transition-all duration-300 ease-in-out flex-shrink-0 relative`}
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
              <div className="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center flex-shrink-0 neon-glow-sm">
                <Shield className="w-4 h-4 text-primary" />
              </div>
              <div className="truncate">
                <p className="text-sm font-bold tracking-tight leading-tight gradient-text">ARK DevSecOps</p>
                <p className="text-[10px] text-muted-foreground font-mono leading-tight">AI Platform v2</p>
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

      {/* Live Scan Indicator */}
      <AnimatePresence>
        {hasRunning && !collapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mx-2 my-1.5 overflow-hidden"
          >
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-neon-cyan/10 border border-neon-cyan/20">
              <span className="relative flex h-2 w-2 flex-shrink-0">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-cyan opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-cyan" />
              </span>
              <span className="text-[11px] text-neon-cyan font-medium">Scan in progress…</span>
              <Activity className="w-3 h-3 text-neon-cyan ml-auto animate-pulse" />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main nav groups */}
      <nav className="flex-1 p-2 space-y-1 overflow-y-auto overflow-x-hidden">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="space-y-0.5">
            <AnimatePresence>
              {!collapsed && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="text-[10px] uppercase tracking-widest text-muted-foreground/40 px-3 pt-3 pb-1 font-medium"
                >
                  {group.label}
                </motion.p>
              )}
            </AnimatePresence>
            {group.items.map((item) => (
              <NavItem
                key={item.path}
                item={item}
                collapsed={collapsed}
                active={isActive(item.path, item.exact)}
              />
            ))}
          </div>
        ))}
      </nav>

      {/* Bottom section */}
      <div className="p-2 border-t border-border/40 space-y-0.5">
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mx-1 mb-2 p-2.5 rounded-lg bg-gradient-to-r from-primary/10 to-neon-purple/5 border border-primary/15"
            >
              <div className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-primary flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-xs font-medium text-primary truncate">Enterprise Plan</p>
                  <p className="text-[10px] text-muted-foreground">All features unlocked</p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {BOTTOM_ITEMS.map((item) => (
          <NavItem
            key={item.path}
            item={item}
            collapsed={collapsed}
            active={isActive(item.path)}
          />
        ))}
      </div>
    </aside>
  );
};

export default DashboardSidebar;
