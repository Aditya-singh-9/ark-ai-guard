import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard, GitBranch, Shield, AlertTriangle,
  Workflow, Settings, User, ChevronLeft, ChevronRight
} from "lucide-react";

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard", path: "/dashboard" },
  { icon: GitBranch, label: "Repositories", path: "/dashboard/repos" },
  { icon: Shield, label: "Security Scans", path: "/dashboard/scans" },
  { icon: AlertTriangle, label: "Vulnerabilities", path: "/dashboard/vulns" },
  { icon: Workflow, label: "CI/CD Generator", path: "/dashboard/cicd" },
  { icon: Settings, label: "Settings", path: "/dashboard/settings" },
  { icon: User, label: "Profile", path: "/dashboard/profile" },
];

const DashboardSidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside className={`${collapsed ? 'w-16' : 'w-60'} min-h-screen border-r border-border bg-sidebar flex flex-col transition-all duration-300`}>
      <div className="p-4 flex items-center justify-between border-b border-border">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-primary" />
            <span className="font-bold text-sm">ARK DevSecOps</span>
          </div>
        )}
        <button onClick={() => setCollapsed(!collapsed)} className="p-1 hover:bg-muted rounded-md transition-colors">
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      <nav className="flex-1 p-2 space-y-1">
        {navItems.map((item) => {
          const active = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200
                ${active
                  ? 'bg-primary/10 text-primary font-medium'
                  : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
                }
              `}
            >
              <item.icon className="w-5 h-5 shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
};

export default DashboardSidebar;
