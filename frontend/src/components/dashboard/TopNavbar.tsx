/**
 * TopNavbar — enterprise application header.
 * Features:
 *  - Live backend connectivity indicator (polls /health)
 *  - ⌘K global search routing
 *  - Notification bell (future: live events)
 *  - Real JWT revocation on logout
 *  - GitHub avatar + dropdown
 */
import { useState, useEffect, useRef } from "react";
import { Search, Bell, X, LogOut, User, Wifi, WifiOff, Settings } from "lucide-react";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { healthCheck } from "@/lib/api";
import { toast } from "sonner";

// ── Backend Health Badge ───────────────────────────────────────────────────────

const BackendHealthBadge = () => {
  const { data, isError, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: healthCheck,
    refetchInterval: 30000,
    retry: 1,
    staleTime: 25000,
  });

  if (isLoading) return null;

  if (isError) {
    return (
      <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-critical/10 border border-critical/20 text-xs text-critical font-medium">
        <WifiOff className="w-3 h-3" />
        <span>API Offline</span>
      </div>
    );
  }

  return (
    <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-60" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
      </span>
      API Online
    </div>
  );
};

// ── Main Navbar ───────────────────────────────────────────────────────────────

const TopNavbar = () => {
  const [showNotif, setShowNotif] = useState(false);
  const [showUser, setShowUser] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const searchRef = useRef<HTMLInputElement>(null);

  const handleLogout = () => {
    setShowUser(false);
    logout();
    toast.success("Signed out successfully.");
    navigate("/");
  };

  // ⌘K / Ctrl+K focuses the search bar
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const handleSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== "Enter" || !searchQuery.trim()) return;
    const q = searchQuery.toLowerCase();

    const routes: [string, string][] = [
      ["vuln", "/dashboard/vulns"],
      ["scan", "/dashboard/scans"],
      ["threat", "/dashboard/threats"],
      ["compliance", "/dashboard/compliance"],
      ["policy", "/dashboard/policy"],
      ["trend", "/dashboard/trends"],
      ["sbom", "/dashboard/trends"],
      ["cicd", "/dashboard/cicd"],
      ["pipeline", "/dashboard/cicd"],
      ["setting", "/dashboard/settings"],
      ["profile", "/dashboard/profile"],
      ["repo", "/dashboard/repos"],
    ];

    const match = routes.find(([keyword]) => q.includes(keyword));
    navigate(match ? match[1] : "/dashboard/repos");
    setSearchQuery("");
    searchRef.current?.blur();
  };

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest("#user-menu") && !target.closest("#notif-menu")) {
        setShowUser(false);
        setShowNotif(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const initials = user
    ? (user.display_name ?? user.username)
        .split(" ")
        .map((n) => n[0])
        .slice(0, 2)
        .join("")
        .toUpperCase()
    : "?";

  return (
    <header className="h-14 border-b border-border/60 bg-card/40 backdrop-blur-xl flex items-center justify-between px-4 md:px-6 sticky top-0 z-30">
      {/* Search */}
      <div className="relative w-56 md:w-72">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          ref={searchRef}
          id="top-search"
          placeholder="Search pages, scans…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={handleSearch}
          className="w-full bg-muted/60 rounded-lg pl-9 pr-14 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 focus:bg-muted transition-all placeholder:text-muted-foreground/60 font-mono"
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground/50 bg-muted px-1.5 py-0.5 rounded font-mono hidden sm:block">⌘K</span>
      </div>

      {/* Right actions */}
      <div className="flex items-center gap-2 md:gap-4">
        {/* Backend health */}
        <BackendHealthBadge />

        {/* GitHub status */}
        {user && (
          <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-blue/10 border border-neon-blue/20 text-xs text-neon-blue font-medium">
            <span className="font-mono">@{user.username}</span>
          </div>
        )}

        {/* Notifications */}
        <div className="relative" id="notif-menu">
          <button
            id="notifications-btn"
            onClick={() => { setShowNotif(!showNotif); setShowUser(false); }}
            className="relative p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <Bell className="w-5 h-5 text-muted-foreground" />
            {/* Future: show badge */}
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
                <div className="px-4 py-8 text-center text-muted-foreground">
                  <Bell className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No notifications yet.</p>
                  <p className="text-xs mt-1">Scan alerts will appear here.</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* User avatar + dropdown */}
        <div className="relative" id="user-menu">
          <button onClick={() => { setShowUser(!showUser); setShowNotif(false); }}>
            <Avatar className="w-8 h-8 ring-2 ring-border hover:ring-primary/40 transition-all cursor-pointer">
              {user?.avatar_url && <AvatarImage src={user.avatar_url} alt={user.username} />}
              <AvatarFallback className="bg-primary/20 text-primary text-xs font-bold">{initials}</AvatarFallback>
            </Avatar>
          </button>

          <AnimatePresence>
            {showUser && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-12 w-60 glass rounded-xl shadow-2xl border border-border/80 overflow-hidden z-50"
              >
                {/* User info */}
                <div className="px-4 py-3 border-b border-border/50 bg-primary/5">
                  <div className="flex items-center gap-3">
                    <Avatar className="w-9 h-9">
                      {user?.avatar_url && <AvatarImage src={user.avatar_url} />}
                      <AvatarFallback className="bg-primary/20 text-primary text-xs font-bold">{initials}</AvatarFallback>
                    </Avatar>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{user?.display_name ?? user?.username ?? "Not logged in"}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">@{user?.username ?? "—"}</p>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="p-2">
                  <button
                    onClick={() => { setShowUser(false); navigate("/dashboard/profile"); }}
                    className="flex w-full items-center gap-2.5 px-3 py-2 rounded-lg text-sm hover:bg-muted transition-colors"
                  >
                    <User className="w-4 h-4 text-muted-foreground" />
                    Profile
                  </button>
                  <button
                    onClick={() => { setShowUser(false); navigate("/dashboard/settings"); }}
                    className="flex w-full items-center gap-2.5 px-3 py-2 rounded-lg text-sm hover:bg-muted transition-colors"
                  >
                    <Settings className="w-4 h-4 text-muted-foreground" />
                    Settings
                  </button>
                  <div className="my-1 border-t border-border/50" />
                  <button
                    onClick={handleLogout}
                    className="flex w-full items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-critical hover:bg-critical/10 transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  );
};

export default TopNavbar;
