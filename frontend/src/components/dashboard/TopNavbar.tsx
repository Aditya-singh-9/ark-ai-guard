import { useState, useEffect, useRef } from "react";
import { Search, Bell, X, LogOut, User } from "lucide-react";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";

const TopNavbar = () => {
  const [showNotif, setShowNotif] = useState(false);
  const [showUser, setShowUser] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const searchRef = useRef<HTMLInputElement>(null);

  const handleLogout = () => {
    logout();
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
    if (q.includes("vuln"))       navigate("/dashboard/vulns");
    else if (q.includes("scan"))  navigate("/dashboard/scans");
    else if (q.includes("cicd") || q.includes("pipeline") || q.includes("ci")) navigate("/dashboard/cicd");
    else if (q.includes("profile") || q.includes("setting")) navigate("/dashboard/profile");
    else                          navigate("/dashboard/repos");
    setSearchQuery("");
    searchRef.current?.blur();
  };

  const initials = user
    ? (user.display_name ?? user.username)
        .split(" ")
        .map((n) => n[0])
        .slice(0, 2)
        .join("")
        .toUpperCase()
    : "?";

  return (
    <header className="h-14 border-b border-border/60 bg-card/40 backdrop-blur-xl flex items-center justify-between px-6 sticky top-0 z-30">
      {/* Search */}
      <div className="relative w-72">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <input
          ref={searchRef}
          id="top-search"
          placeholder="Search repositories, scans..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={handleSearch}
          className="w-full bg-muted/60 rounded-lg pl-9 pr-4 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 focus:bg-muted transition-all placeholder:text-muted-foreground/60 font-mono"
        />
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground/50 bg-muted px-1.5 py-0.5 rounded font-mono">⌘K</span>
      </div>


      {/* Right actions */}
      <div className="flex items-center gap-4">
        {/* GitHub Connected indicator */}
        {user && (
          <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
            </span>
            GitHub Connected
          </div>
        )}

        {/* Notifications — static for now, future: poll API */}
        <div className="relative">
          <button
            id="notifications-btn"
            onClick={() => { setShowNotif(!showNotif); setShowUser(false); }}
            className="relative p-2 hover:bg-muted rounded-lg transition-colors"
          >
            <Bell className="w-5 h-5 text-muted-foreground" />
          </button>

          <AnimatePresence>
            {showNotif && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-12 w-72 glass rounded-xl shadow-2xl border border-border/80 overflow-hidden z-50"
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-border/50">
                  <h4 className="text-sm font-semibold">Notifications</h4>
                  <button onClick={() => setShowNotif(false)} className="p-0.5 hover:text-foreground text-muted-foreground">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="px-4 py-8 text-center text-muted-foreground text-sm">
                  No notifications yet.
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* User avatar + dropdown */}
        <div className="relative">
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
                className="absolute right-0 top-12 w-56 glass rounded-xl shadow-2xl border border-border/80 overflow-hidden z-50"
              >
                <div className="px-4 py-3 border-b border-border/50">
                  <p className="text-sm font-semibold">{user?.display_name ?? user?.username ?? "Not logged in"}</p>
                  <p className="text-xs text-muted-foreground font-mono">@{user?.username ?? "—"}</p>
                </div>
                <div className="p-2">
                  <button
                    onClick={() => { setShowUser(false); navigate("/dashboard/profile"); }}
                    className="flex w-full items-center gap-2 px-3 py-2 rounded-lg text-sm hover:bg-muted transition-colors"
                  >
                    <User className="w-4 h-4" /> Profile
                  </button>
                  <button
                    onClick={handleLogout}
                    className="flex w-full items-center gap-2 px-3 py-2 rounded-lg text-sm text-critical hover:bg-critical/10 transition-colors"
                  >
                    <LogOut className="w-4 h-4" /> Logout
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
