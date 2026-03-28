import { motion } from "framer-motion";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { GitBranch, Shield, Workflow, Star } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useQuery } from "@tanstack/react-query";
import { getDashboardStats } from "@/lib/api";

const ProfilePage = () => {
  const { user } = useAuth();
  const { data: stats } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: getDashboardStats,
  });

  const initials = user
    ? (user.display_name ?? user.username)
        .split(" ")
        .map((n) => n[0])
        .slice(0, 2)
        .join("")
        .toUpperCase()
    : "?";

  const statCards = [
    { label: "Repositories", value: stats?.total_repositories ?? "—", icon: GitBranch, color: "text-neon-cyan" },
    { label: "Scans Run", value: stats?.total_scans ?? "—", icon: Shield, color: "text-neon-purple" },
    { label: "Vulnerabilities", value: stats?.total_vulnerabilities ?? "—", icon: Workflow, color: "text-neon-green" },
    { label: "Critical Found", value: stats?.critical_count ?? "—", icon: Star, color: "text-warning" },
  ];

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold mb-1">Profile</h1>
        <p className="text-sm text-muted-foreground">Your developer identity and activity.</p>
      </div>

      {/* Profile card */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass rounded-xl p-6"
      >
        <div className="flex items-start gap-5">
          <div className="relative">
            <Avatar className="w-20 h-20 ring-2 ring-primary/30">
              {user?.avatar_url && <AvatarImage src={user.avatar_url} alt={user.username} />}
              <AvatarFallback className="bg-primary/20 text-primary text-2xl font-bold">{initials}</AvatarFallback>
            </Avatar>
            <span className="absolute bottom-0 right-0 w-4 h-4 bg-neon-green rounded-full border-2 border-background" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-bold">{user?.display_name ?? user?.username ?? "Not logged in"}</h2>
            <p className="text-sm text-muted-foreground font-mono">
              @{user?.username ?? "—"} · {user?.email ?? "No email"}
            </p>
            <div className="flex items-center gap-2 mt-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
                <GitBranch className="w-3 h-3" /> GitHub Connected
              </span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {statCards.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.08 }}
            className="glass rounded-xl p-4 text-center"
          >
            <s.icon className={`w-5 h-5 mx-auto mb-2 ${s.color}`} />
            <div className="text-2xl font-bold">{s.value}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
          </motion.div>
        ))}
      </div>

      {/* Account info (read-only) */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass rounded-xl p-5 space-y-4"
      >
        <h3 className="font-semibold text-sm border-b border-border/50 pb-3">Account Details</h3>
        {[
          { label: "Display Name", value: user?.display_name ?? "—" },
          { label: "Email Address", value: user?.email ?? "—" },
          { label: "GitHub Username", value: user?.username ?? "—" },
          { label: "Member Since", value: user?.created_at ? new Date(user.created_at).toLocaleDateString() : "—" },
        ].map((field) => (
          <div key={field.label}>
            <label className="text-xs text-muted-foreground block mb-1.5">{field.label}</label>
            <div className="w-full bg-muted/50 rounded-lg px-3 py-2 text-sm font-mono text-foreground/80">
              {field.value}
            </div>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">Profile details are sourced from GitHub and updated on each login.</p>
      </motion.div>
    </div>
  );
};

export default ProfilePage;
