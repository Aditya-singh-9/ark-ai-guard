import { motion } from "framer-motion";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { GitBranch, Shield, Workflow, Star, Edit2 } from "lucide-react";

const stats = [
  { label: "Repositories", value: "24", icon: GitBranch, color: "text-neon-cyan" },
  { label: "Scans Run", value: "142", icon: Shield, color: "text-neon-purple" },
  { label: "Pipelines", value: "18", icon: Workflow, color: "text-neon-green" },
  { label: "Vulns Fixed", value: "89", icon: Star, color: "text-warning" },
];

const ProfilePage = () => (
  <div className="space-y-6 max-w-3xl">
    <div>
      <h1 className="text-2xl font-bold mb-1">Profile</h1>
      <p className="text-sm text-muted-foreground">Manage your developer identity and activity.</p>
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
            <AvatarFallback className="bg-primary/20 text-primary text-2xl font-bold">DV</AvatarFallback>
          </Avatar>
          <span className="absolute bottom-0 right-0 w-4 h-4 bg-neon-green rounded-full border-2 border-background" />
        </div>
        <div className="flex-1">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-xl font-bold">Dev User</h2>
              <p className="text-sm text-muted-foreground font-mono">@devuser · devuser@company.com</p>
              <div className="flex items-center gap-2 mt-2">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-neon-cyan/10 border border-neon-cyan/20 text-xs text-neon-cyan font-medium">
                  <Star className="w-3 h-3" /> PRO Plan
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-neon-green/10 border border-neon-green/20 text-xs text-neon-green font-medium">
                  <GitBranch className="w-3 h-3" /> GitHub Connected
                </span>
              </div>
            </div>
            <Button variant="outline" size="sm" className="gap-1.5 flex-shrink-0">
              <Edit2 className="w-3.5 h-3.5" /> Edit Profile
            </Button>
          </div>
        </div>
      </div>
    </motion.div>

    {/* Stats */}
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {stats.map((s, i) => (
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

    {/* Profile form */}
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 }}
      className="glass rounded-xl p-5 space-y-4"
    >
      <h3 className="font-semibold text-sm border-b border-border/50 pb-3">Account Details</h3>
      {[
        { label: "Display Name", value: "Dev User", type: "text" },
        { label: "Email Address", value: "devuser@company.com", type: "email" },
        { label: "GitHub Username", value: "devuser", type: "text" },
        { label: "Organization", value: "myorg", type: "text" },
      ].map((field) => (
        <div key={field.label}>
          <label className="text-xs text-muted-foreground block mb-1.5">{field.label}</label>
          <input
            type={field.type}
            defaultValue={field.value}
            className="w-full bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono"
          />
        </div>
      ))}
      <Button className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 mt-2">
        Save Changes
      </Button>
    </motion.div>
  </div>
);

export default ProfilePage;
