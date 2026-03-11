import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Shield, Bell, Key, Link, Palette, Save } from "lucide-react";

const SettingsPage = () => {
  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold mb-1">Settings</h1>
        <p className="text-sm text-muted-foreground">Manage your account preferences and integrations.</p>
      </div>

      {/* Sections */}
      {[
        {
          icon: Link,
          title: "Integrations",
          color: "text-neon-cyan",
          bg: "bg-neon-cyan/10",
          items: [
            { label: "GitHub Personal Access Token", type: "password", placeholder: "ghp_••••••••••••••••••", hint: "Required for repository scanning" },
            { label: "GitLab Token (Optional)", type: "password", placeholder: "glpat-••••••••••••••••", hint: "Connect your GitLab repositories" },
          ],
        },
        {
          icon: Shield,
          title: "Security Scanning",
          color: "text-neon-purple",
          bg: "bg-neon-purple/10",
          items: [
            { label: "Minimum Severity to Flag", type: "select", options: ["low", "medium", "high", "critical"], hint: "Vulnerabilities below this will not trigger alerts" },
            { label: "Auto-scan on Push", type: "toggle", hint: "Automatically scan repositories on every git push" },
          ],
        },
        {
          icon: Bell,
          title: "Notifications",
          color: "text-warning",
          bg: "bg-warning/10",
          items: [
            { label: "Email Alerts", type: "toggle", hint: "Receive email on critical vulnerabilities" },
            { label: "Slack Webhook URL", type: "text", placeholder: "https://hooks.slack.com/services/...", hint: "Send alerts to your Slack workspace" },
          ],
        },
      ].map((section, si) => (
        <motion.div
          key={section.title}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: si * 0.1 }}
          className="glass rounded-xl overflow-hidden"
        >
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border/50">
            <div className={`w-8 h-8 rounded-lg ${section.bg} flex items-center justify-center`}>
              <section.icon className={`w-4 h-4 ${section.color}`} />
            </div>
            <h2 className="font-semibold text-sm">{section.title}</h2>
          </div>
          <div className="p-5 space-y-5">
            {section.items.map((item, ii) => (
              <div key={ii}>
                <label className="text-sm font-medium block mb-1.5">{item.label}</label>
                {item.type === "toggle" ? (
                  <label className="flex items-center gap-3 cursor-pointer">
                    <div className="relative">
                      <input type="checkbox" defaultChecked className="sr-only peer" />
                      <div className="w-10 h-5 bg-muted rounded-full peer peer-checked:bg-primary transition-colors" />
                      <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform peer-checked:translate-x-5" />
                    </div>
                    <span className="text-xs text-muted-foreground">{item.hint}</span>
                  </label>
                ) : item.type === "select" ? (
                  <div>
                    <select className="w-full bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono">
                      {item.options?.map((o) => <option key={o}>{o}</option>)}
                    </select>
                    <p className="text-xs text-muted-foreground mt-1">{item.hint}</p>
                  </div>
                ) : (
                  <div>
                    <input
                      type={item.type}
                      placeholder={item.placeholder}
                      className="w-full bg-muted rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-primary/60 font-mono placeholder:text-muted-foreground/50"
                    />
                    <p className="text-xs text-muted-foreground mt-1">{item.hint}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      ))}

      <Button className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
        <Save className="w-4 h-4" /> Save Settings
      </Button>
    </div>
  );
};

export default SettingsPage;
