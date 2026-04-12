import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Bell, Slack, Webhook, Key, ToggleLeft, ToggleRight, Save,
  Check, AlertCircle, ExternalLink, Copy, Shield, Globe, EyeOff, Eye,
  Loader2,
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { testSlackWebhook, getBadgeUrl, getRepositories } from "@/lib/api";
import { toast } from "sonner";
import { useQuery } from "@tanstack/react-query";

// ── Local storage helpers ─────────────────────────────────────────────────────

const LS_KEY = "ark_settings";

interface Settings {
  slackWebhook: string;
  slackEnabled: boolean;
  emailAlerts: boolean;
  emailAddress: string;
  alertOnCritical: boolean;
  alertOnHigh: boolean;
  alertOnComplete: boolean;
  autoScanOnPush: boolean;  // visual only for now
  badgeRepoId: number | null;
}

const DEFAULT_SETTINGS: Settings = {
  slackWebhook: "",
  slackEnabled: false,
  emailAlerts: false,
  emailAddress: "",
  alertOnCritical: true,
  alertOnHigh: false,
  alertOnComplete: false,
  autoScanOnPush: false,
  badgeRepoId: null,
};

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? { ...DEFAULT_SETTINGS, ...JSON.parse(raw) } : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function saveSettings(s: Settings) {
  localStorage.setItem(LS_KEY, JSON.stringify(s));
}

// ── Toggle ────────────────────────────────────────────────────────────────────

const Toggle = ({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) => (
  <button
    onClick={() => onChange(!checked)}
    className={`relative w-10 h-5.5 h-6 rounded-full transition-colors duration-200 ${checked ? "bg-primary" : "bg-muted"}`}
    style={{ height: "22px", width: "40px" }}
  >
    <motion.div
      className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow"
      animate={{ left: checked ? "20px" : "2px" }}
      transition={{ type: "spring", stiffness: 500, damping: 30 }}
    />
  </button>
);

// ── Section wrapper ────────────────────────────────────────────────────────────

const Section = ({
  icon: Icon,
  title,
  description,
  children,
  iconColor = "text-primary",
}: {
  icon: React.ElementType;
  title: string;
  description: string;
  children: React.ReactNode;
  iconColor?: string;
}) => (
  <motion.div
    initial={{ opacity: 0, y: 8 }}
    animate={{ opacity: 1, y: 0 }}
    className="glass rounded-xl p-5 space-y-4"
  >
    <div className="flex items-center gap-3">
      <div className={`w-9 h-9 rounded-lg bg-current/10 flex items-center justify-center border border-current/20 ${iconColor}`} style={{ backgroundColor: "rgba(255,255,255,0.05)" }}>
        <Icon className={`w-4.5 h-4.5 ${iconColor}`} style={{ width: "18px", height: "18px" }} />
      </div>
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
    </div>
    <div className="border-t border-border/30 pt-4 space-y-3">
      {children}
    </div>
  </motion.div>
);

// ── Row ───────────────────────────────────────────────────────────────────────

const Row = ({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) => (
  <div className="flex items-center justify-between gap-4">
    <div>
      <p className="text-sm font-medium">{label}</p>
      {description && <p className="text-xs text-muted-foreground mt-0.5">{description}</p>}
    </div>
    {children}
  </div>
);

// ── Badge Embed ────────────────────────────────────────────────────────────────

const BadgeSection = ({ settings, onChange }: { settings: Settings; onChange: (partial: Partial<Settings>) => void }) => {
  const { data: repos = [] } = useQuery({
    queryKey: ["repositories"],
    queryFn: getRepositories,
    staleTime: 30_000,
  });

  const selectedRepo = repos.find(r => r.id === settings.badgeRepoId);
  const badgeUrl = settings.badgeRepoId ? getBadgeUrl(settings.badgeRepoId) : null;
  const markdownSnippet = badgeUrl ? `![ARK Security](${badgeUrl})` : null;
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!markdownSnippet) return;
    navigator.clipboard.writeText(markdownSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Section icon={Shield} title="Security Badge" description="Embed a live security score badge in your README" iconColor="text-neon-cyan">
      <Row label="Repository" description="Which repo to show the score for">
        <select
          value={settings.badgeRepoId ?? ""}
          onChange={e => onChange({ badgeRepoId: e.target.value ? parseInt(e.target.value) : null })}
          className="glass text-sm px-3 py-1.5 rounded-lg border border-border/60 text-foreground bg-transparent min-w-44"
        >
          <option value="">Select repo…</option>
          {repos.map(r => <option key={r.id} value={r.id}>{r.full_name}</option>)}
        </select>
      </Row>
      {badgeUrl && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <img src={badgeUrl} alt="Security badge preview" className="h-5" onError={e => (e.currentTarget.style.display = "none")} />
            <span className="text-xs text-muted-foreground">Live preview</span>
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono bg-muted/30 rounded-lg px-3 py-2 text-muted-foreground truncate">
              {markdownSnippet}
            </code>
            <button
              onClick={handleCopy}
              className="p-2 glass rounded-lg border border-border/60 hover:border-primary/40 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-neon-green" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      )}
    </Section>
  );
};

// ── Main Settings Page ─────────────────────────────────────────────────────────

const SettingsPage = () => {
  const [settings, setSettings] = useState<Settings>(loadSettings);
  const [showWebhookUrl, setShowWebhookUrl] = useState(false);
  const [saved, setSaved] = useState(false);

  const update = (partial: Partial<Settings>) => {
    setSettings(prev => ({ ...prev, ...partial }));
  };

  const handleSave = () => {
    saveSettings(settings);
    setSaved(true);
    toast.success("Settings saved!");
    setTimeout(() => setSaved(false), 1500);
  };

  const { mutate: testSlack, isPending: testingSlack } = useMutation({
    mutationFn: () => testSlackWebhook(settings.slackWebhook),
    onSuccess: () => toast.success("Test notification sent to Slack! ✓"),
    onError: (e: Error) => toast.error(`Slack test failed: ${e.message}`),
  });

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-1">Settings</h1>
          <p className="text-sm text-muted-foreground">Configure notifications, integrations, and preferences.</p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:opacity-90 transition-all"
        >
          {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          {saved ? "Saved!" : "Save Changes"}
        </button>
      </div>

      {/* Slack */}
      <Section icon={Bell} title="Slack Alerts" description="Get notified in Slack when scans complete or critical issues are found" iconColor="text-warning">
        <Row label="Enable Slack Notifications" description="Send scan alerts to a Slack channel">
          <Toggle checked={settings.slackEnabled} onChange={v => update({ slackEnabled: v })} />
        </Row>

        {settings.slackEnabled && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} className="space-y-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1.5">Slack Incoming Webhook URL</label>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showWebhookUrl ? "text" : "password"}
                    value={settings.slackWebhook}
                    onChange={e => update({ slackWebhook: e.target.value })}
                    placeholder="https://hooks.slack.com/services/T.../B.../..."
                    className="w-full glass text-sm px-3 py-2 rounded-lg border border-border/60 text-foreground bg-transparent font-mono pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowWebhookUrl(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showWebhookUrl ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <button
                  onClick={() => testSlack()}
                  disabled={!settings.slackWebhook || testingSlack}
                  className={`px-3 py-2 rounded-lg text-xs font-mono border transition-all ${settings.slackWebhook && !testingSlack ? "glass border-border/60 hover:border-primary/40 text-foreground" : "opacity-40 cursor-not-allowed border-border/30 text-muted-foreground"}`}
                >
                  {testingSlack ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Test"}
                </button>
              </div>
              <p className="text-[10px] text-muted-foreground mt-1.5">
                <a
                  href="https://api.slack.com/messaging/webhooks"
                  target="_blank" rel="noreferrer"
                  className="underline hover:text-foreground transition-colors"
                >
                  Create a webhook at api.slack.com ↗
                </a>
              </p>
            </div>

            <div className="space-y-2">
              <p className="text-xs text-muted-foreground font-medium">Alert me when:</p>
              <Row label="Critical vulnerabilities found">
                <Toggle checked={settings.alertOnCritical} onChange={v => update({ alertOnCritical: v })} />
              </Row>
              <Row label="High severity issues found">
                <Toggle checked={settings.alertOnHigh} onChange={v => update({ alertOnHigh: v })} />
              </Row>
              <Row label="Scan completes (any result)">
                <Toggle checked={settings.alertOnComplete} onChange={v => update({ alertOnComplete: v })} />
              </Row>
            </div>
          </motion.div>
        )}
      </Section>

      {/* Auto-scan */}
      <Section icon={Webhook} title="Automation" description="Automatically trigger scans and integrate with your workflow" iconColor="text-neon-purple">
        <Row
          label="Auto-scan on Git Push"
          description="Requires a GitHub App installation (coming soon)"
        >
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground bg-muted/30 px-2 py-0.5 rounded-full">Coming Soon</span>
            <Toggle checked={false} onChange={() => toast.info("Auto-scan on push coming in the next update!")} />
          </div>
        </Row>
        <Row
          label="PR Security Gate"
          description="Block PRs with critical vulnerabilities (GitHub App required)"
        >
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground bg-muted/30 px-2 py-0.5 rounded-full">Coming Soon</span>
            <Toggle checked={false} onChange={() => toast.info("PR gate coming in the next update!")} />
          </div>
        </Row>
      </Section>

      {/* Badge */}
      <BadgeSection settings={settings} onChange={update} />

      {/* Danger zone */}
      <Section icon={AlertCircle} title="Account" description="Manage your account settings" iconColor="text-critical">
        <Row label="Data retention" description="Scan history is retained for 90 days">
          <span className="text-xs text-muted-foreground">90 days</span>
        </Row>
        <Row label="Export all data" description="Download a JSON archive of all your scan data">
          <button className="text-xs px-3 py-1.5 glass rounded-lg border border-border/60 hover:border-warning/40 text-warning transition-colors">
            Export
          </button>
        </Row>
      </Section>
    </div>
  );
};

export default SettingsPage;
