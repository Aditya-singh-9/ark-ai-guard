import { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";
import { ReactNode } from "react";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
  color?: "cyan" | "green" | "purple" | "orange" | "red";
  delay?: number;
}

const colorMap = {
  cyan: {
    icon: "text-neon-cyan",
    bg: "bg-neon-cyan/10",
    glow: "group-hover:shadow-[0_0_30px_-5px_hsl(var(--neon-cyan)/0.3)]",
    border: "group-hover:border-neon-cyan/30",
  },
  green: {
    icon: "text-neon-green",
    bg: "bg-neon-green/10",
    glow: "group-hover:shadow-[0_0_30px_-5px_hsl(var(--neon-green)/0.3)]",
    border: "group-hover:border-neon-green/30",
  },
  purple: {
    icon: "text-neon-purple",
    bg: "bg-neon-purple/10",
    glow: "group-hover:shadow-[0_0_30px_-5px_hsl(var(--neon-purple)/0.3)]",
    border: "group-hover:border-neon-purple/30",
  },
  orange: {
    icon: "text-warning",
    bg: "bg-warning/10",
    glow: "group-hover:shadow-[0_0_30px_-5px_hsl(var(--warning)/0.3)]",
    border: "group-hover:border-warning/30",
  },
  red: {
    icon: "text-critical",
    bg: "bg-critical/10",
    glow: "group-hover:shadow-[0_0_30px_-5px_hsl(var(--critical)/0.3)]",
    border: "group-hover:border-critical/30",
  },
};

const MetricCard = ({
  title,
  value,
  icon: Icon,
  trend,
  trendUp,
  color = "cyan",
  delay = 0,
}: MetricCardProps) => {
  const c = colorMap[color];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ y: -4, transition: { duration: 0.2, ease: [0.22, 1, 0.36, 1] } }}
      whileTap={{ scale: 0.98 }}
      style={{ willChange: "opacity, transform" }}
      className={`group glass rounded-xl p-5 transition-all duration-250 cursor-default border border-border/50 ${c.border} ${c.glow}`}
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`w-10 h-10 rounded-lg ${c.bg} flex items-center justify-center transition-transform group-hover:scale-110`}>
          <Icon className={`w-5 h-5 ${c.icon}`} />
        </div>
        <span className="text-xs text-muted-foreground font-mono px-2 py-1 rounded-md bg-muted/50">
          live
        </span>
      </div>

      <div className="space-y-1">
        <div className="text-3xl font-bold tracking-tight">{value}</div>
        <div className="text-sm text-muted-foreground">{title}</div>
      </div>

      {trend && (
        <div className={`mt-3 flex items-center gap-1 text-xs font-medium ${
          trendUp ? "text-neon-green" : "text-critical"
        }`}>
          <span>{trendUp ? "↑" : "↓"}</span>
          <span>{trend}</span>
        </div>
      )}
    </motion.div>
  );
};

export default MetricCard;
