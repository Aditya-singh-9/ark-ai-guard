import { ReactNode } from "react";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
}

const MetricCard = ({ title, value, icon: Icon, trend, trendUp }: MetricCardProps) => (
  <div className="glass-hover rounded-xl p-5">
    <div className="flex items-center justify-between mb-3">
      <span className="text-sm text-muted-foreground">{title}</span>
      <Icon className="w-5 h-5 text-primary" />
    </div>
    <div className="text-3xl font-bold mb-1">{value}</div>
    {trend && (
      <span className={`text-xs ${trendUp ? 'text-neon-green' : 'text-critical'}`}>
        {trendUp ? '↑' : '↓'} {trend}
      </span>
    )}
  </div>
);

export default MetricCard;
