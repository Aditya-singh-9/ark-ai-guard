import {
  AreaChart, Area, XAxis, YAxis, ResponsiveContainer,
  Tooltip, CartesianGrid, Legend
} from "recharts";
import { motion } from "framer-motion";

const data = [
  { name: "Mon", scans: 12, resolved: 8 },
  { name: "Tue", scans: 19, resolved: 14 },
  { name: "Wed", scans: 8, resolved: 5 },
  { name: "Thu", scans: 15, resolved: 11 },
  { name: "Fri", scans: 22, resolved: 18 },
  { name: "Sat", scans: 6, resolved: 6 },
  { name: "Sun", scans: 10, resolved: 7 },
];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass rounded-lg p-3 text-xs border border-border/80 shadow-xl">
        <p className="font-semibold text-foreground mb-1">{label}</p>
        {payload.map((p: any) => (
          <p key={p.name} style={{ color: p.color }}>
            {p.name}: <span className="font-bold">{p.value}</span>
          </p>
        ))}
      </div>
    );
  }
  return null;
};

const ActivityChart = () => (
  <motion.div
    initial={{ opacity: 0, y: 16 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.6, delay: 0.3 }}
    className="glass rounded-xl p-5 h-full"
  >
    <div className="flex items-center justify-between mb-5">
      <div>
        <h3 className="text-sm font-semibold">Scan Activity</h3>
        <p className="text-xs text-muted-foreground mt-0.5">Weekly scan & resolution trends</p>
      </div>
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-3 h-0.5 bg-neon-cyan rounded-full" />
          Scans
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-3 h-0.5 bg-neon-green rounded-full" />
          Resolved
        </span>
      </div>
    </div>
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="hsl(185 100% 50%)" stopOpacity={0.3} />
            <stop offset="95%" stopColor="hsl(185 100% 50%)" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="resolvedGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="hsl(150 100% 50%)" stopOpacity={0.3} />
            <stop offset="95%" stopColor="hsl(150 100% 50%)" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.5)" vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="scans"
          name="Scans"
          stroke="hsl(185 100% 50%)"
          strokeWidth={2}
          fill="url(#scanGradient)"
          dot={false}
          activeDot={{ r: 4, fill: 'hsl(185 100% 50%)', strokeWidth: 0 }}
        />
        <Area
          type="monotone"
          dataKey="resolved"
          name="Resolved"
          stroke="hsl(150 100% 50%)"
          strokeWidth={2}
          fill="url(#resolvedGradient)"
          dot={false}
          activeDot={{ r: 4, fill: 'hsl(150 100% 50%)', strokeWidth: 0 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  </motion.div>
);

export default ActivityChart;
