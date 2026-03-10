import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid } from "recharts";

const data = [
  { name: "Mon", scans: 12 },
  { name: "Tue", scans: 19 },
  { name: "Wed", scans: 8 },
  { name: "Thu", scans: 15 },
  { name: "Fri", scans: 22 },
  { name: "Sat", scans: 6 },
  { name: "Sun", scans: 10 },
];

const ActivityChart = () => (
  <div className="glass rounded-xl p-5 h-full">
    <h3 className="text-sm font-semibold mb-4">Scan Activity</h3>
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis dataKey="name" tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} />
        <YAxis tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} />
        <Tooltip
          contentStyle={{
            background: 'hsl(var(--card))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            color: 'hsl(var(--foreground))',
          }}
        />
        <Bar dataKey="scans" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  </div>
);

export default ActivityChart;
