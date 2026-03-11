import { useEffect, useState } from "react";
import { motion } from "framer-motion";

interface SecurityScoreGaugeProps {
  score: number;
}

const SecurityScoreGauge = ({ score }: SecurityScoreGaugeProps) => {
  const [animatedScore, setAnimatedScore] = useState(0);
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (animatedScore / 100) * circumference;

  const color =
    score >= 80
      ? "hsl(150 100% 50%)"
      : score >= 50
      ? "hsl(45 100% 55%)"
      : "hsl(0 90% 60%)";

  const label =
    score >= 80 ? "Excellent" : score >= 60 ? "Fair" : "Critical";

  const labelColor =
    score >= 80
      ? "text-neon-green"
      : score >= 60
      ? "text-warning"
      : "text-critical";

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 300);
    return () => clearTimeout(timer);
  }, [score]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6 }}
      className="flex flex-col items-center gap-3"
    >
      <div className="relative">
        <svg width="160" height="160" className="-rotate-90">
          {/* Background track */}
          <circle
            cx="80" cy="80" r={radius}
            fill="none"
            stroke="hsl(var(--muted))"
            strokeWidth="10"
          />
          {/* Glow ring (decorative) */}
          <circle
            cx="80" cy="80" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeOpacity="0.08"
          />
          {/* Score arc */}
          <circle
            cx="80" cy="80" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{
              transition: "stroke-dashoffset 1.4s cubic-bezier(0.4, 0, 0.2, 1)",
              filter: `drop-shadow(0 0 10px ${color}80)`,
            }}
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold">{score}</span>
          <span className="text-xs text-muted-foreground mt-0.5">/ 100</span>
        </div>
      </div>

      <div className="text-center">
        <p className="text-sm font-semibold">Security Score</p>
        <p className={`text-xs font-medium mt-0.5 ${labelColor}`}>{label}</p>
      </div>

      {/* Score breakdown mini-bars */}
      <div className="w-full space-y-1.5 px-2">
        {[
          { label: "Code Quality", val: 92 },
          { label: "Dependencies", val: 74 },
          { label: "Secrets", val: 100 },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground w-24 flex-shrink-0">{item.label}</span>
            <div className="flex-1 h-1 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${item.val}%`,
                  background: item.val >= 80 ? color : "hsl(45 100% 55%)",
                  boxShadow: `0 0 6px ${item.val >= 80 ? color : "hsl(45 100% 55%)"}60`,
                  transition: "width 1.4s ease",
                }}
              />
            </div>
            <span className="text-muted-foreground w-6 text-right">{item.val}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
};

export default SecurityScoreGauge;
