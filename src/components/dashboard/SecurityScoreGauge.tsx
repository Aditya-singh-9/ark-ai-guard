interface SecurityScoreGaugeProps {
  score: number;
}

const SecurityScoreGauge = ({ score }: SecurityScoreGaugeProps) => {
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? 'hsl(var(--neon-green))' : score >= 50 ? 'hsl(var(--warning))' : 'hsl(var(--critical))';

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" className="-rotate-90">
        <circle cx="70" cy="70" r="54" fill="none" stroke="hsl(var(--muted))" strokeWidth="10" />
        <circle
          cx="70" cy="70" r="54" fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-1000"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="absolute mt-10 text-center">
        <div className="text-3xl font-bold">{score}</div>
        <div className="text-xs text-muted-foreground">Security Score</div>
      </div>
    </div>
  );
};

export default SecurityScoreGauge;
