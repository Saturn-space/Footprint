import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: LucideIcon;
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  variant?: 'default' | 'cyan' | 'emerald' | 'amber' | 'rose';
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtext,
  icon: Icon,
  trend,
  variant = 'default',
  onClick
}) => {
  const variantStyles = {
    default: 'border-slate-800/80 bg-slate-900/60 hover:border-slate-700',
    cyan: 'border-cyan-900/40 bg-slate-900/60 hover:border-cyan-800/60',
    emerald: 'border-emerald-900/40 bg-slate-900/60 hover:border-emerald-800/60',
    amber: 'border-amber-900/40 bg-slate-900/60 hover:border-amber-800/60',
    rose: 'border-rose-900/40 bg-slate-900/60 hover:border-rose-800/60'
  };

  const iconColors = {
    default: 'text-slate-400',
    cyan: 'text-cyan-400',
    emerald: 'text-emerald-400',
    amber: 'text-amber-400',
    rose: 'text-rose-400'
  };

  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-lg border transition-all ${variantStyles[variant]} ${
        onClick ? 'cursor-pointer' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-slate-400 truncate">{label}</span>
        {Icon && <Icon className={`w-4 h-4 shrink-0 ${iconColors[variant]}`} />}
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-semibold tracking-tight text-slate-100 font-mono tabular-nums">
          {value}
        </span>
        {trend && (
          <span
            className={`text-xs font-mono tabular-nums ${
              trend.isPositive ? 'text-emerald-400' : 'text-rose-400'
            }`}
          >
            {trend.value}
          </span>
        )}
      </div>
      {subtext && <p className="mt-1 text-xs text-slate-400 truncate">{subtext}</p>}
    </div>
  );
};
