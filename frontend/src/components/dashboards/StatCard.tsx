import { type ElementType, useEffect, useState, useRef } from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';
import { motion } from 'framer-motion';
import { clsx } from 'clsx';

type Accent = 'blue' | 'green' | 'orange' | 'purple' | 'red' | 'cyan';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: ElementType;
  trend?: { value: string; direction: 'up' | 'down' };
  accent?: Accent;
  sparklineData?: number[];
  className?: string;
}

const accentColors: Record<Accent, { bg: string; text: string; stroke: string; border: string }> = {
  blue:   { bg: 'bg-blue-100 dark:bg-blue-950', text: 'text-blue-600 dark:text-blue-400', stroke: '#3b82f6', border: 'border-l-blue-500 dark:border-l-blue-500' },
  green:  { bg: 'bg-emerald-100 dark:bg-emerald-950', text: 'text-emerald-600 dark:text-emerald-400', stroke: '#10b981', border: 'border-l-emerald-500 dark:border-l-emerald-500' },
  orange: { bg: 'bg-orange-100 dark:bg-orange-950', text: 'text-orange-600 dark:text-orange-400', stroke: '#f97316', border: 'border-l-orange-500 dark:border-l-orange-500' },
  purple: { bg: 'bg-purple-100 dark:bg-purple-950', text: 'text-purple-600 dark:text-purple-400', stroke: '#8b5cf6', border: 'border-l-purple-500 dark:border-l-purple-500' },
  red:    { bg: 'bg-red-100 dark:bg-red-950', text: 'text-red-600 dark:text-red-400', stroke: '#ef4444', border: 'border-l-red-500 dark:border-l-red-500' },
  cyan:   { bg: 'bg-cyan-100 dark:bg-cyan-950', text: 'text-cyan-600 dark:text-cyan-400', stroke: '#06b6d4', border: 'border-l-cyan-500 dark:border-l-cyan-500' },
};

function AnimatedValue({ value }: { value: string | number }) {
  const [display, setDisplay] = useState(0);
  const num = typeof value === 'string' ? parseFloat(value) : value;

  useEffect(() => {
    if (isNaN(num)) { setDisplay(0); return; }
    const duration = 600;
    const start = performance.now();
    let raf: number;
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(num * eased));
      if (progress < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [num]);

  return <>{display.toLocaleString()}</>;
}

function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (!data || data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * 100;
    const y = 20 - ((v - min) / range) * 16 - 2;
    return `${i === 0 ? 'M' : 'L'}${x},${y}`;
  }).join(' ');

  return (
    <div className="h-8 mt-2">
      <svg width="100%" height="100%" viewBox="0 0 100 20" preserveAspectRatio="none">
        <path d={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

export function StatCard({ label, value, icon: Icon, trend, accent = 'blue', sparklineData, className }: StatCardProps) {
  const colors = accentColors[accent];

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={clsx(
        'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800',
        'shadow-sm dark:shadow-none p-5 border-l-4',
        colors.border,
        'hover:-translate-y-1 hover:shadow-md dark:hover:shadow-lg transition-all duration-200',
        className,
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-500 uppercase tracking-wider mb-1">{label}</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
            <AnimatedValue value={value} />
          </p>
          {trend && (
            <div className="flex items-center gap-1 mt-1.5">
              {trend.direction === 'up' ? (
                <TrendingUp className="w-3.5 h-3.5 text-red-500" />
              ) : (
                <TrendingDown className="w-3.5 h-3.5 text-emerald-500" />
              )}
              <span className={clsx('text-xs font-medium', trend.direction === 'up' ? 'text-red-500' : 'text-emerald-500')}>
                {trend.value}
              </span>
            </div>
          )}
        </div>
        <div className={clsx('p-2.5 rounded-xl', colors.bg)}>
          <Icon className={clsx('w-5 h-5', colors.text)} />
        </div>
      </div>
      {sparklineData && <Sparkline data={sparklineData} color={colors.stroke} />}
    </motion.div>
  );
}
