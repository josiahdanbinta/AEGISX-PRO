import { type ReactNode } from 'react';
import { motion } from 'framer-motion';
import { clsx } from 'clsx';

type Accent = 'blue' | 'green' | 'orange' | 'purple' | 'red' | 'cyan';

interface CardProps {
  children: ReactNode;
  className?: string;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  hover?: boolean;
  accent?: Accent;
}

const paddings = { none: '', sm: 'p-4', md: 'p-5', lg: 'p-7' };
const accentBorders: Record<Accent, string> = {
  blue: 'border-l-blue-500 dark:border-l-blue-500',
  green: 'border-l-emerald-500 dark:border-l-emerald-500',
  orange: 'border-l-orange-500 dark:border-l-orange-500',
  purple: 'border-l-purple-500 dark:border-l-purple-500',
  red: 'border-l-red-500 dark:border-l-red-500',
  cyan: 'border-l-cyan-500 dark:border-l-cyan-500',
};

export function Card({ children, className, padding = 'md', hover = false, accent }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={clsx(
        'bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800',
        'shadow-sm dark:shadow-none',
        paddings[padding],
        hover && 'hover:-translate-y-0.5 hover:shadow-md dark:hover:shadow-lg dark:hover:border-slate-700 transition-all duration-200 cursor-pointer',
        accent && 'border-l-4',
        accent && accentBorders[accent],
        className,
      )}
    >
      {children}
    </motion.div>
  );
}

export function CardHeader({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('flex items-center justify-between mb-4', className)}>{children}</div>;
}

export function CardTitle({ children, className }: { children: ReactNode; className?: string }) {
  return <h3 className={clsx('text-base font-semibold text-slate-900 dark:text-white', className)}>{children}</h3>;
}
