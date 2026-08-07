import { type ReactNode } from 'react';
import { motion } from 'framer-motion';
import { clsx } from 'clsx';

type Accent = 'purple' | 'green' | 'orange' | 'red' | 'cyan';

interface CardProps {
  children: ReactNode;
  className?: string;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  hover?: boolean;
  accent?: Accent;
}

const paddings = { none: '', sm: 'p-4', md: 'p-5', lg: 'p-7' };
const accentBorders: Record<Accent, string> = {
  purple: 'border-l-brand-500',
  green:  'border-l-emerald-500',
  orange: 'border-l-orange-500',
  red:    'border-l-red-500',
  cyan:   'border-l-cyan-500',
};

export function Card({ children, className, padding = 'md', hover, accent }: CardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={clsx(
        'bg-surface-card border border-surface-border rounded-card',
        paddings[padding],
        hover && 'hover:shadow-card-hover hover:border-brand-500/20 transition-all duration-200 cursor-pointer',
        accent && `border-l-2 ${accentBorders[accent]}`,
        className,
      )}
    >
      {children}
    </motion.div>
  );
}

export function CardHeader({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={clsx('flex items-center justify-between mb-4', className)}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <h3 className={clsx('text-base font-semibold text-white', className)}>
      {children}
    </h3>
  );
}
