import { clsx } from 'clsx';
import type { ReactNode } from 'react';

type Variant = 'danger' | 'warning' | 'info' | 'success' | 'default';
type Size = 'sm' | 'md' | 'lg';

interface BadgeProps {
  children: ReactNode;
  variant?: Variant;
  size?: Size;
  className?: string;
}

const variants: Record<Variant, string> = {
  danger:  'bg-red-900/50 text-red-300 border-red-800',
  warning:'bg-amber-900/50 text-amber-300 border-amber-800',
  info:    'bg-brand-900/40 text-brand-300 border-brand-800',
  success: 'bg-emerald-900/50 text-emerald-300 border-emerald-800',
  default: 'bg-surface-hover text-gray-300 border-surface-border',
};

const sizes: Record<Size, string> = {
  sm: 'px-1.5 py-0.5 text-[10px]',
  md: 'px-2 py-0.5 text-xs',
  lg: 'px-2.5 py-1 text-sm',
};

export function Badge({ children, variant = 'default', size = 'md', className }: BadgeProps) {
  return (
    <span className={clsx('inline-flex items-center font-medium rounded-full border', variants[variant], sizes[size], className)}>
      {children}
    </span>
  );
}
