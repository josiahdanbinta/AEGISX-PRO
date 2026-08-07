import { forwardRef, type ButtonHTMLAttributes, type ElementType } from 'react';
import { clsx } from 'clsx';
import { Loader2 } from 'lucide-react';

type Variant = 'primary' | 'secondary' | 'danger' | 'success' | 'ghost' | 'outline';
type Size = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ElementType;
}

const variants: Record<Variant, string> = {
  primary:   'bg-brand-500 hover:bg-brand-600 text-white shadow-sm hover:shadow-glow-sm focus:ring-brand-500',
  secondary: 'bg-surface-card border border-surface-border text-gray-200 hover:bg-surface-hover hover:border-brand-500/30 focus:ring-brand-500',
  danger:    'bg-red-600 hover:bg-red-700 text-white shadow-sm focus:ring-red-500',
  success:   'bg-emerald-600 hover:bg-emerald-700 text-white shadow-sm focus:ring-emerald-500',
  ghost:     'text-gray-400 hover:text-gray-200 hover:bg-surface-hover focus:ring-brand-500',
  outline:   'border border-surface-border bg-transparent text-gray-300 hover:bg-surface-hover hover:border-brand-500/50 focus:ring-brand-500',
};

const sizes: Record<Size, string> = {
  sm: 'px-3 py-1.5 text-xs rounded-lg gap-1.5 min-h-[32px]',
  md: 'px-4 py-2 text-sm rounded-button gap-2 min-h-[40px]',
  lg: 'px-6 py-2.5 text-base rounded-button gap-2 min-h-[48px]',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', loading, icon: Icon, className, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      className={clsx(
        'inline-flex items-center justify-center font-medium transition-all duration-200',
        'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-surface-base',
        'disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.97]',
        variants[variant],
        sizes[size],
        className,
      )}
      disabled={disabled || loading}
      aria-disabled={disabled || loading}
      aria-busy={loading ? true : undefined}
      type={props.type || 'button'}
      {...props}
    >
      {loading ? (
        <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
      ) : Icon ? (
        <Icon className="w-4 h-4" aria-hidden="true" />
      ) : null}
      {children}
    </button>
  ),
);
Button.displayName = 'Button';
