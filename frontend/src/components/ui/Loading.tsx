import { clsx } from 'clsx';

interface LoadingProps {
  fullScreen?: boolean;
  size?: 'sm' | 'md' | 'lg';
  text?: string;
}

const sizes = { sm: 'w-4 h-4', md: 'w-8 h-8', lg: 'w-12 h-12' };

export function Loading({ fullScreen, size = 'md', text }: LoadingProps) {
  const spinner = (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className={clsx('rounded-full border-2 border-slate-200 dark:border-slate-700 border-t-brand-500 animate-spin', sizes[size])} />
      {text && <p className="text-sm text-slate-500 dark:text-slate-400">{text}</p>}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-slate-50 dark:bg-slate-950 z-50">
        {spinner}
      </div>
    );
  }
  return spinner;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx('animate-pulse bg-slate-200 dark:bg-slate-800 rounded-lg', className)} />;
}
