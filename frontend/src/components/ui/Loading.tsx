import { clsx } from 'clsx';

interface LoadingProps {
  fullScreen?: boolean;
  size?: 'sm' | 'md' | 'lg';
  text?: string;
}

const sizes = { sm: 'w-5 h-5', md: 'w-8 h-8', lg: 'w-12 h-12' };

export function Loading({ fullScreen, size = 'md', text }: LoadingProps) {
  const spinner = (
    <div className="flex flex-col items-center gap-3">
      <div className={clsx('animate-spin rounded-full border-2 border-surface-border border-t-brand-500', sizes[size])} />
      {text && <p className="text-sm text-gray-400">{text}</p>}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 flex items-center justify-center" style={{ background: '#0F1419' }}>
        {spinner}
      </div>
    );
  }

  return <div className="flex items-center justify-center py-16">{spinner}</div>;
}
