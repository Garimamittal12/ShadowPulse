export function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div className={`card p-4 ${className}`}>
      <div className="space-y-3">
        <div className="skeleton h-4 w-24" />
        <div className="skeleton h-8 w-16" />
        <div className="skeleton h-3 w-full" />
      </div>
    </div>
  );
}

export function SkeletonList({ count = 4 }: { count?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="card p-3.5">
          <div className="flex items-start gap-3">
            <div className="skeleton w-9 h-9 rounded-lg" />
            <div className="flex-1 space-y-2">
              <div className="flex justify-between">
                <div className="skeleton h-4 w-32" />
                <div className="skeleton h-3 w-16" />
              </div>
              <div className="skeleton h-3 w-3/4" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="card p-0 overflow-hidden">
      <div className="p-3 border-b border-soc-border">
        <div className="skeleton h-4 w-48" />
      </div>
      <div className="divide-y divide-soc-border">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex gap-4 p-3">
            {Array.from({ length: cols }).map((_, c) => (
              <div key={c} className="skeleton h-3 flex-1" style={{ maxWidth: `${100 / cols}%` }} />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  message,
  action,
}: {
  icon: typeof import('lucide-react').Shield;
  title: string;
  message: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="card flex flex-col items-center justify-center text-center py-16 px-6">
      <div className="w-14 h-14 rounded-full bg-green-500/10 flex items-center justify-center mb-4">
        <Icon className="w-7 h-7 text-green-400" />
      </div>
      <h3 className="text-base font-semibold text-white mb-1">{title}</h3>
      <p className="text-sm text-ink-400 max-w-md">{message}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="card flex flex-col items-center justify-center text-center py-12 px-6 border-red-500/30">
      <div className="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mb-3">
        <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M5.07 19h13.86c1.54 0 2.5-1.67 1.73-3L13.73 4c-.77-1.33-2.69-1.33-3.46 0L3.34 16c-.77 1.33.19 3 1.73 3z" />
        </svg>
      </div>
      <h3 className="text-sm font-semibold text-white mb-1">Cannot reach ShadowPulse backend</h3>
      <p className="text-xs text-ink-400 max-w-sm">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn-outline mt-4 text-xs">
          Retry connection
        </button>
      )}
    </div>
  );
}
