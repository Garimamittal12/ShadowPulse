import { useDashboard } from '@/context/DashboardContext';
import { SEVERITY_META } from '@/lib/detectors';
import { X, ShieldAlert } from 'lucide-react';

export function ToastContainer() {
  const { toasts, dismissToast } = useDashboard();
  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2 w-80">
      {toasts.map((t) => {
        const meta = SEVERITY_META[t.severity];
        return (
          <div
            key={t.id}
            className="card p-3.5 animate-slide-in-right shadow-xl"
            style={{ borderLeftWidth: '3px', borderLeftColor: meta.color }}
          >
            <div className="flex items-start gap-2.5">
              <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: meta.color }} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-white">{t.title}</div>
                <div className="text-xs text-ink-400 mt-0.5">{t.message}</div>
              </div>
              <button onClick={() => dismissToast(t.id)} className="text-ink-500 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
