import { useState } from 'react';
import { ChevronDown, ChevronRight, ShieldQuestion } from 'lucide-react';
import { DETECTORS } from '@/lib/detectors';
import type { DetectorKey } from '@/lib/types';

export function WhatDoesThisMean({ detector }: { detector: DetectorKey }) {
  const [open, setOpen] = useState(false);
  const meta = DETECTORS[detector];
  return (
    <div className="border-t border-soc-border pt-2 mt-2">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 transition-colors"
      >
        {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        <ShieldQuestion className="w-3.5 h-3.5" />
        What does this mean?
      </button>
      {open && (
        <div className="mt-2 space-y-2 animate-slide-up">
          <p className="text-xs text-ink-300 leading-relaxed">{meta.plainEnglish}</p>
          <div className="flex gap-2 rounded-lg bg-blue-500/10 border border-blue-500/20 p-2">
            <div className="text-xs text-blue-300 leading-relaxed">
              <span className="font-semibold">Next step: </span>
              {meta.nextStep}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
