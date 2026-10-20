/** Shared screen patterns: MonitorStatusBadge, MetricCard, etc. */

import {
  MONITOR_STATE_LABELS,
  type MonitorState,
} from '@sitesentinel/shared';

import { Badge, type BadgeTone } from './ui';

const ICONS = {
  clock: <svg className="h-3 w-3" viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.8" /><path d="M10 6v4l2.5 1.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>,
  check: <svg className="h-3 w-3" viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m4.5 10.5 3.5 3.5 7.5-8" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" /></svg>,
  ban: <svg className="h-3 w-3" viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.8" /><path d="m5.5 5.5 9 9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>,
  file: <svg className="h-3 w-3" viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M5 2.5h6l4 4v11a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-14a1 1 0 0 1 1-1Z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /></svg>,
  warn: <svg className="h-3 w-3" viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 6.5v4.5M10 14h.01M8.6 2.9 2.3 14.4A1.6 1.6 0 0 0 3.7 17h12.6a1.6 1.6 0 0 0 1.4-2.6L11.4 2.9a1.6 1.6 0 0 0-2.8 0Z" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>,
};

const MONITOR_TONES: Record<MonitorState, { tone: BadgeTone; icon: keyof typeof ICONS }> = {
  pending: { tone: 'neutral', icon: 'file' },
  up: { tone: 'success', icon: 'check' },
  degraded: { tone: 'warning', icon: 'clock' },
  down: { tone: 'danger', icon: 'warn' },
  unknown: { tone: 'neutral', icon: 'warn' },
  paused: { tone: 'neutral', icon: 'file' },
};

export function MonitorStatusBadge({ status }: { status: string }) {
  const key = (status in MONITOR_TONES ? status : 'unknown') as MonitorState;
  const definition = MONITOR_TONES[key];
  return (
    <Badge tone={definition.tone} icon={ICONS[definition.icon]}>
      {MONITOR_STATE_LABELS[key] ?? status}
    </Badge>
  );
}