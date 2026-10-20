import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';

import { api } from '../lib/api';
import { useSession } from '../lib/session';
import { Card, PageHeader } from '../components/ui';
import { MonitorStatusBadge } from '../components/patterns';

interface MonitorDetail {
  id: string;
  name: string;
  monitorType: string;
  target: string;
  currentState: string;
  enabled: boolean;
  intervalSeconds: number;
  timeoutMs: number;
  lastCheckedAt: string | null;
  nextCheckAt: string | null;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  tags: string[];
}

export function MonitorDetailPage() {
  const { monitorId = '' } = useParams();
  const { activeOrganizationId } = useSession();

  const monitor = useQuery({
    queryKey: ['sitesentinel', activeOrganizationId, 'monitor', monitorId],
    queryFn: () => api.get<MonitorDetail>(`/${activeOrganizationId}/monitors/${monitorId}`),
    enabled: Boolean(activeOrganizationId && monitorId),
  });

  if (monitor.isError) {
    return (
      <>
        <PageHeader title="Monitor" />
        <Card>Failed to load monitor.</Card>
      </>
    );
  }

  const data = monitor.data;

  return (
    <>
      <PageHeader
        title={data?.name ?? 'Monitor'}
        description={`Type: ${data?.monitorType} • Target: ${data?.target}`}
        actions={
          <Link to={`/${activeOrganizationId}/monitors`} className="btn btn-ghost">
            Back
          </Link>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          <div className="card">
            <h2 className="text-lg font-semibold text-ink mb-4">Status</h2>
            <dl className="grid gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-ink-muted">Current State</dt>
                <dd className="mt-1"><MonitorStatusBadge status={data?.currentState ?? 'unknown'} /></dd>
              </div>
              <div>
                <dt className="text-ink-muted">Enabled</dt>
                <dd className="mt-1 tabular">{data?.enabled ? 'Yes' : 'No'}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Type</dt>
                <dd className="mt-1 text-ink">{data?.monitorType}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Target</dt>
                <dd className="tabular text-ink">{data?.target}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Interval</dt>
                <dd className="tabular text-ink">{data?.intervalSeconds}s</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Timeout</dt>
                <dd className="tabular text-ink">{data?.timeoutMs}ms</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Last Checked</dt>
                <dd className="tabular text-ink">{data?.lastCheckedAt ? new Date(data.lastCheckedAt).toLocaleString() : 'Never'}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Next Check</dt>
                <dd className="tabular text-ink">{data?.nextCheckAt ? new Date(data.nextCheckAt).toLocaleString() : '—'}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Consecutive Failures</dt>
                <dd className="tabular text-ink">{data?.consecutiveFailures}</dd>
              </div>
              <div>
                <dt className="text-ink-muted">Consecutive Successes</dt>
                <dd className="tabular text-ink">{data?.consecutiveSuccesses}</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <div className="card">
          <h2 className="text-lg font-semibold text-ink mb-4">Tags</h2>
          {data?.tags?.length ? (
            <div className="flex flex-wrap gap-2">
              {data.tags.map((tag) => (
                <span key={tag} className="px-2 py-1 rounded bg-surface-sunken text-[13px] text-ink">{tag}</span>
              ))}
            </div>
          ) : (
            <p className="text-ink-muted">No tags.</p>
          )}
        </div>
      </div>
    </>
  );
}