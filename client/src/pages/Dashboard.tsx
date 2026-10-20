import { useQuery } from '@tanstack/react-query';

import { api } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useSession } from '../lib/session';
import { PageHeader } from '../components/ui';

interface DashboardSummary {
  stateCounts: Record<string, number>;
  totalChecks: number;
  successfulChecks: number;
  staleMonitorCount: number;
  rangeLabel: string;
  method: string;
  totalRows: number;
}

export function DashboardPage() {
  const { activeOrganizationId } = useSession();

  const summary = useQuery({
    queryKey: ['sitesentinel', activeOrganizationId, 'dashboard'],
    queryFn: () => api.get<DashboardSummary>(`/${activeOrganizationId}/dashboard/summary`),
    enabled: Boolean(activeOrganizationId),
  });

  if (summary.isError) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <div className="card">Failed to load dashboard.</div>
      </>
    );
  }

  const data = summary.data;

  const stateCounts = data?.stateCounts ?? {};

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={
          data
            ? `Overview of your monitors as of ${formatDateTime(data.rangeLabel)}.`
            : 'Loading dashboard…'
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <p className="text-xs text-ink-muted">Total Monitors</p>
          <p className="text-2xl font-semibold text-ink">{(stateCounts.up ?? 0) + (stateCounts.down ?? 0) + (stateCounts.unknown ?? 0) + (stateCounts.degraded ?? 0) + (stateCounts.paused ?? 0)}</p>
        </div>
        <div className="card">
          <p className="text-xs text-ink-muted">Up</p>
          <p className="text-2xl font-semibold text-success">{stateCounts.up ?? 0}</p>
        </div>
        <div className="card">
          <p className="text-xs text-ink-muted">Down</p>
          <p className="text-2xl font-semibold text-danger">{stateCounts.down ?? 0}</p>
        </div>
        <div className="card">
          <p className="text-xs text-ink-muted">Unknown</p>
          <p className="text-2xl font-semibold text-warning">{stateCounts.unknown ?? 0}</p>
        </div>
      </div>

      <div className="mt-4 card">
        <h2 className="text-lg font-semibold text-ink mb-4">Recent Checks</h2>
        <p className="text-[13px] text-ink-muted">
          {data?.totalChecks ?? 0} checks in the last 24 hours ({data?.successfulChecks ?? 0} successful).
        </p>
      </div>
    </>
  );
}