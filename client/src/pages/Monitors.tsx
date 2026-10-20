import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { api } from '../lib/api';
import { useSession } from '../lib/session';
import { EmptyState, PageHeader } from '../components/ui';
import { MonitorStatusBadge } from '../components/patterns';

interface MonitorsResponse {
  items: Array<{
    id: string;
    name: string;
    monitorType: string;
    target: string;
    currentState: string;
    enabled: boolean;
    lastCheckedAt: string | null;
    nextCheckAt: string | null;
  }>;
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export function MonitorsPage() {
  const { activeOrganizationId } = useSession();

  const monitors = useQuery({
    queryKey: ['sitesentinel', activeOrganizationId, 'monitors'],
    queryFn: () => api.get<MonitorsResponse>(`/${activeOrganizationId}/monitors`),
    enabled: Boolean(activeOrganizationId),
  });

  return (
    <>
      <PageHeader
        title="Monitors"
        description="All your monitors and their current state."
        actions={
          <a href={`/${activeOrganizationId}/monitors/new`} className="btn btn-primary">
            Add Monitor
          </a>
        }
      />

      <div className="card">
        {monitors.isLoading ? (
          <div className="p-4 text-center text-ink-muted">Loading…</div>
        ) : monitors.isError ? (
          <div className="p-4 text-danger">Failed to load monitors.</div>
        ) : monitors.data?.items.length === 0 ? (
          <EmptyState
            title="No monitors yet"
            description="Add your first monitor to start monitoring."
            action={<a href={`/${activeOrganizationId}/monitors/new`} className="btn btn-primary">Add Monitor</a>}
          />
        ) : (
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="border-b border-line text-xs text-ink-muted uppercase">
                <th className="py-2 font-semibold">Name</th>
                <th className="py-2 font-semibold">Target</th>
                <th className="py-2 font-semibold">Type</th>
                <th className="py-2 font-semibold">State</th>
                <th className="py-2 font-semibold">Last Check</th>
                <th className="py-2 font-semibold">Next Check</th>
                <th className="py-2 font-semibold"></th>
              </tr>
            </thead>
            <tbody>
              {monitors.data?.items.map((monitor) => (
                <tr key={monitor.id} className="border-b border-line last:border-0">
                  <td className="py-2 text-ink">{monitor.name}</td>
                  <td className="py-2 tabular text-ink-muted">{monitor.target}</td>
                  <td className="py-2 text-ink-muted">{monitor.monitorType}</td>
                  <td className="py-2"><MonitorStatusBadge status={monitor.currentState} /></td>
                  <td className="tabular py-2 text-ink-muted">{monitor.lastCheckedAt ? new Date(monitor.lastCheckedAt).toLocaleString() : '—'}</td>
                  <td className="tabular py-2 text-ink-muted">{monitor.nextCheckAt ? new Date(monitor.nextCheckAt).toLocaleString() : '—'}</td>
                  <td className="py-2 text-right">
                    <Link to={`/${activeOrganizationId}/monitors/${monitor.id}`} className="text-[13px] text-brand-700 underline">View</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}