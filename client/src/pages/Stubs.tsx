import { Card, EmptyState, PageHeader } from '../components/ui';

export function IncidentsPage() {
  return (
    <>
      <PageHeader title="Incidents" description="All incidents across your monitors." />
      <Card>
        <EmptyState title="No incidents" description="No incidents have been recorded yet." />
      </Card>
    </>
  );
}

export function IncidentDetailPage() {
  return (
    <>
      <div className="page-header">
        <h1>Incident Detail</h1>
      </div>
      <div className="card">
        <p>Incident detail coming soon.</p>
      </div>
    </>
  );
}

export function AlertsPage() {
  return (
    <>
      <div className="page-header">
        <h1>Alert Channels</h1>
      </div>
      <div className="card">
        <p>Alert channels coming soon.</p>
      </div>
    </>
  );
}

export function MaintenancePage() {
  return (
    <>
      <div className="page-header">
        <h1>Maintenance Windows</h1>
      </div>
      <div className="card">
        <p>Maintenance windows coming soon.</p>
      </div>
    </>
  );
}

export function StatusPagesPage() {
  return (
    <>
      <div className="page-header">
        <h1>Status Pages</h1>
      </div>
      <div className="card">
        <p>Status pages coming soon.</p>
      </div>
    </>
  );
}

export function CreateMonitorPage() {
  return (
    <>
      <div className="page-header">
        <h1>Add Monitor</h1>
      </div>
      <div className="card">
        <p>Create monitor form coming soon.</p>
      </div>
    </>
  );
}