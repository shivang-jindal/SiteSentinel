import { Card, EmptyState, PageHeader } from '../components/ui';

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Manage your organization settings." />
      <Card>
        <EmptyState title="Settings" description="Settings page coming soon." />
      </Card>
    </>
  );
}