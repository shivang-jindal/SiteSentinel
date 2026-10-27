import { Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom';

import { AppShell } from './components/AppShell';
import { SessionProvider, useSession } from './lib/session';
import { AcceptInvitationPage } from './pages/AcceptInvitation';
import { CreateOrganizationPage } from './pages/CreateOrganization';
import { DashboardPage } from './pages/Dashboard';
import { LoginPage } from './pages/Login';
import { MonitorsPage } from './pages/Monitors';
import { MonitorDetailPage } from './pages/MonitorDetail';
import { NotFoundPage } from './pages/NotFound';
import { SettingsPage } from './pages/Settings';
import {
  IncidentsPage,
  IncidentDetailPage,
  AlertsPage,
  MaintenancePage,
  StatusPagesPage,
  CreateMonitorPage,
} from './pages/Stubs';

function FullPageLoading() {
  return (
    <div className="flex min-h-screen items-center justify-center" role="status" aria-live="polite">
      <span className="text-sm text-ink-muted">Loading SiteSentinel…</span>
    </div>
  );
}

function RequireSession({ children }: { children: React.ReactNode }) {
  const { user, loading, memberships } = useSession();

  if (loading) return <FullPageLoading />;
  if (!user) return <Navigate to="/login" replace />;
  if (memberships.length === 0) return <Navigate to="/welcome" replace />;
  return <>{children}</>;
}

function RequireOrganization({ children }: { children: React.ReactNode }) {
  const params = useParams();
  const navigate = useNavigate();
  const { memberships, activeOrganizationId, loading } = useSession();
  const organizationId = params.organizationId;

  if (loading) return <FullPageLoading />;
  if (!organizationId) return <Navigate to="/dashboard" replace />;
  if (!memberships.some((membership) => membership.organizationId === organizationId)) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="card w-full max-w-md">
          <div className="px-5 py-5">
            <h2 className="text-lg font-semibold text-ink">Organization not available</h2>
            <p className="mt-2 text-[13px] text-ink-muted">
              You are not a member of this organization, or it no longer exists.
            </p>
            <button
              className="mt-4 btn btn-primary"
              onClick={() => navigate(`/${activeOrganizationId}/dashboard`)}
            >
              Go to my dashboard
            </button>
          </div>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

function RedirectToFirstOrganization() {
  const { memberships, loading } = useSession();
  if (loading) return <FullPageLoading />;
  const first = memberships[0];
  if (!first) return <Navigate to="/welcome" replace />;
  return <Navigate to={`/${first.organizationId}/dashboard`} replace />;
}

function OrganizationLayout() {
  return (
    <AppShell>
      <Routes>
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="monitors" element={<MonitorsPage />} />
        <Route path="monitors/new" element={<CreateMonitorPage />} />
        <Route path="monitors/:monitorId" element={<MonitorDetailPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="maintenance" element={<MaintenancePage />} />
        <Route path="status-pages" element={<StatusPagesPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppShell>
  );
}

export function AppRouter() {
  return (
    <SessionProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<Navigate to="/login" replace />} />
        <Route path="/forgot-password" element={<Navigate to="/login" replace />} />
        <Route path="/reset-password" element={<Navigate to="/login" replace />} />
        <Route path="/accept-invitation" element={<AcceptInvitationPage />} />
        <Route path="/welcome" element={<RequireSession><CreateOrganizationPage /></RequireSession>} />
        <Route path="/dashboard" element={<RequireSession><RedirectToFirstOrganization /></RequireSession>} />
        <Route
          path="/:organizationId/*"
          element={
            <RequireSession>
              <RequireOrganization>
                <OrganizationLayout />
              </RequireOrganization>
            </RequireSession>
          }
        />
        <Route path="/" element={<RequireSession><RedirectToFirstOrganization /></RequireSession>} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </SessionProvider>
  );
}