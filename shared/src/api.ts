/**
 * API contract types (Part A / A7, Part F / F6).
 *
 * Every list endpoint returns `Paginated<T>`; every error returns `ApiError`.
 * Public status-page payloads live in their own namespace so it is obvious in
 * a code review which fields may ever leave the tenant boundary.
 */

import type {
  AlertChannelType,
  AlertDeliveryStatus,
  AlertEventType,
  DomainCheckStatus,
  FailureType,
  IncidentEventType,
  IncidentSeverity,
  IncidentStatus,
  MonitorState,
  MonitorType,
  Role,
} from './constants.js';

export interface Paginated<T> {
  items: T[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export type ApiErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'UNPROCESSABLE'
  | 'RATE_LIMITED'
  | 'INTEGRATION_UNAVAILABLE'
  | 'INTERNAL_ERROR';

export interface ApiFieldIssue {
  path: string;
  message: string;
}

export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;
    fields?: Record<string, string[]>;
    issues?: ApiFieldIssue[];
    requestId: string;
  };
}

/* -------------------------------------------------------------------------- */
/* Session                                                                    */
/* -------------------------------------------------------------------------- */

export interface SessionUser {
  id: string;
  email: string;
  displayName: string | null;
  createdAt: string;
}

export interface MembershipSummary {
  organizationId: string;
  organizationName: string;
  organizationSlug: string;
  baseCurrency: string;
  timezone: string;
  role: Role;
  permissions: string[];
}

export interface AuthSessionResponse {
  user: SessionUser;
  memberships: MembershipSummary[];
  activeOrganizationId: string | null;
}

/* -------------------------------------------------------------------------- */
/* Monitors                                                                   */
/* -------------------------------------------------------------------------- */

export interface MonitorSummary {
  id: string;
  name: string;
  monitorType: MonitorType;
  target: string;
  enabled: boolean;
  currentState: MonitorState;
  /** `true` when the last check is missing or older than the stale window. */
  stale: boolean;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  lastCheckedAt: string | null;
  nextCheckAt: string | null;
  lastLatencyMs: number | null;
  uptimePercent: number | null;
  checksRecorded: number;
  expectedChecks: number;
  coverage: number | null;
  averageLatencyMs: number | null;
  openIncidentCount: number;
  tags: string[];
  intervalSeconds: number;
  timeoutMs: number;
  createdAt: string;
  archivedAt: string | null;
}

export interface MonitorDetail extends MonitorSummary {
  expectedStatusCodes: number[];
  keywordMatch: string | null;
  consecutiveFailureThreshold: number;
  recoverySuccessThreshold: number;
  alertChannelCount: number;
  onStatusPage: boolean;
  lastCheck: MonitorCheck | null;
  lastSsl: SslCertificateReport | null;
  domainCheck: DomainCheckReport | null;
}

export interface MonitorCheck {
  id: string;
  checkedAt: string;
  finishedAt: string | null;
  result: 'success' | 'failure';
  failureType: FailureType | null;
  statusCode: number | null;
  latencyMs: number | null;
  dnsMs: number | null;
  responseSizeBytes: number | null;
  safeMessage: string | null;
  probeLocation: string;
  probeVersion: string;
}

export interface MonitorListQuery {
  page: number;
  pageSize: number;
  q?: string;
  state?: MonitorState | 'all';
  type?: MonitorType | 'all';
  tag?: string;
  sort?: 'name' | 'last_checked_at' | 'latency' | 'created_at';
  order?: 'asc' | 'desc';
}

/* -------------------------------------------------------------------------- */
/* Uptime                                                                     */
/* -------------------------------------------------------------------------- */

export interface UptimePoint {
  /** Bucket start, ISO-8601 UTC. */
  at: string;
  totalChecks: number;
  successfulChecks: number;
  /** `null` when no checks were recorded - never a fake 0%. */
  uptimePercent: number | null;
  averageLatencyMs: number | null;
}

export interface UptimeReport {
  from: string;
  to: string;
  intervalSeconds: number;
  /** Checks the monitor should have run in the window. */
  expectedChecks: number;
  totalChecks: number;
  successfulChecks: number;
  failedChecks: number;
  /** `null` when no checks were recorded. */
  uptimePercent: number | null;
  coverage: number | null;
  averageLatencyMs: number | null;
  p95LatencyMs: number | null;
  method: string;
  points: UptimePoint[];
  statusCodeDistribution: Array<{ statusCode: number | null; count: number }>;
  failureBreakdown: Array<{ failureType: FailureType; count: number }>;
}

export interface ResponseCodeSlice {
  statusCode: number;
  count: number;
}

/* -------------------------------------------------------------------------- */
/* SSL and domain checks                                                      */
/* -------------------------------------------------------------------------- */

export interface SslCertificateReport {
  host: string;
  checkedAt: string;
  /** `false` when the probe could not complete - never "expired". */
  available: boolean;
  expiresAt: string | null;
  daysRemaining: number | null;
  issuer: string | null;
  subject: string | null;
  serialNumber: string | null;
  protocol: string | null;
  chainValid: boolean | null;
  chainError: string | null;
  selfSigned: boolean | null;
  /** Highest lead time that has been crossed, e.g. 30/14/7/3/1. */
  warningLevelDays: number | null;
  safeMessage: string;
}

export interface DomainCheckReport {
  host: string;
  checkedAt: string;
  status: DomainCheckStatus;
  /** Always `null` in this build - no RDAP/WHOIS source is configured. */
  expiresAt: string | null;
  source: string | null;
  safeMessage: string;
}

/* -------------------------------------------------------------------------- */
/* Incidents                                                                  */
/* -------------------------------------------------------------------------- */

export interface IncidentListItem {
  id: string;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  startedAt: string;
  acknowledgedAt: string | null;
  resolvedAt: string | null;
  durationSeconds: number | null;
  monitorCount: number;
  monitors: Array<{ id: string; name: string; publicLabel: string | null }>;
  maintenance: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentEvent {
  id: string;
  eventType: IncidentEventType;
  message: string;
  actorUserId: string | null;
  actorName: string | null;
  createdAt: string;
  metadata: Record<string, unknown> | null;
}

export interface IncidentDetail extends IncidentListItem {
  resolutionReason: string | null;
  affectedMonitors: Array<{
    id: string;
    name: string;
    monitorType: MonitorType;
    target: string;
    firstFailedCheckId: string | null;
    recoveryCheckId: string | null;
  }>;
  events: IncidentEvent[];
  alerts: Array<{
    id: string;
    channelId: string;
    channelName: string;
    channelType: AlertChannelType;
    eventType: AlertEventType;
    status: AlertDeliveryStatus;
    attempts: number;
    sentAt: string | null;
    failureCode: string | null;
  }>;
}

/* -------------------------------------------------------------------------- */
/* Alert channels                                                             */
/* -------------------------------------------------------------------------- */

export interface AlertChannelSummary {
  id: string;
  channelType: AlertChannelType;
  name: string;
  enabled: boolean;
  recipients: string[];
  /** Webhook only. Never the plaintext secret. */
  webhookUrl: string | null;
  /** Masked, e.g. `************abcd`. */
  webhookSecretMasked: string | null;
  secretRotatedAt: string | null;
  lastTestedAt: string | null;
  lastTestStatus: 'never_tested' | 'ok' | 'failed' | 'not_configured';
  lastErrorCode: string | null;
  ruleCount: number;
  createdAt: string;
}

export interface AlertRuleSummary {
  id: string;
  monitorId: string | null;
  monitorName: string | null;
  eventType: AlertEventType;
  channelId: string;
  channelName: string;
  enabled: boolean;
  repeatMinutes: number | null;
  quietHours: { start: string; end: string; timezone: string } | null;
}

/* -------------------------------------------------------------------------- */
/* Maintenance                                                                */
/* -------------------------------------------------------------------------- */

export interface MaintenanceWindowSummary {
  id: string;
  name: string;
  startsAt: string;
  endsAt: string;
  timezone: string;
  recurrence: {
    kind: 'none' | 'daily' | 'weekly' | 'monthly';
    weekdays?: number[];
    timeOfDay?: string;
    durationMinutes?: number;
  } | null;
  reason: string | null;
  enabled: boolean;
  suppressNotifications: boolean;
  monitorIds: string[];
  monitorNames: string[];
  /** `true` right now, after timezone expansion. */
  activeNow: boolean;
  nextOccurrenceAt: string | null;
  createdAt: string;
}

/* -------------------------------------------------------------------------- */
/* Status pages                                                               */
/* -------------------------------------------------------------------------- */

export interface StatusPageSummary {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  published: boolean;
  logoUrl: string | null;
  customDomain: string | null;
  customDomainVerified: boolean;
  monitors: Array<{ id: string; monitorId: string; name: string; publicLabel: string; sortOrder: number }>;
  publicUrl: string;
  createdAt: string;
  updatedAt: string;
}

/* -------------------------------------------------------------------------- */
/* Dashboard                                                                  */
/* -------------------------------------------------------------------------- */

export interface PlatformWarning {
  level: 'info' | 'warning' | 'critical';
  code: string;
  message: string;
}

export interface DashboardSummary {
  from: string;
  to: string;
  rangeLabel: string;
  method: string;
  monitorCount: number;
  stateCounts: Record<MonitorState, number>;
  staleMonitorCount: number;
  openIncidentCount: number;
  incidentsLast24h: number;
  averageLatencyMs: number | null;
  organizationUptimePercent: number | null;
  expectedChecks: number;
  totalChecks: number;
  coverage: number | null;
  slowestMonitors: Array<{ id: string; name: string; averageLatencyMs: number; checks: number }>;
  recentIncidents: IncidentListItem[];
  activeMaintenance: Array<{ id: string; name: string; endsAt: string; monitorCount: number }>;
  expiringCertificates: Array<{ id: string; name: string; expiresAt: string | null; daysRemaining: number | null }>;
  warnings: PlatformWarning[];
  email: { provider: string; deliversMessages: boolean; setupHint: string };
  probe: { intervalBucketSeconds: number; dispatchJobId: string | null };
}

/* -------------------------------------------------------------------------- */
/* Public status page (unauthenticated)                                        */
/* -------------------------------------------------------------------------- */

/**
 * Exactly what a public visitor may see. Internal identifiers, targets,
 * timings, monitor ids and internal notes never appear here.
 */
export interface PublicStatusPage {
  title: string;
  description: string | null;
  logoUrl: string | null;
  generatedAt: string;
  /** `operational` | `degraded` | `partial_outage` | `major_outage` | `unknown`. */
  overallStatus: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'unknown';
  components: Array<{
    label: string;
    status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'unknown';
    checkedAt: string | null;
  }>;
  /** Uptime per component over the published window, or `null` when unknown. */
  uptime: Array<{ label: string; uptimePercent: number | null; windowDays: number; checks: number }>;
  incidents: Array<{
    id: string;
    title: string;
    status: IncidentStatus;
    severity: IncidentSeverity;
    startedAt: string;
    resolvedAt: string | null;
  }>;
  windowDays: number;
  method: string;
}
