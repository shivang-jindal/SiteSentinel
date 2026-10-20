/**
 * Domain constants shared by the SiteSentinel server and client.
 *
 * Everything in this file is data only: no behaviour that needs a database, a
 * network or the DOM. It is imported by the browser, the API and the worker.
 */

export const PRODUCT_NAME = 'SiteSentinel';

/* -------------------------------------------------------------------------- */
/* Roles and permissions (Part A / A5, Part F / F2)                           */
/* -------------------------------------------------------------------------- */

export const ROLES = ['owner', 'admin', 'member', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Record<Role, string> = {
  owner: 'Owner',
  admin: 'Admin',
  member: 'Member',
  viewer: 'Viewer',
};

/**
 * `owner` and `admin` hold every operating permission; `ownership.transfer`
 * and `organization.delete` stay owner-only. A `member` is an operator:
 * monitors and incidents, but not alert channels or status pages.
 */
export const PERMISSIONS = [
  'monitor.create',
  'monitor.edit',
  'monitor.pause',
  'monitor.delete',
  'incident.manage',
  'alert.manage',
  'maintenance.manage',
  'status_page.manage',
  'report.export',
  'settings.manage',
  'member.manage',
  'audit.view',
  'ownership.transfer',
  'organization.delete',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const VIEWER_PERMISSIONS: Permission[] = [];
const MEMBER_PERMISSIONS: Permission[] = [
  'monitor.create',
  'monitor.edit',
  'monitor.pause',
  'incident.manage',
];
const ADMIN_PERMISSIONS: Permission[] = [
  ...MEMBER_PERMISSIONS,
  'monitor.delete',
  'alert.manage',
  'maintenance.manage',
  'status_page.manage',
  'report.export',
  'settings.manage',
  'member.manage',
  'audit.view',
];

export function permissionsForRole(role: Role): Permission[] {
  switch (role) {
    case 'owner':
      return [...PERMISSIONS];
    case 'admin':
      return [...ADMIN_PERMISSIONS];
    case 'member':
      return [...MEMBER_PERMISSIONS];
    case 'viewer':
      return [...VIEWER_PERMISSIONS];
  }
}

export function roleHasPermission(role: Role, permission: Permission): boolean {
  return permissionsForRole(role).includes(permission);
}

/* -------------------------------------------------------------------------- */
/* Monitors (Part F / F3.3, F4)                                               */
/* -------------------------------------------------------------------------- */

/**
 * `domain_expiry` is declared so the type and the `domain_checks` table exist,
 * but the product refuses to create one until a real RDAP/WHOIS source is
 * configured. Nothing is ever invented for it (Part F / F1, F4).
 */
export const MONITOR_TYPES = [
  'http',
  'http_keyword',
  'tcp',
  'ssl_certificate',
  'domain_expiry',
] as const;
export type MonitorType = (typeof MONITOR_TYPES)[number];

/** Types that actually run in the probe engine today. */
export const IMPLEMENTED_MONITOR_TYPES: readonly MonitorType[] = [
  'http',
  'http_keyword',
  'tcp',
  'ssl_certificate',
];

export const MONITOR_TYPE_LABELS: Record<MonitorType, string> = {
  http: 'HTTP / HTTPS request',
  http_keyword: 'HTTP keyword check',
  tcp: 'TCP port connection',
  ssl_certificate: 'SSL certificate expiry',
  domain_expiry: 'Domain expiry (unavailable)',
};

export const MONITOR_TYPE_DESCRIPTIONS: Record<MonitorType, string> = {
  http: 'A bounded GET request. Success means the response status is one of the expected codes.',
  http_keyword: 'A bounded GET request that must contain a keyword in the first bytes of the body.',
  tcp: 'A TCP connection to one allowlisted port. No data is read and no request is sent.',
  ssl_certificate: 'A real TLS handshake. Reports the expiry date, issuer and chain validation result.',
  domain_expiry:
    'Unavailable. SiteSentinel ships without an RDAP/WHOIS data source and will never guess an expiry date.',
};

/** Safe HTTP ports for a monitor URL. Everything else must be explicit. */
export const ALLOWED_HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888] as const;

/**
 * TCP monitor port allowlist (Part F / F7). A monitor can never become a port
 * scanner: any port outside this list is rejected by the API.
 */
export const ALLOWED_TCP_PORTS = [
  21, 22, 25, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 5432, 6379, 8080, 8443,
  9200, 11211, 27017,
] as const;

export const MIN_INTERVAL_SECONDS = 60;
export const MAX_INTERVAL_SECONDS = 86_400;
export const DEFAULT_INTERVAL_SECONDS = 300;
export const MIN_TIMEOUT_MS = 1_000;
export const MAX_TIMEOUT_MS = 60_000;
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Hard ceiling on how much of a response body is read (never stored). */
export const MAX_RESPONSE_BYTES = 262_144; // 256 KiB
export const MAX_KEYWORD_BODY_BYTES = 131_072; // 128 KiB
export const MAX_REDIRECTS = 5;

export const MAX_KEYWORD_LENGTH = 120;
export const MAX_TAGS = 10;

/** Default per-organization quota (Part F / F7: rate limits + account quotas). */
export const DEFAULT_MAX_MONITORS = 50;
export const DEFAULT_MAX_ALERT_CHANNELS = 20;
export const DEFAULT_MAX_STATUS_PAGES = 5;
export const DEFAULT_MAX_MAINTENANCE_WINDOWS = 50;

/**
 * A check is considered stale (and therefore `unknown`, never healthy) when it
 * is older than this multiple of the monitor interval.
 */
export const STALE_CHECK_INTERVAL_MULTIPLIER = 3;
export const MIN_STALE_AFTER_MS = 120_000;

/* -------------------------------------------------------------------------- */
/* Check results (Part F / F4)                                                */
/* -------------------------------------------------------------------------- */

export const CHECK_RESULTS = ['success', 'failure'] as const;
export type CheckResult = (typeof CHECK_RESULTS)[number];

/**
 * Failure categories are persisted so the UI can distinguish a timeout from a
 * DNS failure from a probe-infrastructure failure (Part F / F3.4).
 */
export const FAILURE_TYPES = [
  'timeout',
  'dns_error',
  'connection_refused',
  'connection_reset',
  'tls_error',
  'unexpected_status',
  'keyword_mismatch',
  'response_too_large',
  'redirect_blocked',
  'too_many_redirects',
  'blocked_address',
  'invalid_target',
  'unsupported_protocol',
  'ssl_certificate_expired',
  'ssl_certificate_expiring',
  'probe_error',
] as const;
export type FailureType = (typeof FAILURE_TYPES)[number];

export const FAILURE_TYPE_LABELS: Record<FailureType, string> = {
  timeout: 'Timed out',
  dns_error: 'DNS lookup failed',
  connection_refused: 'Connection refused',
  connection_reset: 'Connection reset',
  tls_error: 'TLS error',
  unexpected_status: 'Unexpected response status',
  keyword_mismatch: 'Keyword not found',
  response_too_large: 'Response too large',
  redirect_blocked: 'Redirect blocked by the safety policy',
  too_many_redirects: 'Too many redirects',
  blocked_address: 'Blocked address (private, loopback or metadata)',
  invalid_target: 'Invalid target',
  unsupported_protocol: 'Unsupported protocol',
  ssl_certificate_expired: 'Certificate expired',
  ssl_certificate_expiring: 'Certificate expiring',
  probe_error: 'Probe could not run',
};

/**
 * Failures that say nothing about the target being down - the probe itself
 * could not obtain an answer. These never increment the consecutive-failure
 * counter (Part F / F4.11).
 */
export const PROBE_INFRASTRUCTURE_FAILURES: readonly FailureType[] = [
  'probe_error',
  'invalid_target',
  'blocked_address',
  'unsupported_protocol',
  'redirect_blocked',
];

/* -------------------------------------------------------------------------- */
/* Monitor state                                                              */
/* -------------------------------------------------------------------------- */

export const MONITOR_STATES = ['pending', 'up', 'degraded', 'down', 'unknown', 'paused'] as const;
export type MonitorState = (typeof MONITOR_STATES)[number];

export const MONITOR_STATE_LABELS: Record<MonitorState, string> = {
  pending: 'Not checked yet',
  up: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
  unknown: 'Unknown / stale',
  paused: 'Paused',
};

/* -------------------------------------------------------------------------- */
/* Incidents (Part F / F3.5)                                                  */
/* -------------------------------------------------------------------------- */

export const INCIDENT_STATUSES = ['open', 'acknowledged', 'resolved'] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export const INCIDENT_STATUS_LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
};

export const INCIDENT_SEVERITIES = ['minor', 'major', 'critical'] as const;
export type IncidentSeverity = (typeof INCIDENT_SEVERITIES)[number];

export const INCIDENT_EVENT_TYPES = [
  'detected',
  'alert_sent',
  'acknowledged',
  'note',
  'update',
  'resolved',
  'maintenance',
] as const;
export type IncidentEventType = (typeof INCIDENT_EVENT_TYPES)[number];

/* -------------------------------------------------------------------------- */
/* Alerting (Part F / F3.6)                                                   */
/* -------------------------------------------------------------------------- */

export const ALERT_CHANNEL_TYPES = ['email', 'webhook'] as const;
export type AlertChannelType = (typeof ALERT_CHANNEL_TYPES)[number];

export const ALERT_CHANNEL_TYPE_LABELS: Record<AlertChannelType, string> = {
  email: 'Email',
  webhook: 'Signed webhook',
};

export const ALERT_EVENT_TYPES = [
  'incident_opened',
  'incident_acknowledged',
  'incident_resolved',
  'ssl_expiring',
] as const;
export type AlertEventType = (typeof ALERT_EVENT_TYPES)[number];

export const ALERT_EVENT_LABELS: Record<AlertEventType, string> = {
  incident_opened: 'Incident opened',
  incident_acknowledged: 'Incident acknowledged',
  incident_resolved: 'Incident resolved',
  ssl_expiring: 'SSL certificate expiring',
};

export const ALERT_DELIVERY_STATUSES = [
  'queued',
  'sent',
  'failed',
  'suppressed',
  'skipped',
] as const;
export type AlertDeliveryStatus = (typeof ALERT_DELIVERY_STATUSES)[number];

export const ALERT_DELIVERY_STATUS_LABELS: Record<AlertDeliveryStatus, string> = {
  queued: 'Queued',
  sent: 'Accepted by the provider',
  failed: 'Failed',
  suppressed: 'Suppressed (maintenance)',
  skipped: 'Skipped (duplicate or quiet hours)',
};

/** Cert-expiry lead times used by the SSL monitor and the alert rules (Part F / F4). */
export const SSL_WARNING_DAYS = [30, 14, 7, 3, 1] as const;

/* -------------------------------------------------------------------------- */
/* Maintenance windows (Part F / F3.7)                                        */
/* -------------------------------------------------------------------------- */

export const RECURRENCE_KINDS = ['none', 'daily', 'weekly', 'monthly'] as const;
export type RecurrenceKind = (typeof RECURRENCE_KINDS)[number];

export const RECURRENCE_KIND_LABELS: Record<RecurrenceKind, string> = {
  none: 'One-time window',
  daily: 'Repeats every day',
  weekly: 'Repeats every week',
  monthly: 'Repeats every month',
};

/* -------------------------------------------------------------------------- */
/* Domain checks (Part F / F4)                                                */
/* -------------------------------------------------------------------------- */

export const DOMAIN_CHECK_SOURCES = ['rdap', 'whois'] as const;
export type DomainCheckSource = (typeof DOMAIN_CHECK_SOURCES)[number];

export const DOMAIN_CHECK_STATUSES = [
  'ok',
  'expiring',
  'expired',
  'unavailable',
  'error',
] as const;
export type DomainCheckStatus = (typeof DOMAIN_CHECK_STATUSES)[number];

export const DOMAIN_CHECK_STATUS_LABELS: Record<DomainCheckStatus, string> = {
  ok: 'Registered',
  expiring: 'Expiring soon',
  expired: 'Expired',
  unavailable: 'Unavailable - no reliable data source',
  error: 'Lookup failed',
};

/** The one and only reason domain expiry is unavailable in this build. */
export const DOMAIN_CHECK_UNAVAILABLE_REASON =
  'SiteSentinel ships without an RDAP or WHOIS data source. Domain expiry is reported as "Unavailable" instead of being estimated.';

/* -------------------------------------------------------------------------- */
/* Jobs                                                                       */
/* -------------------------------------------------------------------------- */

export const BACKGROUND_JOB_STATUSES = [
  'queued',
  'running',
  'succeeded',
  'failed',
  'cancelled',
] as const;
export type BackgroundJobStatus = (typeof BACKGROUND_JOB_STATUSES)[number];

export const BACKGROUND_JOB_TYPES = [
  'probes.dispatch',
  'alert.deliver',
  'alerts.repeat',
  'maintenance.cleanup',
] as const;
export type BackgroundJobType = (typeof BACKGROUND_JOB_TYPES)[number];

/* -------------------------------------------------------------------------- */
/* API pagination                                                             */
/* -------------------------------------------------------------------------- */

export const MAX_PAGE_SIZE = 100;
export const DEFAULT_PAGE_SIZE = 25;

/** Dashboard / uptime time-range presets, in hours. */
export const TIME_RANGE_OPTIONS = [
  { key: '1h', hours: 1, label: 'Last hour' },
  { key: '24h', hours: 24, label: 'Last 24 hours' },
  { key: '7d', hours: 24 * 7, label: 'Last 7 days' },
  { key: '30d', hours: 24 * 30, label: 'Last 30 days' },
] as const;
export type TimeRangeKey = (typeof TIME_RANGE_OPTIONS)[number]['key'];

/** How much check history is kept by default (Part F / F3.4). */
export const DEFAULT_RETENTION_DAYS = 90;

/* -------------------------------------------------------------------------- */
/* Uptime definition (Part F / F7)                                            */
/* -------------------------------------------------------------------------- */

export const UPTIME_METHOD_LABEL =
  'Uptime is successful checks divided by all recorded checks in the selected window. Missing probes are never counted as success: they lower the data coverage instead. A window with no recorded checks reports "No data yet" rather than 100%.';

export const UPTIME_METHOD_SHORT =
  'successes / recorded checks. Missing probes are excluded from the numerator and reported as coverage.';
