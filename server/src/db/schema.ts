/**
 * SiteSentinel database schema (Part A / A5, Part F / F5).
 *
 * - UUID primary keys, `timestamptz` UTC timestamps.
 * - Every tenant-owned table carries `organization_id` and is indexed on it.
 * - Page contents are never stored: `monitor_checks` keeps timings, sizes and a
 *   short safe message, nothing else (Part F / F3.3, F7).
 * - `incidents.dedupe_key` is unique per organization, which is what guarantees
 *   "one outage produces one incident" even when several workers race.
 */

import { relations, sql } from 'drizzle-orm';
import {
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

const now = sql`now()`;

/* -------------------------------------------------------------------------- */
/* Shared foundation (Part A / A5)                                            */
/* -------------------------------------------------------------------------- */

export const organizations = pgTable(
  'organizations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    slug: text('slug').notNull(),
    countryCode: text('country_code').notNull().default('US'),
    timezone: text('timezone').notNull().default('UTC'),
    baseCurrency: text('base_currency').notNull().default('USD'),
    logoUrl: text('logo_url'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (table) => [uniqueIndex('organizations_slug_idx').on(table.slug)],
);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').notNull(),
    passwordHash: text('password_hash'),
    displayName: text('display_name').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
    disabledAt: timestamp('disabled_at', { withTimezone: true }),
  },
  (table) => [uniqueIndex('users_email_idx').on(table.email)],
);

export const memberships = pgTable(
  'memberships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull(),
    status: text('status').notNull().default('active'),
    invitedBy: uuid('invited_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('memberships_org_user_idx').on(table.organizationId, table.userId),
    index('memberships_user_idx').on(table.userId),
  ],
);

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** SHA-256 of the opaque session token. The token itself is never stored. */
    tokenHash: text('token_hash').notNull(),
    activeOrganizationId: uuid('active_organization_id').references(() => organizations.id, {
      onDelete: 'set null',
    }),
    userAgent: text('user_agent'),
    ipAddress: text('ip_address'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (table) => [
    uniqueIndex('sessions_token_hash_idx').on(table.tokenHash),
    index('sessions_user_idx').on(table.userId),
  ],
);

export const invitations = pgTable(
  'invitations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    role: text('role').notNull(),
    /** SHA-256 of the single-use invite token. */
    tokenHash: text('token_hash').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    acceptedAt: timestamp('accepted_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    invitedBy: uuid('invited_by')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('invitations_token_hash_idx').on(table.tokenHash),
    index('invitations_org_idx').on(table.organizationId),
  ],
);

export const passwordResetTokens = pgTable(
  'password_reset_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [uniqueIndex('password_reset_token_hash_idx').on(table.tokenHash)],
);

/**
 * Organization-wide monitoring policy. Doubles as the per-tenant quota source
 * and as the place where probe defaults are kept honest (Part F / F7).
 */
export const organizationSettings = pgTable('organization_settings', {
  organizationId: uuid('organization_id')
    .primaryKey()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  defaultIntervalSeconds: integer('default_interval_seconds').notNull().default(300),
  minIntervalSeconds: integer('min_interval_seconds').notNull().default(60),
  defaultTimeoutMs: integer('default_timeout_ms').notNull().default(10_000),
  consecutiveFailureThreshold: integer('consecutive_failure_threshold').notNull().default(2),
  recoverySuccessThreshold: integer('recovery_success_threshold').notNull().default(2),
  retentionDays: integer('retention_days').notNull().default(90),
  maxMonitors: integer('max_monitors').notNull().default(50),
  maxAlertChannels: integer('max_alert_channels').notNull().default(20),
  maxStatusPages: integer('max_status_pages').notNull().default(5),
  maxMaintenanceWindows: integer('max_maintenance_windows').notNull().default(50),
  maxResponseBytes: integer('max_response_bytes').notNull().default(262_144),
  /** Operator-facing label for where the probe worker runs (Part F / F3.9). */
  probeLocationLabel: text('probe_location_label').notNull().default('default-region'),
  /** Emit an `incident_opened` alert when a monitor goes stale. */
  alertOnStaleChecks: boolean('alert_on_stale_checks').notNull().default(true),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
});

export const auditEvents = pgTable(
  'audit_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    actorUserId: uuid('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    action: text('action').notNull(),
    entityType: text('entity_type').notNull(),
    entityId: text('entity_id'),
    /** Redacted metadata only - never credentials or personal data. */
    metadata: jsonb('metadata_json').$type<Record<string, unknown>>(),
    requestId: text('request_id'),
    ipAddress: text('ip_address'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('audit_events_org_created_idx').on(table.organizationId, table.createdAt),
    index('audit_events_entity_idx').on(table.entityType, table.entityId),
  ],
);

export const backgroundJobs = pgTable(
  'background_jobs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id').references(() => organizations.id, {
      onDelete: 'cascade',
    }),
    jobType: text('job_type').notNull(),
    payload: jsonb('payload_json').$type<Record<string, unknown>>().notNull().default({}),
    status: text('status').notNull().default('queued'),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(5),
    runAfter: timestamp('run_after', { withTimezone: true }).notNull().default(now),
    lockedAt: timestamp('locked_at', { withTimezone: true }),
    lockedBy: text('locked_by'),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    lastErrorCode: text('last_error_code'),
    lastErrorMessage: text('last_error_message'),
    idempotencyKey: text('idempotency_key'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('background_jobs_claim_idx').on(table.status, table.runAfter),
    index('background_jobs_org_idx').on(table.organizationId, table.createdAt),
    uniqueIndex('background_jobs_idempotency_idx')
      .on(table.idempotencyKey)
      .where(sql`${table.idempotencyKey} is not null`),
  ],
);

/* -------------------------------------------------------------------------- */
/* Monitors (Part F / F5)                                                     */
/* -------------------------------------------------------------------------- */

export const monitors = pgTable(
  'monitors',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    monitorType: text('monitor_type').notNull(),
    targetUrlOrHost: text('target_url_or_host').notNull(),
    intervalSeconds: integer('interval_seconds').notNull().default(300),
    timeoutMs: integer('timeout_ms').notNull().default(10_000),
    expectedStatusCodes: jsonb('expected_status_codes_json').$type<number[]>().notNull().default([200]),
    keywordMatch: text('keyword_match'),
    enabled: boolean('enabled').notNull().default(true),
    currentState: text('current_state').notNull().default('pending'),
    consecutiveFailures: integer('consecutive_failures').notNull().default(0),
    consecutiveSuccesses: integer('consecutive_successes').notNull().default(0),
    /** Set when the monitor opens an incident or a human acknowledges one. */
    alerting: boolean('alerting').notNull().default(false),
    lastCheckedAt: timestamp('last_checked_at', { withTimezone: true }),
    nextCheckAt: timestamp('next_check_at', { withTimezone: true }),
    lastLatencyMs: integer('last_latency_ms'),
    tags: jsonb('tags_json').$type<string[]>().notNull().default([]),
    /** Per-monitor incident thresholds (override the organization default). */
    consecutiveFailureThreshold: integer('consecutive_failure_threshold').notNull().default(2),
    recoverySuccessThreshold: integer('recovery_success_threshold').notNull().default(2),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
  },
  (table) => [
    index('monitors_org_state_idx').on(table.organizationId, table.currentState),
    index('monitors_enabled_next_check_idx').on(table.enabled, table.nextCheckAt),
    index('monitors_org_name_idx').on(table.organizationId, table.name),
    index('monitors_org_last_checked_idx').on(table.organizationId, table.lastCheckedAt),
  ],
);

export const monitorChecks = pgTable(
  'monitor_checks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id')
      .notNull()
      .references(() => monitors.id, { onDelete: 'cascade' }),
    checkedAt: timestamp('checked_at', { withTimezone: true }).notNull(),
    finishedAt: timestamp('finished_at', { withTimezone: true }),
    result: text('result').notNull(),
    failureType: text('failure_type'),
    statusCode: integer('status_code'),
    latencyMs: integer('latency_ms'),
    dnsMs: integer('dns_ms'),
    tlsExpiryAt: timestamp('tls_expiry_at', { withTimezone: true }),
    /** Certificate summary from a real TLS handshake. Never private key data. */
    tlsIssuer: text('tls_issuer'),
    tlsSubject: text('tls_subject'),
    tlsSerialNumber: text('tls_serial_number'),
    tlsProtocol: text('tls_protocol'),
    tlsChainValid: boolean('tls_chain_valid'),
    tlsChainError: text('tls_chain_error'),
    tlsSelfSigned: boolean('tls_self_signed'),
    responseSizeBytes: integer('response_size_bytes'),
    /**
     * Short operator-facing explanation. Never contains a response body, a
     * request header or a URL credential.
     */
    safeMessage: text('safe_message'),
    probeLocation: text('probe_location').notNull().default('default-region'),
    probeVersion: text('probe_version').notNull().default('1.0.0'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('monitor_checks_monitor_time_idx').on(table.monitorId, table.checkedAt),
    index('monitor_checks_org_time_idx').on(table.organizationId, table.checkedAt),
    index('monitor_checks_result_idx').on(table.monitorId, table.result),
  ],
);

/* -------------------------------------------------------------------------- */
/* Incidents (Part F / F5)                                                    */
/* -------------------------------------------------------------------------- */

export const incidents = pgTable(
  'incidents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    title: text('title').notNull(),
    severity: text('severity').notNull().default('major'),
    status: text('status').notNull().default('open'),
    startedAt: timestamp('started_at', { withTimezone: true }).notNull(),
    acknowledgedAt: timestamp('acknowledged_at', { withTimezone: true }),
    acknowledgedBy: uuid('acknowledged_by').references(() => users.id, { onDelete: 'set null' }),
    resolvedAt: timestamp('resolved_at', { withTimezone: true }),
    resolvedBy: uuid('resolved_by').references(() => users.id, { onDelete: 'set null' }),
    resolutionReason: text('resolution_reason'),
    /**
     * Stable identity of the outage, e.g. `monitor:<id>`. The unique index is
     * the mechanism that stops one outage producing many incidents.
     */
    dedupeKey: text('dedupe_key').notNull(),
    /** Set when the incident started inside a maintenance window. */
    maintenanceWindowId: uuid('maintenance_window_id'),
    lastNotifiedAt: timestamp('last_notified_at', { withTimezone: true }),
    notificationCount: integer('notification_count').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    // Partial unique index: only unresolved incidents reserve a dedupe key, so
    // the same outage can be recorded again after it is resolved.
    uniqueIndex('incidents_dedupe_active_idx')
      .on(table.organizationId, table.dedupeKey)
      .where(sql`${table.status} <> 'resolved'`),
    index('incidents_org_status_start_idx').on(table.organizationId, table.status, table.startedAt),
    index('incidents_org_started_idx').on(table.organizationId, table.startedAt),
  ],
);

export const incidentMonitors = pgTable(
  'incident_monitors',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    incidentId: uuid('incident_id')
      .notNull()
      .references(() => incidents.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id')
      .notNull()
      .references(() => monitors.id, { onDelete: 'cascade' }),
    firstFailedCheckId: uuid('first_failed_check_id'),
    recoveryCheckId: uuid('recovery_check_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('incident_monitors_incident_monitor_idx').on(table.incidentId, table.monitorId),
    index('incident_monitors_monitor_idx').on(table.monitorId),
  ],
);

export const incidentEvents = pgTable(
  'incident_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    incidentId: uuid('incident_id')
      .notNull()
      .references(() => incidents.id, { onDelete: 'cascade' }),
    actorUserId: uuid('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    eventType: text('event_type').notNull(),
    message: text('message').notNull(),
    metadata: jsonb('metadata_redacted_json').$type<Record<string, unknown>>(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [index('incident_events_incident_idx').on(table.incidentId, table.createdAt)],
);

/* -------------------------------------------------------------------------- */
/* Alerting (Part F / F5)                                                     */
/* -------------------------------------------------------------------------- */

export const alertChannels = pgTable(
  'alert_channels',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    channelType: text('channel_type').notNull(),
    name: text('name').notNull(),
    /** AES-256-GCM envelope holding recipients or the webhook secret. */
    encryptedConfig: text('encrypted_config_json'),
    enabled: boolean('enabled').notNull().default(true),
    secretRotatedAt: timestamp('secret_rotated_at', { withTimezone: true }),
    lastTestedAt: timestamp('last_tested_at', { withTimezone: true }),
    lastTestStatus: text('last_test_status').notNull().default('never_tested'),
    lastErrorCode: text('last_error_code'),
    lastErrorMessage: text('last_error_message'),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('alert_channels_org_name_idx').on(table.organizationId, table.name),
    index('alert_channels_org_idx').on(table.organizationId),
  ],
);

export const alertRules = pgTable(
  'alert_rules',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    /** `null` means "every monitor in the organization". */
    monitorId: uuid('monitor_id').references(() => monitors.id, { onDelete: 'cascade' }),
    eventType: text('event_type').notNull(),
    channelId: uuid('channel_id')
      .notNull()
      .references(() => alertChannels.id, { onDelete: 'cascade' }),
    enabled: boolean('enabled').notNull().default(true),
    /** Minimum minutes between repeat notifications for the same incident. */
    repeatMinutes: integer('repeat_minutes'),
    consecutiveFailureThreshold: integer('consecutive_failure_threshold'),
    recoverySuccessThreshold: integer('recovery_success_threshold'),
    quietHours: jsonb('quiet_hours_json').$type<{
      start: string;
      end: string;
      timezone: string;
    } | null>(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('alert_rules_unique_idx').on(
      table.organizationId,
      table.monitorId,
      table.eventType,
      table.channelId,
    ),
    index('alert_rules_org_idx').on(table.organizationId, table.enabled),
  ],
);

export const alertDeliveries = pgTable(
  'alert_deliveries',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    incidentId: uuid('incident_id').references(() => incidents.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id').references(() => monitors.id, { onDelete: 'cascade' }),
    channelId: uuid('channel_id')
      .notNull()
      .references(() => alertChannels.id, { onDelete: 'cascade' }),
    eventType: text('event_type').notNull(),
    status: text('status').notNull().default('queued'),
    /** Exactly what the provider reported; never assumed. */
    providerMessageId: text('provider_message_id'),
    failureCode: text('failure_code'),
    safeMessage: text('safe_message'),
    attempts: integer('attempts').notNull().default(0),
    /** Dedupes (incident, channel, event) so retries never double-notify. */
    idempotencyKey: text('idempotency_key').notNull(),
    sentAt: timestamp('sent_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('alert_deliveries_idempotency_idx').on(table.idempotencyKey),
    index('alert_deliveries_org_created_idx').on(table.organizationId, table.createdAt),
    index('alert_deliveries_incident_idx').on(table.incidentId),
  ],
);

/* -------------------------------------------------------------------------- */
/* Maintenance (Part F / F5)                                                  */
/* -------------------------------------------------------------------------- */

export const maintenanceWindows = pgTable(
  'maintenance_windows',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    startsAt: timestamp('starts_at', { withTimezone: true }).notNull(),
    endsAt: timestamp('ends_at', { withTimezone: true }).notNull(),
    /** IANA timezone used to expand a recurring window. */
    timezone: text('timezone').notNull().default('UTC'),
    recurrence: jsonb('recurrence_rule').$type<{
      kind: 'none' | 'daily' | 'weekly' | 'monthly';
      weekdays?: number[];
      timeOfDay?: string;
      durationMinutes?: number;
    } | null>(),
    reason: text('reason'),
    enabled: boolean('enabled').notNull().default(true),
    /** Suppress notifications while checks keep running (Part F / F7). */
    suppressNotifications: boolean('suppress_notifications').notNull().default(true),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('maintenance_windows_org_enabled_idx').on(table.organizationId, table.enabled),
    index('maintenance_windows_org_starts_idx').on(table.organizationId, table.startsAt),
  ],
);

export const maintenanceMonitors = pgTable(
  'maintenance_monitors',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    maintenanceWindowId: uuid('maintenance_window_id')
      .notNull()
      .references(() => maintenanceWindows.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id')
      .notNull()
      .references(() => monitors.id, { onDelete: 'cascade' }),
  },
  (table) => [
    uniqueIndex('maintenance_monitors_unique_idx').on(table.maintenanceWindowId, table.monitorId),
    index('maintenance_monitors_monitor_idx').on(table.monitorId),
  ],
);

/* -------------------------------------------------------------------------- */
/* Status pages (Part F / F5)                                                 */
/* -------------------------------------------------------------------------- */

export const statusPages = pgTable(
  'status_pages',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    /** 32 characters of CSPRNG entropy: a public URL is not guessable. */
    slug: text('slug').notNull(),
    title: text('title').notNull(),
    description: text('description'),
    published: boolean('published').notNull().default(false),
    logoUrl: text('logo_url'),
    customDomain: text('custom_domain'),
    /** Always false in this build; verification is documented as unimplemented. */
    customDomainVerified: boolean('custom_domain_verified').notNull().default(false),
    /** How many days of uptime and incident history the public page shows. */
    historyDays: integer('history_days').notNull().default(90),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id, { onDelete: 'restrict' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    uniqueIndex('status_pages_slug_idx').on(table.slug),
    index('status_pages_org_idx').on(table.organizationId),
  ],
);

export const statusPageMonitors = pgTable(
  'status_page_monitors',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    statusPageId: uuid('status_page_id')
      .notNull()
      .references(() => statusPages.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id')
      .notNull()
      .references(() => monitors.id, { onDelete: 'cascade' }),
    /** Overrides the monitor name on the public page. */
    publicLabel: text('public_label'),
    sortOrder: integer('sort_order').notNull().default(0),
  },
  (table) => [
    uniqueIndex('status_page_monitors_unique_idx').on(table.statusPageId, table.monitorId),
    index('status_page_monitors_page_idx').on(table.statusPageId, table.sortOrder),
  ],
);

/* -------------------------------------------------------------------------- */
/* Domain checks (Part F / F5)                                                */
/* -------------------------------------------------------------------------- */

export const domainChecks = pgTable(
  'domain_checks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    monitorId: uuid('monitor_id')
      .notNull()
      .references(() => monitors.id, { onDelete: 'cascade' }),
    /** `rdap` or `whois`; `null` in this build because no source is configured. */
    source: text('source'),
    checkedAt: timestamp('checked_at', { withTimezone: true }).notNull().default(now),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    status: text('status').notNull().default('unavailable'),
    safeMessage: text('safe_message').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('domain_checks_monitor_time_idx').on(table.monitorId, table.checkedAt),
    index('domain_checks_org_time_idx').on(table.organizationId, table.checkedAt),
  ],
);

/* -------------------------------------------------------------------------- */
/* Probe leases (Part F / F4.2)                                               */
/* -------------------------------------------------------------------------- */

export const monitorLocks = pgTable(
  'monitor_locks',
  {
    /** Primary key: one active lease row per monitor, enforced by PostgreSQL. */
    monitorId: uuid('monitor_id')
      .primaryKey()
      .references(() => monitors.id, { onDelete: 'cascade' }),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    workerId: text('worker_id').notNull(),
    leaseExpiresAt: timestamp('lease_expires_at', { withTimezone: true }).notNull(),
    acquiredAt: timestamp('acquired_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [index('monitor_locks_lease_idx').on(table.leaseExpiresAt)],
);

/* -------------------------------------------------------------------------- */
/* Email outbox (alert notifications)                                          */
/* -------------------------------------------------------------------------- */

export const emailMessages = pgTable(
  'email_messages',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id').references(() => organizations.id, {
      onDelete: 'cascade',
    }),
    templateType: text('template_type').notNull(),
    toAddress: text('to_address').notNull(),
    fromAddress: text('from_address').notNull(),
    subject: text('subject').notNull(),
    bodyText: text('body_text'),
    status: text('status').notNull().default('queued'),
    providerMessageId: text('provider_message_id'),
    failureCode: text('failure_code'),
    safeFailureMessage: text('safe_failure_message'),
    relatedIncidentId: uuid('related_incident_id').references(() => incidents.id, { onDelete: 'cascade' }),
    idempotencyKey: text('idempotency_key'),
    sentAt: timestamp('sent_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().default(now),
  },
  (table) => [
    index('email_messages_org_status_idx').on(table.organizationId, table.status),
    uniqueIndex('email_messages_idempotency_idx')
      .on(table.idempotencyKey)
      .where(sql`${table.idempotencyKey} is not null`),
  ],
);

/* -------------------------------------------------------------------------- */
/* Relations                                                                  */
/* -------------------------------------------------------------------------- */

export const monitorsRelations = relations(monitors, ({ many, one }) => ({
  organization: one(organizations, {
    fields: [monitors.organizationId],
    references: [organizations.id],
  }),
  checks: many(monitorChecks),
}));

export const monitorChecksRelations = relations(monitorChecks, ({ one }) => ({
  monitor: one(monitors, { fields: [monitorChecks.monitorId], references: [monitors.id] }),
}));

export const incidentsRelations = relations(incidents, ({ many, one }) => ({
  organization: one(organizations, {
    fields: [incidents.organizationId],
    references: [organizations.id],
  }),
  monitors: many(incidentMonitors),
  events: many(incidentEvents),
}));

export const alertChannelsRelations = relations(alertChannels, ({ many }) => ({
  rules: many(alertRules),
  deliveries: many(alertDeliveries),
}));

/* -------------------------------------------------------------------------- */
/* Row types                                                                  */
/* -------------------------------------------------------------------------- */

export type Organization = typeof organizations.$inferSelect;
export type User = typeof users.$inferSelect;
export type Membership = typeof memberships.$inferSelect;
export type OrganizationSettings = typeof organizationSettings.$inferSelect;
export type Monitor = typeof monitors.$inferSelect;
export type MonitorCheck = typeof monitorChecks.$inferSelect;
export type Incident = typeof incidents.$inferSelect;
export type IncidentMonitor = typeof incidentMonitors.$inferSelect;
export type IncidentEvent = typeof incidentEvents.$inferSelect;
export type AlertChannel = typeof alertChannels.$inferSelect;
export type AlertRule = typeof alertRules.$inferSelect;
export type AlertDelivery = typeof alertDeliveries.$inferSelect;
export type MaintenanceWindow = typeof maintenanceWindows.$inferSelect;
export type StatusPage = typeof statusPages.$inferSelect;
export type StatusPageMonitor = typeof statusPageMonitors.$inferSelect;
export type DomainCheck = typeof domainChecks.$inferSelect;
export type MonitorLock = typeof monitorLocks.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
export type BackgroundJob = typeof backgroundJobs.$inferSelect;
export type EmailMessage = typeof emailMessages.$inferSelect;
