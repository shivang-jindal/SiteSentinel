/**
 * Zod schemas shared between the browser and the API (Part A / A4.7).
 *
 * The server always re-validates with these schemas; the client uses them for
 * inline validation. Nothing sent by the browser is trusted.
 */

import { z } from 'zod';

import {
  ALERT_CHANNEL_TYPES,
  ALERT_EVENT_TYPES,
  ALLOWED_HTTP_PORTS,
  ALLOWED_TCP_PORTS,
  DEFAULT_INTERVAL_SECONDS,
  DEFAULT_MAX_ALERT_CHANNELS,
  DEFAULT_MAX_MAINTENANCE_WINDOWS,
  DEFAULT_MAX_MONITORS,
  DEFAULT_MAX_STATUS_PAGES,
  DEFAULT_PAGE_SIZE,
  DEFAULT_RETENTION_DAYS,
  DEFAULT_TIMEOUT_MS,
  IMPLEMENTED_MONITOR_TYPES,
  INCIDENT_SEVERITIES,
  MAX_INTERVAL_SECONDS,
  MAX_KEYWORD_LENGTH,
  MAX_PAGE_SIZE,
  MAX_RESPONSE_BYTES,
  MAX_TAGS,
  MAX_TIMEOUT_MS,
  MIN_INTERVAL_SECONDS,
  MIN_TIMEOUT_MS,
  MONITOR_STATES,
  MONITOR_TYPES,
  RECURRENCE_KINDS,
  ROLES,
} from './constants.js';
import { checkHostnameTarget, checkHttpTarget, checkTcpTarget } from './ssrf.js';

/* -------------------------------------------------------------------------- */
/* Primitives                                                                 */
/* -------------------------------------------------------------------------- */

const uuid = z.string().uuid();
const isoTimestamp = z
  .string()
  .datetime({ offset: true })
  .or(z.string().datetime())
  .or(z.string().refine((value) => !Number.isNaN(Date.parse(value)), 'Expected an ISO-8601 timestamp'));
const clockTime = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'Use HH:MM');

export const idSchema = uuid;
export const emailSchema = z.string().trim().toLowerCase().email('Enter a valid email address');
export const passwordSchema = z
  .string()
  .min(10, 'Use at least 10 characters')
  .max(200, 'Password is too long');

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE),
});

/* -------------------------------------------------------------------------- */
/* Auth                                                                       */
/* -------------------------------------------------------------------------- */

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  displayName: z.string().trim().min(1, 'Enter your name').max(120),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Enter your password').max(200),
});

export const forgotPasswordSchema = z.object({ email: emailSchema });

export const resetPasswordSchema = z.object({
  token: z.string().min(20).max(400),
  password: passwordSchema,
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Enter your current password'),
  newPassword: passwordSchema,
});

export const updateProfileSchema = z.object({
  displayName: z.string().trim().min(1).max(120).optional(),
});

/* -------------------------------------------------------------------------- */
/* Organizations and settings                                                 */
/* -------------------------------------------------------------------------- */

const countryCode = z
  .string()
  .trim()
  .toUpperCase()
  .length(2, 'Use a 2-letter country code');

const currency = z.string().trim().toUpperCase().regex(/^[A-Z]{3}$/, 'Expected a 3-letter currency code');

export const createOrganizationSchema = z.object({
  name: z.string().trim().min(2, 'Enter an organization name').max(120),
  countryCode,
  timezone: z.string().trim().min(1).max(64),
  baseCurrency: currency,
});

export const updateOrganizationSchema = z
  .object({
    name: z.string().trim().min(2).max(120).optional(),
    countryCode: countryCode.optional(),
    timezone: z.string().trim().min(1).max(64).optional(),
    logoUrl: z.string().url().max(500).nullable().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'Provide at least one field to update',
  });

export const createInvitationSchema = z.object({
  email: emailSchema,
  role: z.enum(ROLES).refine((role) => role !== 'owner', {
    message: 'Ownership is transferred separately',
  }),
});

export const changeMemberRoleSchema = z.object({ role: z.enum(ROLES) });

export const acceptInvitationSchema = z.object({ token: z.string().min(20).max(400) });

export const transferOwnershipSchema = z.object({
  membershipId: uuid,
  confirmation: z.literal('TRANSFER OWNERSHIP'),
});

export const updateMonitoringSettingsSchema = z
  .object({
    defaultIntervalSeconds: z.number().int().min(MIN_INTERVAL_SECONDS).max(MAX_INTERVAL_SECONDS).optional(),
    minIntervalSeconds: z.number().int().min(MIN_INTERVAL_SECONDS).max(MAX_INTERVAL_SECONDS).optional(),
    defaultTimeoutMs: z.number().int().min(MIN_TIMEOUT_MS).max(MAX_TIMEOUT_MS).optional(),
    consecutiveFailureThreshold: z.number().int().min(1).max(10).optional(),
    recoverySuccessThreshold: z.number().int().min(1).max(10).optional(),
    retentionDays: z.number().int().min(1).max(365).optional(),
    maxMonitors: z.number().int().min(1).max(500).optional(),
    probeLocationLabel: z.string().trim().min(1).max(64).optional(),
    alertOnStaleChecks: z.boolean().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'Provide at least one field to update' });

export const monitoringSettingsDefaults = {
  defaultIntervalSeconds: DEFAULT_INTERVAL_SECONDS,
  minIntervalSeconds: MIN_INTERVAL_SECONDS,
  defaultTimeoutMs: DEFAULT_TIMEOUT_MS,
  consecutiveFailureThreshold: 2,
  recoverySuccessThreshold: 2,
  retentionDays: DEFAULT_RETENTION_DAYS,
  maxMonitors: DEFAULT_MAX_MONITORS,
  maxAlertChannels: DEFAULT_MAX_ALERT_CHANNELS,
  maxStatusPages: DEFAULT_MAX_STATUS_PAGES,
  maxMaintenanceWindows: DEFAULT_MAX_MAINTENANCE_WINDOWS,
  maxResponseBytes: MAX_RESPONSE_BYTES,
  probeLocationLabel: 'default-region',
  alertOnStaleChecks: true,
} as const;

/* -------------------------------------------------------------------------- */
/* Monitors                                                                   */
/* -------------------------------------------------------------------------- */

const tags = z
  .array(z.string().trim().min(1).max(32))
  .max(MAX_TAGS, `Use at most ${MAX_TAGS} tags`)
  .default([]);

const expectedStatusCodes = z
  .array(z.number().int().min(100).max(599))
  .min(1, 'Expect at least one status code')
  .max(20)
  .default([200]);

const baseMonitorFields = {
  name: z.string().trim().min(1, 'Give the monitor a name').max(120),
  intervalSeconds: z
    .number()
    .int()
    .min(MIN_INTERVAL_SECONDS, `The shortest interval is ${MIN_INTERVAL_SECONDS} seconds`)
    .max(MAX_INTERVAL_SECONDS, 'The longest interval is 24 hours')
    .default(DEFAULT_INTERVAL_SECONDS),
  timeoutMs: z
    .number()
    .int()
    .min(MIN_TIMEOUT_MS, 'Use at least 1000 ms')
    .max(MAX_TIMEOUT_MS, 'Use at most 60000 ms')
    .default(DEFAULT_TIMEOUT_MS),
  enabled: z.boolean().default(true),
  tags,
  consecutiveFailureThreshold: z.number().int().min(1).max(10).default(2),
  recoverySuccessThreshold: z.number().int().min(1).max(10).default(2),
};

export const createMonitorSchema = z
  .discriminatedUnion('monitorType', [
    z.object({
      monitorType: z.literal('http'),
      target: z.string().trim().min(1, 'Enter a URL').max(500),
      expectedStatusCodes,
      keywordMatch: z.null().optional(),
    }),
    z.object({
      monitorType: z.literal('http_keyword'),
      target: z.string().trim().min(1, 'Enter a URL').max(500),
      expectedStatusCodes,
      keywordMatch: z
        .string()
        .trim()
        .min(1, 'Enter the keyword the page must contain')
        .max(MAX_KEYWORD_LENGTH),
    }),
    z.object({
      monitorType: z.literal('tcp'),
      target: z.string().trim().min(1, 'Enter host:port').max(300),
      expectedStatusCodes: z.null().optional(),
      keywordMatch: z.null().optional(),
    }),
    z.object({
      monitorType: z.literal('ssl_certificate'),
      target: z.string().trim().min(1, 'Enter a hostname').max(253),
      expectedStatusCodes: z.null().optional(),
      keywordMatch: z.null().optional(),
    }),
    z.object({
      monitorType: z.literal('domain_expiry'),
      target: z.string().trim().min(1, 'Enter a hostname').max(253),
      expectedStatusCodes: z.null().optional(),
      keywordMatch: z.null().optional(),
    }),
  ])
  .and(z.object(baseMonitorFields))
  .superRefine((value, ctx) => {
    const problem = targetProblem(value.monitorType, value.target);
    if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['target'], message: problem });
    if (value.monitorType === 'domain_expiry') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['monitorType'],
        message:
          'Domain expiry monitoring is unavailable: no RDAP or WHOIS data source is configured, so an expiry date could only be guessed.',
      });
    }
  });

export const updateMonitorSchema = z
  .object({
    name: baseMonitorFields.name.optional(),
    intervalSeconds: baseMonitorFields.intervalSeconds.optional(),
    timeoutMs: baseMonitorFields.timeoutMs.optional(),
    enabled: baseMonitorFields.enabled.optional(),
    tags: tags.optional(),
    target: z.string().trim().min(1).max(500).optional(),
    expectedStatusCodes: expectedStatusCodes.optional(),
    keywordMatch: z.string().trim().min(1).max(MAX_KEYWORD_LENGTH).nullable().optional(),
    consecutiveFailureThreshold: baseMonitorFields.consecutiveFailureThreshold.optional(),
    recoverySuccessThreshold: baseMonitorFields.recoverySuccessThreshold.optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'Provide at least one field to update' });

export const monitorListQuerySchema = paginationSchema.extend({
  q: z.string().trim().max(120).optional(),
  state: z.enum(['all', ...MONITOR_STATES]).default('all'),
  type: z.enum(['all', ...MONITOR_TYPES]).default('all'),
  tag: z.string().trim().max(32).optional(),
  sort: z.enum(['name', 'last_checked_at', 'latency', 'created_at']).default('name'),
  order: z.enum(['asc', 'desc']).default('asc'),
});

export const uptimeQuerySchema = z
  .object({
    from: isoTimestamp.optional(),
    to: isoTimestamp.optional(),
    buckets: z.coerce.number().int().min(6).max(200).default(48),
  })
  .refine((value) => !value.from || !value.to || Date.parse(value.from) < Date.parse(value.to), {
    message: 'The start of the range must be before its end',
    path: ['from'],
  });

export const checkListQuerySchema = paginationSchema.extend({
  result: z.enum(['all', 'success', 'failure']).default('all'),
});

export const pauseMonitorSchema = z.object({
  reason: z.string().trim().max(300).optional(),
});

export const bulkPauseSchema = z.object({
  monitorIds: z.array(uuid).min(1, 'Select at least one monitor').max(100),
  enabled: z.boolean(),
  confirmation: z.literal('PAUSE'),
});

/* -------------------------------------------------------------------------- */
/* Incidents                                                                  */
/* -------------------------------------------------------------------------- */

export const incidentListQuerySchema = paginationSchema.extend({
  status: z.enum(['all', 'open', 'acknowledged', 'resolved']).default('all'),
  severity: z.enum(['all', ...INCIDENT_SEVERITIES]).default('all'),
  monitorId: uuid.optional(),
  q: z.string().trim().max(120).optional(),
  from: isoTimestamp.optional(),
  to: isoTimestamp.optional(),
  sort: z.enum(['started_at', 'severity', 'status']).default('started_at'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

export const acknowledgeIncidentSchema = z.object({
  note: z.string().trim().max(1000).optional(),
});

export const incidentNoteSchema = z.object({
  message: z.string().trim().min(1, 'Write a short note').max(2000),
});

export const incidentUpdateSchema = z.object({
  severity: z.enum(INCIDENT_SEVERITIES).optional(),
  status: z.enum(['open', 'acknowledged']).optional(),
  message: z.string().trim().min(1).max(2000).optional(),
});

export const resolveIncidentSchema = z.object({
  reason: z.string().trim().min(3, 'Give a resolution reason').max(1000),
});

/* -------------------------------------------------------------------------- */
/* Alert channels                                                             */
/* -------------------------------------------------------------------------- */

export const createAlertChannelSchema = z
  .object({
    channelType: z.enum(ALERT_CHANNEL_TYPES),
    name: z.string().trim().min(1, 'Name the channel').max(80),
    enabled: z.boolean().default(true),
    recipients: z.array(emailSchema).max(50).default([]),
    webhookUrl: z.string().trim().max(500).nullable().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.channelType === 'email' && value.recipients.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['recipients'], message: 'Add at least one recipient' });
    }
    if (value.channelType === 'webhook') {
      if (!value.webhookUrl) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['webhookUrl'], message: 'Enter the webhook URL' });
      } else {
        const parsed = checkHttpTarget(value.webhookUrl, [80, 443, 8080, 8443]);
        if (!parsed.ok) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['webhookUrl'],
            message: `Webhook URL rejected: ${parsed.reason}`,
          });
        }
      }
      if (value.recipients.length > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['recipients'],
          message: 'A webhook channel does not use email recipients',
        });
      }
    }
  });

export const updateAlertChannelSchema = z
  .object({
    name: z.string().trim().min(1).max(80).optional(),
    enabled: z.boolean().optional(),
    recipients: z.array(emailSchema).max(50).optional(),
    webhookUrl: z.string().trim().max(500).nullable().optional(),
    rotateSecret: z.boolean().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'Provide at least one field to update' });

export const alertRuleSchema = z.object({
  monitorId: uuid.nullable().default(null),
  eventType: z.enum(ALERT_EVENT_TYPES),
  channelId: uuid,
  enabled: z.boolean().default(true),
  repeatMinutes: z.number().int().min(1).max(10_080).nullable().default(null),
  quietHours: z
    .object({
      start: clockTime,
      end: clockTime,
      timezone: z.string().trim().min(1).max(64),
    })
    .nullable()
    .default(null),
});

export const testAlertChannelSchema = z
  .object({
    note: z.string().trim().max(300).optional(),
  })
  .default({});

/* -------------------------------------------------------------------------- */
/* Maintenance windows                                                        */
/* -------------------------------------------------------------------------- */

export const recurrenceSchema = z
  .object({
    kind: z.enum(RECURRENCE_KINDS),
    weekdays: z.array(z.number().int().min(1).max(7)).max(7).optional(),
    timeOfDay: clockTime.optional(),
    durationMinutes: z.number().int().min(1).max(10_080).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.kind === 'none') return;
    if (value.kind === 'weekly' && (!value.weekdays || value.weekdays.length === 0)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['weekdays'], message: 'Choose at least one weekday' });
    }
    if (!value.durationMinutes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['durationMinutes'],
        message: 'Set how long each occurrence lasts',
      });
    }
  });

export const createMaintenanceWindowSchema = z
  .object({
    name: z.string().trim().min(1, 'Name the window').max(120),
    startsAt: isoTimestamp,
    endsAt: isoTimestamp,
    timezone: z.string().trim().min(1).max(64),
    recurrence: recurrenceSchema.nullable().default(null),
    reason: z.string().trim().max(1000).nullable().default(null),
    enabled: z.boolean().default(true),
    suppressNotifications: z.boolean().default(true),
    monitorIds: z.array(uuid).min(1, 'Select at least one monitor').max(200),
  })
  .superRefine((value, ctx) => {
    const start = Date.parse(value.startsAt);
    const end = Date.parse(value.endsAt);
    if (Number.isNaN(start) || Number.isNaN(end)) return;
    if (value.recurrence && value.recurrence.kind !== 'none') return;
    if (end <= start) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['endsAt'], message: 'The window must end after it starts' });
    }
  });

export const updateMaintenanceWindowSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    startsAt: isoTimestamp.optional(),
    endsAt: isoTimestamp.optional(),
    timezone: z.string().trim().min(1).max(64).optional(),
    recurrence: recurrenceSchema.nullable().optional(),
    reason: z.string().trim().max(1000).nullable().optional(),
    enabled: z.boolean().optional(),
    suppressNotifications: z.boolean().optional(),
    monitorIds: z.array(uuid).min(1).max(200).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'Provide at least one field to update' });

export const maintenanceListQuerySchema = z.object({
  includeInactive: z.coerce.boolean().default(true),
});

/* -------------------------------------------------------------------------- */
/* Status pages                                                               */
/* -------------------------------------------------------------------------- */

export const statusPageMonitorSchema = z.object({
  monitorId: uuid,
  /** Optional safe label shown publicly instead of the monitor name. */
  publicLabel: z.string().trim().max(80).nullable().default(null),
  sortOrder: z.number().int().min(0).max(999).default(0),
});

export const createStatusPageSchema = z.object({
  title: z.string().trim().min(2, 'Give the page a title').max(120),
  description: z.string().trim().max(500).nullable().default(null),
  logoUrl: z.string().url().max(500).nullable().default(null),
  published: z.boolean().default(false),
  customDomain: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/, 'Enter a hostname such as status.example.com')
    .max(253)
    .nullable()
    .default(null),
  monitors: z.array(statusPageMonitorSchema).min(1, 'Select at least one monitor').max(50),
});

export const updateStatusPageSchema = z
  .object({
    title: z.string().trim().min(2).max(120).optional(),
    description: z.string().trim().max(500).nullable().optional(),
    logoUrl: z.string().url().max(500).nullable().optional(),
    published: z.boolean().optional(),
    customDomain: z.string().trim().toLowerCase().max(253).nullable().optional(),
    monitors: z.array(statusPageMonitorSchema).min(1).max(50).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'Provide at least one field to update' });

export const publicStatusQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).default(90),
});

/* -------------------------------------------------------------------------- */
/* Dashboard                                                                  */
/* -------------------------------------------------------------------------- */

export const dashboardQuerySchema = z
  .object({
    from: isoTimestamp.optional(),
    to: isoTimestamp.optional(),
    hours: z.coerce.number().int().min(1).max(24 * 90).optional(),
  })
  .refine((value) => !value.from || !value.to || Date.parse(value.from) < Date.parse(value.to), {
    message: 'The start of the range must be before its end',
    path: ['from'],
  });

/* -------------------------------------------------------------------------- */
/* Exports                                                                    */
/* -------------------------------------------------------------------------- */

export const createExportSchema = z.object({
  dataset: z.enum(['monitors', 'checks', 'incidents', 'alert_deliveries']),
  monitorId: uuid.optional(),
  from: isoTimestamp.optional(),
  to: isoTimestamp.optional(),
});

/* -------------------------------------------------------------------------- */
/* Shared target validation (used by both the API and the browser)            */
/* -------------------------------------------------------------------------- */

export function targetProblem(monitorType: (typeof MONITOR_TYPES)[number], target: string): string | null {
  if (!IMPLEMENTED_MONITOR_TYPES.includes(monitorType)) {
    return 'This monitor type is not available in this build.';
  }
  const value = target.trim();
  if (value === '') return 'Enter a target.';

  if (monitorType === 'http' || monitorType === 'http_keyword') {
    const result = checkHttpTarget(value, ALLOWED_HTTP_PORTS);
    return result.ok ? null : result.reason;
  }
  if (monitorType === 'tcp') {
    const result = checkTcpTarget(value, ALLOWED_TCP_PORTS);
    return result.ok ? null : result.reason;
  }
  const result = checkHostnameTarget(value);
  return result.ok ? null : result.reason;
}

export const schemaCatalog = {
  register: registerSchema,
  login: loginSchema,
  createOrganization: createOrganizationSchema,
  createMonitor: createMonitorSchema,
  updateMonitor: updateMonitorSchema,
  createAlertChannel: createAlertChannelSchema,
  createMaintenanceWindow: createMaintenanceWindowSchema,
  createStatusPage: createStatusPageSchema,
};
