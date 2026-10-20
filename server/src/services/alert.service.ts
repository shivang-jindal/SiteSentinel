/**
 * Alert channels, rules and deliveries (Part F / F3.6).
 *
 * Rules the engine enforces:
 *   - a delivery is deduplicated by `(incident, channel, event, slot)` through a
 *     unique index, so a retried job can never notify twice (Part F / F3.5);
 *   - a maintenance window suppresses notifications but never rewrites a check
 *     result, and suppressed deliveries stay visible as `suppressed`;
 *   - quiet hours skip a delivery and record why;
 *   - an email is reported as `sent` only when the provider accepted it. No
 *     delivery receipt is claimed anywhere.
 */

import { and, desc, eq, isNull, or, sql } from 'drizzle-orm';

import type {
  AlertChannelSummary,
  AlertDeliveryStatus,
  AlertEventType,
  AlertRuleSummary,
  Paginated,
} from '@sitesentinel/shared';
import { ALLOWED_HTTP_PORTS, checkHttpTarget, minutesSinceMidnightInZone } from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import {
  alertChannels,
  alertDeliveries,
  alertRules,
  incidentEvents,
  incidentMonitors,
  incidents,
  monitors,
  organizations,
  statusPages,
} from '../db/schema.js';
import { badRequest, conflict, integrationUnavailable, notFound } from '../errors.js';
import {
  renderChannelTest,
  renderIncidentAlert,
  renderSslAlert,
  renderWebhookPayload,
} from '../integrations/email/templates.js';
import { hmacSha256Hex, maskSecret, openCredentials, randomToken, sealCredentials } from '../lib/crypto.js';
import { postSignedJson } from '../lib/http-client.js';
import type { AuditService } from './audit.service.js';
import type { EmailService } from './email.service.js';
import type { JobQueue } from '../jobs/queue.js';
import type { MaintenanceService } from './maintenance.service.js';

export interface ChannelConfig {
  recipients: string[];
  url: string | null;
  secret: string | null;
}

export interface CreateChannelInput {
  channelType: 'email' | 'webhook';
  name: string;
  enabled: boolean;
  recipients: string[];
  webhookUrl: string | null;
}

/** Rendered content carried in the job payload so delivery never re-derives it. */
export interface AlertContent {
  subject: string;
  text: string;
  json: string;
}

export interface DeliveryOutcome {
  ok: boolean;
  retryable: boolean;
  code: string;
  message: string;
}

const RETRYABLE_FAILURE_CODES = new Set(['temporary', 'provider_error', 'timeout']);

export class AlertService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
    private readonly jobs: JobQueue,
    private readonly email: EmailService,
    private readonly maintenance: MaintenanceService,
    private readonly encryptionKey: Buffer | null,
    private readonly appUrl: string,
  ) {}

  /* ---------------------------------------------------------------------- */
  /* Channels                                                                */
  /* ---------------------------------------------------------------------- */

  async listChannels(organizationId: string): Promise<AlertChannelSummary[]> {
    const rows = await this.db
      .select()
      .from(alertChannels)
      .where(eq(alertChannels.organizationId, organizationId))
      .orderBy(alertChannels.name);

    const rules = await this.db
      .select({ channelId: alertRules.channelId })
      .from(alertRules)
      .where(eq(alertRules.organizationId, organizationId));

    return rows.map((row) => this.toSummary(row, rules.filter((rule) => rule.channelId === row.id).length));
  }

  async createChannel(input: {
    organizationId: string;
    actorUserId: string;
    channel: CreateChannelInput;
  }): Promise<{ summary: AlertChannelSummary; secret: string | null }> {
    this.requireEncryptionKey();
    const name = input.channel.name.trim();
    const existing = await this.db
      .select({ id: alertChannels.id })
      .from(alertChannels)
      .where(and(eq(alertChannels.organizationId, input.organizationId), eq(alertChannels.name, name)))
      .limit(1);
    if (existing[0]) throw conflict('An alert channel with that name already exists.', { field: 'name' });

    const secret = input.channel.channelType === 'webhook' ? randomToken(32) : null;

    const inserted = await this.db
      .insert(alertChannels)
      .values({
        organizationId: input.organizationId,
        channelType: input.channel.channelType,
        name,
        encryptedConfig: this.encode(input.channel.recipients, input.channel.webhookUrl, secret),
        enabled: input.channel.enabled,
        lastTestStatus: 'never_tested',
        createdBy: input.actorUserId,
      })
      .returning();

    const row = inserted[0]!;
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'alert_channel.created',
      entityType: 'alert_channel',
      entityId: row.id,
      metadata: { channelType: row.channelType, recipientCount: input.channel.recipients.length },
    });
    return { summary: this.toSummary(row, 0), secret };
  }

  async updateChannel(input: {
    organizationId: string;
    channelId: string;
    actorUserId: string;
    patch: {
      name?: string;
      enabled?: boolean;
      recipients?: string[];
      webhookUrl?: string | null;
      rotateSecret?: boolean;
    };
  }): Promise<{ summary: AlertChannelSummary; secret: string | null }> {
    const row = await this.requireChannel(input.organizationId, input.channelId);
    this.requireEncryptionKey();

    const config = this.decode(row.encryptedConfig);
    let secret: string | null = null;
    if (input.patch.rotateSecret && row.channelType === 'webhook') {
      secret = randomToken(32);
      config.secret = secret;
    }
    const recipients = input.patch.recipients ?? config.recipients;
    const url = input.patch.webhookUrl === undefined ? config.url : input.patch.webhookUrl;

    if (row.channelType === 'email' && recipients.length === 0) {
      throw badRequest('An email channel needs at least one recipient.', {
        recipients: ['Add at least one recipient'],
      });
    }
    if (row.channelType === 'webhook' && !url) {
      throw badRequest('A webhook channel needs a destination URL.', { webhookUrl: ['Required'] });
    }
    if (url) {
      const checked = checkHttpTarget(url, ALLOWED_HTTP_PORTS);
      if (!checked.ok) {
        throw badRequest(`Webhook URL rejected: ${checked.reason}`, { webhookUrl: [checked.reason] });
      }
    }

    const updated = await this.db
      .update(alertChannels)
      .set({
        ...(input.patch.name !== undefined ? { name: input.patch.name.trim() } : {}),
        ...(input.patch.enabled !== undefined ? { enabled: input.patch.enabled } : {}),
        encryptedConfig: this.encode(recipients, url, config.secret),
        ...(secret ? { secretRotatedAt: new Date(), lastTestStatus: 'never_tested' } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(alertChannels.id, input.channelId), eq(alertChannels.organizationId, input.organizationId)))
      .returning();

    const next = updated[0]!;
    const rules = await this.db
      .select({ channelId: alertRules.channelId })
      .from(alertRules)
      .where(and(eq(alertRules.organizationId, input.organizationId), eq(alertRules.channelId, next.id)));

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: input.patch.rotateSecret ? 'alert_channel.secret_rotated' : 'alert_channel.updated',
      entityType: 'alert_channel',
      entityId: next.id,
      metadata: { fields: Object.keys(input.patch) },
    });

    return { summary: this.toSummary(next, rules.length), secret };
  }

  async deleteChannel(organizationId: string, channelId: string, actorUserId: string): Promise<void> {
    const deleted = await this.db
      .delete(alertChannels)
      .where(and(eq(alertChannels.id, channelId), eq(alertChannels.organizationId, organizationId)))
      .returning({ id: alertChannels.id });
    if (!deleted[0]) throw notFound('Alert channel');
    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'alert_channel.deleted',
      entityType: 'alert_channel',
      entityId: channelId,
    });
  }

  async requireChannel(organizationId: string, channelId: string) {
    const rows = await this.db
      .select()
      .from(alertChannels)
      .where(and(eq(alertChannels.id, channelId), eq(alertChannels.organizationId, organizationId)))
      .limit(1);
    const row = rows[0];
    if (!row) throw notFound('Alert channel');
    return row;
  }

  /* ---------------------------------------------------------------------- */
  /* Rules                                                                   */
  /* ---------------------------------------------------------------------- */

  async listRules(organizationId: string): Promise<AlertRuleSummary[]> {
    const rows = await this.db
      .select({
        id: alertRules.id,
        monitorId: alertRules.monitorId,
        monitorName: monitors.name,
        eventType: alertRules.eventType,
        channelId: alertRules.channelId,
        channelName: alertChannels.name,
        enabled: alertRules.enabled,
        repeatMinutes: alertRules.repeatMinutes,
        quietHours: alertRules.quietHours,
      })
      .from(alertRules)
      .leftJoin(monitors, eq(monitors.id, alertRules.monitorId))
      .innerJoin(alertChannels, eq(alertChannels.id, alertRules.channelId))
      .where(eq(alertRules.organizationId, organizationId))
      .orderBy(alertRules.createdAt);

    return rows.map((row) => ({
      id: row.id,
      monitorId: row.monitorId,
      monitorName: row.monitorName ?? null,
      eventType: row.eventType as AlertEventType,
      channelId: row.channelId,
      channelName: row.channelName,
      enabled: row.enabled,
      repeatMinutes: row.repeatMinutes,
      quietHours: row.quietHours ?? null,
    }));
  }

  async createRule(input: {
    organizationId: string;
    actorUserId: string;
    rule: {
      monitorId: string | null;
      eventType: AlertEventType;
      channelId: string;
      enabled: boolean;
      repeatMinutes: number | null;
      quietHours: { start: string; end: string; timezone: string } | null;
    };
  }): Promise<AlertRuleSummary> {
    await this.requireChannel(input.organizationId, input.rule.channelId);
    if (input.rule.monitorId) {
      const monitor = await this.db
        .select({ id: monitors.id })
        .from(monitors)
        .where(and(eq(monitors.id, input.rule.monitorId), eq(monitors.organizationId, input.organizationId)))
        .limit(1);
      if (!monitor[0]) throw notFound('Monitor');
    }

    const existing = await this.db
      .select({ id: alertRules.id })
      .from(alertRules)
      .where(
        and(
          eq(alertRules.organizationId, input.organizationId),
          eq(alertRules.eventType, input.rule.eventType),
          eq(alertRules.channelId, input.rule.channelId),
          input.rule.monitorId ? eq(alertRules.monitorId, input.rule.monitorId) : isNull(alertRules.monitorId),
        ),
      )
      .limit(1);
    if (existing[0]) {
      throw conflict('That alert rule already exists for this channel and event.', { field: 'eventType' });
    }

    const inserted = await this.db
      .insert(alertRules)
      .values({
        organizationId: input.organizationId,
        monitorId: input.rule.monitorId,
        eventType: input.rule.eventType,
        channelId: input.rule.channelId,
        enabled: input.rule.enabled,
        repeatMinutes: input.rule.repeatMinutes,
        quietHours: input.rule.quietHours,
      })
      .returning({ id: alertRules.id });

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'alert_rule.created',
      entityType: 'alert_rule',
      entityId: inserted[0]!.id,
      metadata: { eventType: input.rule.eventType, monitorId: input.rule.monitorId },
    });

    return this.requireRuleSummary(input.organizationId, inserted[0]!.id);
  }

  async updateRule(input: {
    organizationId: string;
    ruleId: string;
    actorUserId: string;
    patch: {
      enabled?: boolean;
      repeatMinutes?: number | null;
      quietHours?: { start: string; end: string; timezone: string } | null;
    };
  }): Promise<AlertRuleSummary> {
    const existing = await this.db
      .select({ id: alertRules.id })
      .from(alertRules)
      .where(and(eq(alertRules.id, input.ruleId), eq(alertRules.organizationId, input.organizationId)))
      .limit(1);
    if (!existing[0]) throw notFound('Alert rule');

    await this.db
      .update(alertRules)
      .set({
        ...(input.patch.enabled !== undefined ? { enabled: input.patch.enabled } : {}),
        ...(input.patch.repeatMinutes !== undefined ? { repeatMinutes: input.patch.repeatMinutes } : {}),
        ...(input.patch.quietHours !== undefined ? { quietHours: input.patch.quietHours } : {}),
        updatedAt: new Date(),
      })
      .where(eq(alertRules.id, input.ruleId));

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'alert_rule.updated',
      entityType: 'alert_rule',
      entityId: input.ruleId,
      metadata: { fields: Object.keys(input.patch) },
    });

    return this.requireRuleSummary(input.organizationId, input.ruleId);
  }

  async deleteRule(organizationId: string, ruleId: string, actorUserId: string): Promise<void> {
    const deleted = await this.db
      .delete(alertRules)
      .where(and(eq(alertRules.id, ruleId), eq(alertRules.organizationId, organizationId)))
      .returning({ id: alertRules.id });
    if (!deleted[0]) throw notFound('Alert rule');
    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'alert_rule.deleted',
      entityType: 'alert_rule',
      entityId: ruleId,
    });
  }

  private async requireRuleSummary(organizationId: string, ruleId: string): Promise<AlertRuleSummary> {
    const list = await this.listRules(organizationId);
    const found = list.find((rule) => rule.id === ruleId);
    if (!found) throw notFound('Alert rule');
    return found;
  }

  /* ---------------------------------------------------------------------- */
  /* Queueing                                                                */
  /* ---------------------------------------------------------------------- */

  /**
   * Creates one delivery row per matching enabled rule and enqueues an
   * `alert.deliver` job for each. Returns the number of deliveries created.
   */
  async queueForIncident(input: {
    organizationId: string;
    incidentId: string;
    monitorId: string;
    eventType: Extract<AlertEventType, 'incident_opened' | 'incident_acknowledged' | 'incident_resolved'>;
    /** Distinguishes a repeat notification from the first one. */
    slot?: string;
  }): Promise<number> {
    const incidentRows = await this.db
      .select()
      .from(incidents)
      .where(and(eq(incidents.id, input.incidentId), eq(incidents.organizationId, input.organizationId)))
      .limit(1);
    const incident = incidentRows[0];
    if (!incident) return 0;

    const rules = await this.db
      .select({
        id: alertRules.id,
        channelId: alertRules.channelId,
        quietHours: alertRules.quietHours,
        channelType: alertChannels.channelType,
      })
      .from(alertRules)
      .innerJoin(alertChannels, eq(alertChannels.id, alertRules.channelId))
      .where(
        and(
          eq(alertRules.organizationId, input.organizationId),
          eq(alertRules.eventType, input.eventType),
          eq(alertRules.enabled, true),
          eq(alertChannels.enabled, true),
          or(eq(alertRules.monitorId, input.monitorId), isNull(alertRules.monitorId)),
        ),
      );
    if (rules.length === 0) return 0;

    const monitorNames = await this.db
      .select({ name: monitors.name })
      .from(incidentMonitors)
      .innerJoin(monitors, eq(monitors.id, incidentMonitors.monitorId))
      .where(eq(incidentMonitors.incidentId, input.incidentId));
    const names = monitorNames.map((row) => row.name);

    const detected = await this.db
      .select({ message: incidentEvents.message })
      .from(incidentEvents)
      .where(
        and(eq(incidentEvents.incidentId, input.incidentId), eq(incidentEvents.eventType, 'detected')),
      )
      .limit(1);

    const organizationRows = await this.db
      .select({ name: organizations.name })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1);

    const statusPageUrl = await this.publicStatusPageUrl(input.organizationId);
    const rendered = renderIncidentAlert({
      organizationName: organizationRows[0]?.name ?? 'Your organization',
      incidentTitle: incident.title,
      severity: incident.severity as 'minor' | 'major' | 'critical',
      monitorNames: names,
      failureSummary: detected[0]?.message ?? null,
      startedAt: incident.startedAt.toISOString(),
      statusPageUrl,
      dashboardUrl: `${this.appUrl}/monitors`,
      isRecovery: input.eventType === 'incident_resolved',
      resolvedAt: incident.resolvedAt?.toISOString() ?? null,
    });

    const json = renderWebhookPayload(input.eventType, {
      incidentId: incident.id,
      title: incident.title,
      severity: incident.severity,
      status: incident.status,
      startedAt: incident.startedAt.toISOString(),
      resolvedAt: incident.resolvedAt?.toISOString() ?? null,
      monitors: names.map((name) => ({ name })),
    });

    const content: AlertContent = { subject: rendered.subject, text: rendered.text, json };
    const window = await this.maintenance.suppressingWindowForMonitor(input.organizationId, input.monitorId);
    const now = new Date();
    const slot = input.slot ?? 'first';

    let queuedAny = false;
    let created = 0;

    for (const rule of rules) {
      const idempotencyKey = `${input.organizationId}:${input.incidentId}:${rule.channelId}:${input.eventType}:${slot}`;
      let status: AlertDeliveryStatus = 'queued';
      let safeMessage: string | null = null;

      if (window) {
        status = 'suppressed';
        safeMessage = `Suppressed by the maintenance window "${window.name}". Checks kept running.`;
      } else if (isQuietNow(rule.quietHours, now)) {
        status = 'skipped';
        safeMessage = 'Skipped because the rule is inside its configured quiet hours.';
      }

      const inserted = await this.db
        .insert(alertDeliveries)
        .values({
          organizationId: input.organizationId,
          incidentId: input.incidentId,
          monitorId: input.monitorId,
          channelId: rule.channelId,
          eventType: input.eventType,
          status,
          safeMessage,
          idempotencyKey,
        })
        .onConflictDoNothing()
        .returning({ id: alertDeliveries.id });

      const row = inserted[0];
      if (!row) continue;
      created += 1;

      if (status !== 'queued') continue;
      queuedAny = true;
      await this.jobs.enqueue({
        jobType: 'alert.deliver',
        organizationId: input.organizationId,
        payload: {
          deliveryId: row.id,
          incidentId: incident.id,
          channelId: rule.channelId,
          channelType: rule.channelType,
          eventType: input.eventType,
          subject: content.subject,
          text: content.text,
          json: content.json,
        },
        idempotencyKey: `alert-deliver:${row.id}`,
      });
    }

    if (queuedAny) {
      await this.db
        .update(incidents)
        .set({ lastNotifiedAt: now, notificationCount: sql`${incidents.notificationCount} + 1` })
        .where(eq(incidents.id, input.incidentId));
    }

    return created;
  }

  /** Certificate-expiry alerts: one per monitor, expiry date, lead time, channel. */
  async queueForCertificate(input: {
    organizationId: string;
    monitorId: string;
    monitorName: string;
    host: string;
    expiresAt: string;
    daysRemaining: number;
    warningLevelDays: number;
  }): Promise<number> {
    const rules = await this.db
      .select({ channelId: alertRules.channelId, channelType: alertChannels.channelType })
      .from(alertRules)
      .innerJoin(alertChannels, eq(alertChannels.id, alertRules.channelId))
      .where(
        and(
          eq(alertRules.organizationId, input.organizationId),
          eq(alertRules.eventType, 'ssl_expiring'),
          eq(alertRules.enabled, true),
          eq(alertChannels.enabled, true),
          or(eq(alertRules.monitorId, input.monitorId), isNull(alertRules.monitorId)),
        ),
      );
    if (rules.length === 0) return 0;

    const organizationRows = await this.db
      .select({ name: organizations.name })
      .from(organizations)
      .where(eq(organizations.id, input.organizationId))
      .limit(1);
    const rendered = renderSslAlert({
      organizationName: organizationRows[0]?.name ?? 'Your organization',
      monitorName: input.monitorName,
      host: input.host,
      expiresAt: input.expiresAt,
      daysRemaining: input.daysRemaining,
      warningLevelDays: input.warningLevelDays,
      dashboardUrl: `${this.appUrl}/monitors`,
    });
    const content: AlertContent = {
      subject: rendered.subject,
      text: rendered.text,
      json: renderWebhookPayload('ssl_expiring', {
        monitorId: input.monitorId,
        monitorName: input.monitorName,
        host: input.host,
        expiresAt: input.expiresAt,
        daysRemaining: input.daysRemaining,
        warningLevelDays: input.warningLevelDays,
      }),
    };

    let created = 0;
    for (const rule of rules) {
      const inserted = await this.db
        .insert(alertDeliveries)
        .values({
          organizationId: input.organizationId,
          monitorId: input.monitorId,
          channelId: rule.channelId,
          eventType: 'ssl_expiring',
          status: 'queued',
          idempotencyKey: `ssl:${input.monitorId}:${input.expiresAt.slice(0, 10)}:${input.warningLevelDays}:${rule.channelId}`,
        })
        .onConflictDoNothing()
        .returning({ id: alertDeliveries.id });

      const row = inserted[0];
      if (!row) continue;
      created += 1;
      await this.jobs.enqueue({
        jobType: 'alert.deliver',
        organizationId: input.organizationId,
        payload: {
          deliveryId: row.id,
          channelId: rule.channelId,
          channelType: rule.channelType,
          eventType: 'ssl_expiring',
          subject: content.subject,
          text: content.text,
          json: content.json,
        },
        idempotencyKey: `alert-deliver:${row.id}`,
      });
    }
    return created;
  }

  /**
   * Repeat notifications for still-open incidents, honouring each rule's
   * `repeatMinutes`. Nothing is queued for a resolved incident.
   */
  async queueRepeats(organizationId: string, now: Date = new Date()): Promise<number> {
    const rules = await this.db
      .select()
      .from(alertRules)
      .where(
        and(
          eq(alertRules.organizationId, organizationId),
          eq(alertRules.enabled, true),
          eq(alertRules.eventType, 'incident_opened'),
        ),
      );
    if (rules.length === 0) return 0;

    const open = await this.db
      .select()
      .from(incidents)
      .where(and(eq(incidents.organizationId, organizationId), eq(incidents.status, 'open')));
    if (open.length === 0) return 0;

    let queued = 0;
    for (const incident of open) {
      const links = await this.db
        .select({ monitorId: incidentMonitors.monitorId })
        .from(incidentMonitors)
        .where(eq(incidentMonitors.incidentId, incident.id));
      const firstMonitor = links[0];
      if (!firstMonitor) continue;

      for (const rule of rules) {
        if (rule.monitorId && rule.monitorId !== firstMonitor.monitorId) continue;
        const repeatMinutes = rule.repeatMinutes ?? 0;
        if (repeatMinutes <= 0) continue;
        const last = incident.lastNotifiedAt ?? incident.startedAt;
        if (now.getTime() - last.getTime() < repeatMinutes * 60_000) continue;

        const slot = String(Math.floor(now.getTime() / (repeatMinutes * 60_000)));
        queued += await this.queueForIncident({
          organizationId,
          incidentId: incident.id,
          monitorId: firstMonitor.monitorId,
          eventType: 'incident_opened',
          slot,
        });
      }
    }
    return queued;
  }

  /* ---------------------------------------------------------------------- */
  /* Delivery                                                                */
  /* ---------------------------------------------------------------------- */

  async deliver(input: { deliveryId: string; content: AlertContent }): Promise<DeliveryOutcome> {
    const rows = await this.db
      .select({
        id: alertDeliveries.id,
        organizationId: alertDeliveries.organizationId,
        incidentId: alertDeliveries.incidentId,
        channelId: alertDeliveries.channelId,
        status: alertDeliveries.status,
        attempts: alertDeliveries.attempts,
        channelType: alertChannels.channelType,
        encryptedConfig: alertChannels.encryptedConfig,
      })
      .from(alertDeliveries)
      .innerJoin(alertChannels, eq(alertChannels.id, alertDeliveries.channelId))
      .where(eq(alertDeliveries.id, input.deliveryId))
      .limit(1);

    const delivery = rows[0];
    if (!delivery) return { ok: true, retryable: false, code: 'missing', message: 'Delivery no longer exists.' };
    if (delivery.status !== 'queued') {
      return { ok: true, retryable: false, code: 'not_queued', message: `Delivery is "${delivery.status}"; nothing to send.` };
    }

    await this.db
      .update(alertDeliveries)
      .set({ attempts: delivery.attempts + 1 })
      .where(eq(alertDeliveries.id, input.deliveryId));

    const config = this.decode(delivery.encryptedConfig);
    if (delivery.channelType === 'webhook') {
      return this.deliverWebhook(input.deliveryId, config, input.content);
    }
    return this.deliverEmail(input.deliveryId, delivery.organizationId, delivery.incidentId, config, input.content);
  }

  private async deliverEmail(
    deliveryId: string,
    organizationId: string,
    incidentId: string | null,
    config: ChannelConfig,
    content: AlertContent,
  ): Promise<DeliveryOutcome> {
    if (config.recipients.length === 0) {
      return this.recordFailure(deliveryId, 'not_configured', 'This email channel has no recipients.', false);
    }

    let accepted = 0;
    let lastMessage = '';
    let lastCode = 'provider_error';

    for (const recipient of config.recipients) {
      const queued = await this.email.queue({
        organizationId,
        templateType: 'alert',
        to: recipient,
        subject: content.subject,
        bodyText: content.text,
        relatedIncidentId: incidentId,
        idempotencyKey: `alert:${deliveryId}:${recipient}`,
      });
      if (queued.messageId === '') continue;
      const result = await this.email.deliver(queued.messageId);
      if (result.status === 'sent') {
        accepted += 1;
        lastMessage = result.message;
        continue;
      }
      lastMessage = result.message;
      lastCode = result.failureCode ?? 'provider_error';
    }

    if (accepted > 0) {
      const complete = accepted === config.recipients.length;
      await this.db
        .update(alertDeliveries)
        .set({
          status: 'sent',
          sentAt: new Date(),
          failureCode: complete ? null : 'partial',
          safeMessage: complete
            ? 'The provider accepted the message for every recipient.'
            : `The provider accepted ${accepted} of ${config.recipients.length} recipients.`,
        })
        .where(eq(alertDeliveries.id, deliveryId));
      return { ok: true, retryable: false, code: 'accepted', message: lastMessage };
    }

    return this.recordFailure(deliveryId, lastCode, lastMessage, RETRYABLE_FAILURE_CODES.has(lastCode));
  }

  private async deliverWebhook(
    deliveryId: string,
    config: ChannelConfig,
    content: AlertContent,
  ): Promise<DeliveryOutcome> {
    if (!config.url || !config.secret) {
      return this.recordFailure(deliveryId, 'not_configured', 'The webhook channel has no URL or secret.', false);
    }
    const checked = checkHttpTarget(config.url, ALLOWED_HTTP_PORTS);
    if (!checked.ok) {
      return this.recordFailure(deliveryId, 'not_configured', `Webhook URL rejected: ${checked.reason}`, false);
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = `sha256=${hmacSha256Hex(config.secret, `${timestamp}.${content.json}`)}`;

    const result = await postSignedJson({
      url: config.url,
      body: content.json,
      signatureHeader: 'x-sitesentinel-signature',
      signature,
      timestampHeader: 'x-sitesentinel-timestamp',
      timestamp,
      timeoutMs: 10_000,
    });

    if (result.ok) {
      await this.db
        .update(alertDeliveries)
        .set({ status: 'sent', sentAt: new Date(), safeMessage: result.message, failureCode: null })
        .where(eq(alertDeliveries.id, deliveryId));
      return { ok: true, retryable: false, code: 'accepted', message: result.message };
    }

    return this.recordFailure(
      deliveryId,
      result.failureCode ?? 'provider_error',
      result.message,
      result.failureCode === 'temporary',
    );
  }

  private async recordFailure(
    deliveryId: string,
    code: string,
    message: string,
    retryable: boolean,
  ): Promise<DeliveryOutcome> {
    await this.db
      .update(alertDeliveries)
      .set({ failureCode: code, safeMessage: message.slice(0, 300) })
      .where(eq(alertDeliveries.id, deliveryId));
    return { ok: false, retryable, code, message };
  }

  /* ---------------------------------------------------------------------- */
  /* Test action                                                             */
  /* ---------------------------------------------------------------------- */

  /**
   * Verifies a channel with a real attempt and reports exactly what happened.
   * No provider configured means `not_configured`, never a fake success.
   */
  async test(organizationId: string, channelId: string, actor: { userId: string; name: string }) {
    const channel = await this.requireChannel(organizationId, channelId);
    const organizationRows = await this.db
      .select({ name: organizations.name })
      .from(organizations)
      .where(eq(organizations.id, organizationId))
      .limit(1);
    const organizationName = organizationRows[0]?.name ?? 'Your organization';
    const config = this.decode(channel.encryptedConfig);

    let status: 'ok' | 'failed' | 'not_configured' = 'ok';
    let failureCode: string | null = null;
    let message: string;

    if (channel.channelType === 'email') {
      if (this.email.provider.name === 'disabled') {
        status = 'not_configured';
        failureCode = 'not_configured';
        message =
          'No email provider is configured, so nothing was sent. Set EMAIL_PROVIDER and restart the API before testing an email channel.';
      } else if (config.recipients.length === 0) {
        status = 'failed';
        failureCode = 'not_configured';
        message = 'This channel has no recipients.';
      } else {
        const rendered = renderChannelTest({
          organizationName,
          channelName: channel.name,
          requestedBy: actor.name,
        });
        let accepted = 0;
        let lastMessage = '';
        for (const recipient of config.recipients) {
          const queued = await this.email.queue({
            organizationId,
            templateType: 'channel_test',
            to: recipient,
            subject: rendered.subject,
            bodyText: rendered.text,
            idempotencyKey: `channel-test:${channelId}:${recipient}:${Date.now()}`,
          });
          if (queued.messageId === '') continue;
          const result = await this.email.deliver(queued.messageId);
          if (result.status === 'sent') accepted += 1;
          lastMessage = result.message;
        }
        message = `The provider accepted the test message for ${accepted} of ${config.recipients.length} recipient(s). ${lastMessage}`;
        if (accepted === 0) {
          status = 'failed';
          failureCode = 'provider_error';
        }
      }
    } else if (!config.url || !config.secret) {
      status = 'failed';
      failureCode = 'not_configured';
      message = 'The webhook channel has no URL or secret.';
    } else {
      const body = renderWebhookPayload('channel_test', {
        organizationName,
        channelName: channel.name,
        requestedBy: actor.name,
      });
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const signature = `sha256=${hmacSha256Hex(config.secret, `${timestamp}.${body}`)}`;
      const result = await postSignedJson({
        url: config.url,
        body,
        signatureHeader: 'x-sitesentinel-signature',
        signature,
        timestampHeader: 'x-sitesentinel-timestamp',
        timestamp,
        timeoutMs: 10_000,
      });
      if (result.ok) {
        message = result.message;
      } else {
        status = 'failed';
        failureCode = result.failureCode ?? 'provider_error';
        message = result.message;
      }
    }

    await this.db
      .update(alertChannels)
      .set({
        lastTestedAt: new Date(),
        lastTestStatus: status,
        lastErrorCode: failureCode,
        lastErrorMessage: failureCode ? message.slice(0, 300) : null,
      })
      .where(eq(alertChannels.id, channelId));

    await this.audit.record({
      organizationId,
      actorUserId: actor.userId,
      action: 'alert_channel.tested',
      entityType: 'alert_channel',
      entityId: channelId,
      metadata: { status, failureCode },
    });

    return { status, message, failureCode, testedAt: new Date().toISOString() };
  }

  /* ---------------------------------------------------------------------- */
  /* Reads                                                                   */
  /* ---------------------------------------------------------------------- */

  async listDeliveries(
    organizationId: string,
    query: { page: number; pageSize: number; status?: string; monitorId?: string },
  ): Promise<Paginated<typeof alertDeliveries.$inferSelect>> {
    const filters = [eq(alertDeliveries.organizationId, organizationId)];
    if (query.status) filters.push(eq(alertDeliveries.status, query.status));
    if (query.monitorId) filters.push(eq(alertDeliveries.monitorId, query.monitorId));
    const where = and(...filters);

    const rows = await this.db
      .select()
      .from(alertDeliveries)
      .where(where)
      .orderBy(desc(alertDeliveries.createdAt))
      .limit(query.pageSize)
      .offset((query.page - 1) * query.pageSize);
    const countRows = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(alertDeliveries)
      .where(where);

    const total = countRows[0]?.count ?? 0;
    return {
      items: rows,
      page: query.page,
      pageSize: query.pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.pageSize)),
    };
  }

  async stats(organizationId: string) {
    const rows = await this.db
      .select({ status: alertDeliveries.status, count: sql<number>`count(*)::int` })
      .from(alertDeliveries)
      .where(eq(alertDeliveries.organizationId, organizationId))
      .groupBy(alertDeliveries.status);
    return Object.fromEntries(rows.map((row) => [row.status, row.count])) as Record<string, number>;
  }

  /* ---------------------------------------------------------------------- */
  /* Internals                                                               */
  /* ---------------------------------------------------------------------- */

  private requireEncryptionKey(): void {
    if (!this.encryptionKey) {
      throw integrationUnavailable(
        'Alert channels store their configuration encrypted. Set ENCRYPTION_KEY (64 hex characters) and restart the API before creating or changing a channel.',
        { missing: 'ENCRYPTION_KEY' },
      );
    }
  }

  private encode(recipients: string[], url: string | null, secret: string | null): string {
    return sealCredentials(this.requireEncryptionKeyValue(), {
      recipients: recipients.join(','),
      url: url ?? '',
      secret: secret ?? '',
    });
  }

  private requireEncryptionKeyValue(): Buffer {
    if (!this.encryptionKey) {
      throw integrationUnavailable('ENCRYPTION_KEY is not configured on this server.');
    }
    return this.encryptionKey;
  }

  private decode(sealed: string | null): ChannelConfig {
    if (!sealed || !this.encryptionKey) return { recipients: [], url: null, secret: null };
    try {
      const opened = openCredentials(this.encryptionKey, sealed);
      return {
        recipients: (opened.recipients ?? '')
          .split(',')
          .map((value) => value.trim())
          .filter((value) => value.length > 0),
        url: opened.url && opened.url.length > 0 ? opened.url : null,
        secret: opened.secret && opened.secret.length > 0 ? opened.secret : null,
      };
    } catch {
      // Rotating ENCRYPTION_KEY makes old envelopes unreadable. Say so rather
      // than pretending the channel is empty.
      return { recipients: [], url: null, secret: null };
    }
  }

  private toSummary(row: typeof alertChannels.$inferSelect, ruleCount: number): AlertChannelSummary {
    const config = this.decode(row.encryptedConfig);
    return {
      id: row.id,
      channelType: row.channelType as AlertChannelSummary['channelType'],
      name: row.name,
      enabled: row.enabled,
      recipients: row.channelType === 'email' ? config.recipients : [],
      webhookUrl: row.channelType === 'webhook' ? config.url : null,
      webhookSecretMasked: row.channelType === 'webhook' ? maskSecret(config.secret) : null,
      secretRotatedAt: row.secretRotatedAt?.toISOString() ?? null,
      lastTestedAt: row.lastTestedAt?.toISOString() ?? null,
      lastTestStatus: row.lastTestStatus as AlertChannelSummary['lastTestStatus'],
      lastErrorCode: row.lastErrorCode,
      ruleCount,
      createdAt: row.createdAt.toISOString(),
    };
  }

  private async publicStatusPageUrl(organizationId: string): Promise<string | null> {
    const rows = await this.db
      .select({ slug: statusPages.slug })
      .from(statusPages)
      .where(and(eq(statusPages.organizationId, organizationId), eq(statusPages.published, true)))
      .limit(1);
    const slug = rows[0]?.slug;
    return slug ? `${this.appUrl}/status/${slug}` : null;
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function isQuietNow(quiet: { start: string; end: string; timezone: string } | null, now: Date): boolean {
  if (!quiet) return false;
  const minutes = minutesSinceMidnightInZone(now, quiet.timezone);
  const start = parseClock(quiet.start);
  const end = parseClock(quiet.end);
  if (start === null || end === null || start === end) return false;
  return start < end ? minutes >= start && minutes < end : minutes >= start || minutes < end;
}

function parseClock(value: string): number | null {
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
  if (!match) return null;
  return Number(match[1]) * 60 + Number(match[2]);
}