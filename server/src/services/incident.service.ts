/**
 * Incident state machine (Part F / F3.5, F4.6-9, F7).
 *
 * Rules enforced here:
 *   - a monitor opens at most one unresolved incident, enforced by the partial
 *     unique index on `(organization_id, dedupe_key) WHERE status <> 'resolved'`
 *     and re-checked inside the transaction, so two racing workers cannot both
 *     win (Part F / F8);
 *   - recovery requires the configured number of consecutive successful checks,
 *     never a single one (Part F / F3.5);
 *   - maintenance suppresses notifications but never suppresses the incident
 *     itself (Part F / F7).
 */

import { and, desc, eq, gte, inArray, isNull, lte, sql, type SQL } from 'drizzle-orm';

import type {
  IncidentDetail,
  IncidentListItem,
  IncidentSeverity,
  IncidentStatus,
  Paginated,
} from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import {
  alertDeliveries,
  alertChannels,
  incidentEvents,
  incidentMonitors,
  incidents,
  monitors,
  statusPageMonitors,
  users,
} from '../db/schema.js';
import { notFound, unprocessable } from '../errors.js';
import type { AuditService } from './audit.service.js';

const OPEN_STATUSES: IncidentStatus[] = ['open', 'acknowledged'];

export interface IncidentQuery {
  page: number;
  pageSize: number;
  status: 'all' | 'open' | 'acknowledged' | 'resolved';
  severity: 'all' | IncidentSeverity;
  monitorId?: string;
  q?: string;
  from?: string;
  to?: string;
  sort: 'started_at' | 'severity' | 'status';
  order: 'asc' | 'desc';
}

export interface OpenIncidentInput {
  organizationId: string;
  monitorId: string;
  monitorName: string;
  checkId: string | null;
  failureType: string | null;
  safeMessage: string | null;
  maintenanceWindowId: string | null;
}

export class IncidentService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
  ) {}

  /* ---------------------------------------------------------------------- */
  /* State machine                                                          */
  /* ---------------------------------------------------------------------- */

  /**
   * Opens an incident for a monitor, or returns the existing one when the
   * outage is already being tracked. The unique index makes the insert
   * idempotent under concurrency.
   */
  async openForMonitor(input: OpenIncidentInput): Promise<{ incidentId: string; created: boolean }> {
    const dedupeKey = `monitor:${input.monitorId}`;

    return this.db.transaction(async (tx): Promise<{ incidentId: string; created: boolean }> => {
      const inserted = await tx
        .insert(incidents)
        .values({
          organizationId: input.organizationId,
          title: `${input.monitorName} is not responding`,
          severity: 'major',
          status: 'open',
          startedAt: new Date(),
          dedupeKey,
          maintenanceWindowId: input.maintenanceWindowId,
        })
        .onConflictDoNothing()
        .returning({ id: incidents.id });

      const createdRow = inserted[0];
      if (createdRow) {
        await tx
          .insert(incidentMonitors)
          .values({
            organizationId: input.organizationId,
            incidentId: createdRow.id,
            monitorId: input.monitorId,
            firstFailedCheckId: input.checkId,
          })
          .onConflictDoNothing();
        await tx.insert(incidentEvents).values({
          organizationId: input.organizationId,
          incidentId: createdRow.id,
          eventType: 'detected',
          message: input.safeMessage
            ? `Detected after the configured failure threshold. ${input.safeMessage}`
            : 'Detected after the configured failure threshold.',
          metadata: input.failureType ? { failureType: input.failureType } : null,
        });
        return { incidentId: createdRow.id, created: true };
      }

      const existing = await tx
        .select({ id: incidents.id })
        .from(incidents)
        .where(
          and(
            eq(incidents.organizationId, input.organizationId),
            eq(incidents.dedupeKey, dedupeKey),
            inArray(incidents.status, OPEN_STATUSES),
          ),
        )
        .limit(1);
      const row = existing[0];
      if (!row) {
        // The unresolved incident disappeared between the failed insert and
        // this read. Throwing keeps the caller's contract: it will report the
        // outage as not-yet-open rather than silently inventing an id.
        throw unprocessable('The previous incident for this monitor was resolved a moment ago. Re-run the check.');
      }

      await tx
        .update(incidentMonitors)
        .set({ firstFailedCheckId: input.checkId })
        .where(
          and(
            eq(incidentMonitors.incidentId, row.id),
            eq(incidentMonitors.monitorId, input.monitorId),
            isNull(incidentMonitors.firstFailedCheckId),
          ),
        );

      return { incidentId: row.id, created: false };
    });
  }

  /** Resolve the incident attached to a monitor, if there is one. */
  async resolveForMonitor(input: {
    organizationId: string;
    monitorId: string;
    checkId: string | null;
    reason: string;
  }): Promise<{ incidentId: string; resolvedAt: Date } | null> {
    const open = await this.openIncidentForMonitor(input.organizationId, input.monitorId);
    if (!open) return null;

    const resolvedAt = new Date();
    await this.db.transaction(async (tx) => {
      const updated = await tx
        .update(incidents)
        .set({ status: 'resolved', resolvedAt, resolutionReason: input.reason, updatedAt: resolvedAt })
        .where(and(eq(incidents.id, open.id), inArray(incidents.status, OPEN_STATUSES)))
        .returning({ id: incidents.id });

      if (!updated[0]) return;
      await tx
        .update(incidentMonitors)
        .set({ recoveryCheckId: input.checkId })
        .where(and(eq(incidentMonitors.incidentId, open.id), eq(incidentMonitors.monitorId, input.monitorId)));
      await tx.insert(incidentEvents).values({
        organizationId: input.organizationId,
        incidentId: open.id,
        eventType: 'resolved',
        message: input.reason,
      });
    });

    return { incidentId: open.id, resolvedAt };
  }

  async acknowledge(input: {
    organizationId: string;
    incidentId: string;
    actorUserId: string;
    note?: string | null;
  }): Promise<IncidentDetail> {
    await this.requireIncident(input.organizationId, input.incidentId);
    const at = new Date();
    await this.db.transaction(async (tx) => {
      await tx
        .update(incidents)
        .set({ status: 'acknowledged', acknowledgedAt: at, acknowledgedBy: input.actorUserId, updatedAt: at })
        .where(
          and(
            eq(incidents.id, input.incidentId),
            eq(incidents.organizationId, input.organizationId),
            eq(incidents.status, 'open'),
          ),
        );
      await tx.insert(incidentEvents).values({
        organizationId: input.organizationId,
        incidentId: input.incidentId,
        actorUserId: input.actorUserId,
        eventType: 'acknowledged',
        message: input.note?.trim() || 'Incident acknowledged.',
      });
    });
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'incident.acknowledged',
      entityType: 'incident',
      entityId: input.incidentId,
    });
    return this.detail(input.organizationId, input.incidentId);
  }

  async addNote(input: {
    organizationId: string;
    incidentId: string;
    actorUserId: string;
    message: string;
  }): Promise<IncidentDetail> {
    await this.requireIncident(input.organizationId, input.incidentId);
    await this.db.insert(incidentEvents).values({
      organizationId: input.organizationId,
      incidentId: input.incidentId,
      actorUserId: input.actorUserId,
      eventType: 'note',
      message: input.message.trim(),
    });
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'incident.note_added',
      entityType: 'incident',
      entityId: input.incidentId,
    });
    return this.detail(input.organizationId, input.incidentId);
  }

  async update(input: {
    organizationId: string;
    incidentId: string;
    actorUserId: string;
    severity?: IncidentSeverity;
    status?: 'open' | 'acknowledged';
    message?: string;
  }): Promise<IncidentDetail> {
    const existing = await this.requireIncident(input.organizationId, input.incidentId);
    if (existing.status === 'resolved') {
      throw unprocessable('A resolved incident can no longer be edited.');
    }
    const at = new Date();
    await this.db.transaction(async (tx) => {
      await tx
        .update(incidents)
        .set({
          ...(input.severity !== undefined ? { severity: input.severity } : {}),
          ...(input.status !== undefined
            ? {
                status: input.status,
                ...(input.status === 'acknowledged'
                  ? { acknowledgedAt: at, acknowledgedBy: input.actorUserId }
                  : {}),
              }
            : {}),
          updatedAt: at,
        })
        .where(and(eq(incidents.id, input.incidentId), eq(incidents.organizationId, input.organizationId)));

      await tx.insert(incidentEvents).values({
        organizationId: input.organizationId,
        incidentId: input.incidentId,
        actorUserId: input.actorUserId,
        eventType: 'update',
        message:
          input.message?.trim() ??
          `Updated (${[input.severity ? `severity=${input.severity}` : null, input.status ? `status=${input.status}` : null]
            .filter(Boolean)
            .join(', ') || 'no changes'})`,
        metadata: {
          ...(input.severity ? { severity: input.severity } : {}),
          ...(input.status ? { status: input.status } : {}),
        },
      });
    });
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'incident.updated',
      entityType: 'incident',
      entityId: input.incidentId,
      metadata: { fields: Object.keys(input).filter((key) => key !== 'organizationId' && key !== 'incidentId' && key !== 'actorUserId') },
    });
    return this.detail(input.organizationId, input.incidentId);
  }

  async resolve(input: {
    organizationId: string;
    incidentId: string;
    actorUserId: string;
    reason: string;
  }): Promise<IncidentDetail> {
    const existing = await this.requireIncident(input.organizationId, input.incidentId);
    if (existing.status === 'resolved') {
      throw unprocessable('This incident is already resolved.');
    }
    const at = new Date();
    await this.db.transaction(async (tx) => {
      await tx
        .update(incidents)
        .set({ status: 'resolved', resolvedAt: at, resolutionReason: input.reason.trim(), updatedAt: at })
        .where(and(eq(incidents.id, input.incidentId), eq(incidents.organizationId, input.organizationId)));
      await tx.insert(incidentEvents).values({
        organizationId: input.organizationId,
        incidentId: input.incidentId,
        actorUserId: input.actorUserId,
        eventType: 'resolved',
        message: input.reason.trim(),
      });
    });
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'incident.resolved',
      entityType: 'incident',
      entityId: input.incidentId,
      metadata: { reason: input.reason.trim().slice(0, 200) },
    });
    return this.detail(input.organizationId, input.incidentId);
  }

  /* ---------------------------------------------------------------------- */
  /* Reads                                                                   */
  /* ---------------------------------------------------------------------- */

  async openIncidentForMonitor(organizationId: string, monitorId: string) {
    const rows = await this.db
      .select({
        id: incidents.id,
        status: incidents.status,
        startedAt: incidents.startedAt,
        lastNotifiedAt: incidents.lastNotifiedAt,
        notificationCount: incidents.notificationCount,
      })
      .from(incidents)
      .innerJoin(incidentMonitors, eq(incidentMonitors.incidentId, incidents.id))
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          eq(incidentMonitors.monitorId, monitorId),
          inArray(incidents.status, OPEN_STATUSES),
        ),
      )
      .limit(1);
    return rows[0] ?? null;
  }

  async list(organizationId: string, query: IncidentQuery): Promise<Paginated<IncidentListItem>> {
    const filters: SQL[] = [eq(incidents.organizationId, organizationId)];
    if (query.status !== 'all') filters.push(eq(incidents.status, query.status));
    if (query.severity !== 'all') filters.push(eq(incidents.severity, query.severity));
    if (query.from) filters.push(gte(incidents.startedAt, new Date(query.from)));
    if (query.to) filters.push(lte(incidents.startedAt, new Date(query.to)));
    if (query.q) {
      const needle = `%${query.q.toLowerCase()}%`;
      filters.push(sql`lower(${incidents.title}) like ${needle}`);
    }
    if (query.monitorId) {
      const linked = await this.db
        .select({ incidentId: incidentMonitors.incidentId })
        .from(incidentMonitors)
        .where(eq(incidentMonitors.monitorId, query.monitorId));
      const ids = linked.map((row) => row.incidentId);
      filters.push(ids.length > 0 ? inArray(incidents.id, ids) : sql`false`);
    }

    const where = and(...filters);
    const orderColumn =
      query.sort === 'severity'
        ? incidents.severity
        : query.sort === 'status'
          ? incidents.status
          : incidents.startedAt;
    const direction = query.order === 'asc' ? 'asc' : 'desc';

    const rows = await this.db
      .select()
      .from(incidents)
      .where(where)
      .orderBy(sql`${orderColumn} ${sql.raw(direction)}, ${incidents.startedAt} desc`)
      .limit(query.pageSize)
      .offset((query.page - 1) * query.pageSize);

    const countRows = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(incidents)
      .where(where);
    const total = countRows[0]?.count ?? 0;

    const links = rows.length > 0 ? await this.monitorLinks(rows.map((row) => row.id)) : new Map();
    const items = rows.map((row) => this.toListItem(row, links.get(row.id) ?? []));

    return {
      items,
      page: query.page,
      pageSize: query.pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.pageSize)),
    };
  }

  async detail(organizationId: string, incidentId: string): Promise<IncidentDetail> {
    const row = await this.requireIncident(organizationId, incidentId);
    const links = await this.monitorLinks([incidentId]);
    const linkRows = links.get(incidentId) ?? [];

    const events = await this.db
      .select({
        id: incidentEvents.id,
        eventType: incidentEvents.eventType,
        message: incidentEvents.message,
        actorUserId: incidentEvents.actorUserId,
        actorName: users.displayName,
        createdAt: incidentEvents.createdAt,
        metadata: incidentEvents.metadata,
      })
      .from(incidentEvents)
      .leftJoin(users, eq(users.id, incidentEvents.actorUserId))
      .where(eq(incidentEvents.incidentId, incidentId))
      .orderBy(incidentEvents.createdAt);

    const alerts = await this.db
      .select({
        id: alertDeliveries.id,
        channelId: alertDeliveries.channelId,
        channelName: alertChannels.name,
        channelType: alertChannels.channelType,
        eventType: alertDeliveries.eventType,
        status: alertDeliveries.status,
        attempts: alertDeliveries.attempts,
        sentAt: alertDeliveries.sentAt,
        failureCode: alertDeliveries.failureCode,
      })
      .from(alertDeliveries)
      .innerJoin(alertChannels, eq(alertChannels.id, alertDeliveries.channelId))
      .where(eq(alertDeliveries.incidentId, incidentId))
      .orderBy(alertDeliveries.createdAt);

    const affected = linkRows.map((link) => ({
      id: link.monitorId,
      name: link.monitorName,
      monitorType: link.monitorType as IncidentDetail['affectedMonitors'][number]['monitorType'],
      target: link.target,
      firstFailedCheckId: link.firstFailedCheckId,
      recoveryCheckId: link.recoveryCheckId,
    }));

    return {
      ...this.toListItem(row, linkRows),
      resolutionReason: row.resolutionReason,
      affectedMonitors: affected,
      events: events.map((event) => ({
        id: event.id,
        eventType: event.eventType as IncidentDetail['events'][number]['eventType'],
        message: event.message,
        actorUserId: event.actorUserId,
        actorName: event.actorName,
        createdAt: event.createdAt.toISOString(),
        metadata: event.metadata ?? null,
      })),
      alerts: alerts.map((alert) => ({
        ...alert,
        channelType: alert.channelType as IncidentDetail['alerts'][number]['channelType'],
        eventType: alert.eventType as IncidentDetail['alerts'][number]['eventType'],
        status: alert.status as IncidentDetail['alerts'][number]['status'],
        sentAt: alert.sentAt?.toISOString() ?? null,
      })),
    };
  }

  /** Lightweight list used by the dashboard. */
  async recent(organizationId: string, limit = 5): Promise<IncidentListItem[]> {
    const rows = await this.db
      .select()
      .from(incidents)
      .where(eq(incidents.organizationId, organizationId))
      .orderBy(desc(incidents.startedAt))
      .limit(limit);
    const links = rows.length > 0 ? await this.monitorLinks(rows.map((row) => row.id)) : new Map();
    return rows.map((row) => this.toListItem(row, links.get(row.id) ?? []));
  }

  async openCount(organizationId: string): Promise<number> {
    const rows = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(incidents)
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          inArray(incidents.status, OPEN_STATUSES),
        ),
      );
    return rows[0]?.count ?? 0;
  }

  async countSince(organizationId: string, since: Date): Promise<number> {
    const rows = await this.db
      .select({ count: sql<number>`count(*)::int` })
      .from(incidents)
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          gte(incidents.startedAt, since),
          inArray(incidents.status, OPEN_STATUSES),
        ),
      );
    return rows[0]?.count ?? 0;
  }

  async openIncidentsOlderThan(organizationId: string, since: Date) {
    return this.db
      .select()
      .from(incidents)
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          inArray(incidents.status, OPEN_STATUSES),
          gte(incidents.startedAt, since),
        ),
      );
  }

  async requireIncident(organizationId: string, incidentId: string) {
    const rows = await this.db
      .select()
      .from(incidents)
      .where(and(eq(incidents.id, incidentId), eq(incidents.organizationId, organizationId)))
      .limit(1);
    const row = rows[0];
    if (!row) throw notFound('Incident');
    return row;
  }

  /* ---------------------------------------------------------------------- */
  /* Internals                                                               */
  /* ---------------------------------------------------------------------- */

  private async monitorLinks(incidentIds: string[]) {
    const links = await this.db
      .select({
        incidentId: incidentMonitors.incidentId,
        monitorId: monitors.id,
        monitorName: monitors.name,
        monitorType: monitors.monitorType,
        target: monitors.targetUrlOrHost,
        firstFailedCheckId: incidentMonitors.firstFailedCheckId,
        recoveryCheckId: incidentMonitors.recoveryCheckId,
      })
      .from(incidentMonitors)
      .innerJoin(monitors, eq(monitors.id, incidentMonitors.monitorId))
      .where(inArray(incidentMonitors.incidentId, incidentIds));

    const labels = await this.db
      .select({ monitorId: statusPageMonitors.monitorId, publicLabel: statusPageMonitors.publicLabel })
      .from(statusPageMonitors);

    const labelMap = new Map(labels.map((row) => [row.monitorId, row.publicLabel]));

    const map = new Map<
      string,
      Array<{
        monitorId: string;
        monitorName: string;
        monitorType: string;
        target: string;
        firstFailedCheckId: string | null;
        recoveryCheckId: string | null;
        publicLabel: string | null;
      }>
    >();
    for (const link of links) {
      const entry: (typeof links)[number] & { publicLabel: string | null } = {
        ...link,
        publicLabel: labelMap.get(link.monitorId) ?? null,
      };
      const list = map.get(link.incidentId) ?? [];
      list.push(entry);
      map.set(link.incidentId, list);
    }
    return map;
  }

  private toListItem(
    row: typeof incidents.$inferSelect,
    links: Array<{ monitorId: string; monitorName: string; publicLabel: string | null }>,
  ): IncidentListItem {
    return {
      id: row.id,
      title: row.title,
      severity: row.severity as IncidentSeverity,
      status: row.status as IncidentStatus,
      startedAt: row.startedAt.toISOString(),
      acknowledgedAt: row.acknowledgedAt?.toISOString() ?? null,
      resolvedAt: row.resolvedAt?.toISOString() ?? null,
      durationSeconds: row.resolvedAt
        ? Math.max(0, Math.round((row.resolvedAt.getTime() - row.startedAt.getTime()) / 1000))
        : null,
      monitorCount: links.length,
      monitors: links.map((link) => ({
        id: link.monitorId,
        name: link.monitorName,
        publicLabel: link.publicLabel,
      })),
      maintenance: row.maintenanceWindowId !== null,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }
}

/** `true` when an incident status still counts as active. */
export function isOpenStatus(status: string): boolean {
  return status === 'open' || status === 'acknowledged';
}