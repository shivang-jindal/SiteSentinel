/**
 * Maintenance windows (Part F / F3.7).
 *
 * A window suppresses notifications but never rewrites check results and never
 * pauses a monitor by itself (Part F / F7). Recurrence is expanded with the
 * shared timezone helper so a daylight-saving transition shifts the UTC instant
 * while keeping the local time the operator chose.
 */

import { and, asc, eq, inArray } from 'drizzle-orm';

import type { MaintenanceWindowSummary } from '@sitesentinel/shared';
import { maintenanceOccurrences, type MaintenanceOccurrence } from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import { maintenanceMonitors, maintenanceWindows, monitors, type MaintenanceWindow } from '../db/schema.js';
import { badRequest, conflict, notFound } from '../errors.js';
import type { AuditService } from './audit.service.js';

export interface RecurrenceInput {
  kind: 'none' | 'daily' | 'weekly' | 'monthly';
  weekdays?: number[];
  timeOfDay?: string;
  durationMinutes?: number;
}

export interface CreateMaintenanceInput {
  organizationId: string;
  actorUserId: string;
  name: string;
  startsAt: Date;
  endsAt: Date;
  timezone: string;
  recurrence: RecurrenceInput | null;
  reason: string | null;
  enabled: boolean;
  suppressNotifications: boolean;
  monitorIds: string[];
}

export type UpdateMaintenanceInput = Partial<Omit<CreateMaintenanceInput, 'organizationId' | 'actorUserId'>>;

export class MaintenanceService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
  ) {}

  async list(organizationId: string, includeInactive: boolean): Promise<MaintenanceWindowSummary[]> {
    const rows = await this.db
      .select()
      .from(maintenanceWindows)
      .where(eq(maintenanceWindows.organizationId, organizationId))
      .orderBy(asc(maintenanceWindows.startsAt));

    const links = await this.db
      .select({
        windowId: maintenanceMonitors.maintenanceWindowId,
        monitorId: maintenanceMonitors.monitorId,
        name: monitors.name,
      })
      .from(maintenanceMonitors)
      .innerJoin(monitors, eq(monitors.id, maintenanceMonitors.monitorId))
      .where(eq(maintenanceMonitors.organizationId, organizationId));

    const now = new Date();
    return rows
      .filter((row) => includeInactive || row.enabled)
      .map((row) => summarize(row, links.filter((link) => link.windowId === row.id), now));
  }

  async get(organizationId: string, windowId: string): Promise<MaintenanceWindowSummary> {
    const rows = await this.db
      .select()
      .from(maintenanceWindows)
      .where(and(eq(maintenanceWindows.id, windowId), eq(maintenanceWindows.organizationId, organizationId)))
      .limit(1);
    const row = rows[0];
    if (!row) throw notFound('Maintenance window');

    const links = await this.db
      .select({ monitorId: maintenanceMonitors.monitorId, name: monitors.name })
      .from(maintenanceMonitors)
      .innerJoin(monitors, eq(monitors.id, maintenanceMonitors.monitorId))
      .where(eq(maintenanceMonitors.maintenanceWindowId, windowId));

    return summarize(row, links, new Date());
  }

  async create(input: CreateMaintenanceInput): Promise<MaintenanceWindowSummary> {
    const ids = await this.assertMonitors(input.organizationId, input.monitorIds);
    validateWindow(input);

    const created = await this.db.transaction(async (tx) => {
      const inserted = await tx
        .insert(maintenanceWindows)
        .values({
          organizationId: input.organizationId,
          name: input.name.trim(),
          startsAt: input.startsAt,
          endsAt: input.endsAt,
          timezone: input.timezone,
          recurrence: input.recurrence,
          reason: input.reason,
          enabled: input.enabled,
          suppressNotifications: input.suppressNotifications,
          createdBy: input.actorUserId,
        })
        .returning();
      const window = inserted[0]!;
      if (ids.length > 0) {
        await tx.insert(maintenanceMonitors).values(
          ids.map((monitorId) => ({
            organizationId: input.organizationId,
            maintenanceWindowId: window.id,
            monitorId,
          })),
        );
      }
      return window;
    });

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'maintenance_window.created',
      entityType: 'maintenance_window',
      entityId: created.id,
      metadata: { monitorCount: ids.length, recurrence: input.recurrence?.kind ?? 'none' },
    });

    return this.get(input.organizationId, created.id);
  }

  async update(
    organizationId: string,
    windowId: string,
    actorUserId: string,
    patch: UpdateMaintenanceInput,
  ): Promise<MaintenanceWindowSummary> {
    const existing = await this.get(organizationId, windowId);
    const startsAt = patch.startsAt ?? new Date(existing.startsAt);
    const endsAt = patch.endsAt ?? new Date(existing.endsAt);
    const recurrence = patch.recurrence === undefined ? (existing.recurrence ?? null) : patch.recurrence;
    validateWindow({ startsAt, endsAt, recurrence: recurrence as RecurrenceInput | null });

    const ids = patch.monitorIds ? await this.assertMonitors(organizationId, patch.monitorIds) : null;

    await this.db.transaction(async (tx) => {
      await tx
        .update(maintenanceWindows)
        .set({
          ...(patch.name !== undefined ? { name: patch.name.trim() } : {}),
          ...(patch.startsAt !== undefined ? { startsAt: patch.startsAt } : {}),
          ...(patch.endsAt !== undefined ? { endsAt: patch.endsAt } : {}),
          ...(patch.timezone !== undefined ? { timezone: patch.timezone } : {}),
          ...(patch.recurrence !== undefined ? { recurrence: patch.recurrence } : {}),
          ...(patch.reason !== undefined ? { reason: patch.reason } : {}),
          ...(patch.enabled !== undefined ? { enabled: patch.enabled } : {}),
          ...(patch.suppressNotifications !== undefined
            ? { suppressNotifications: patch.suppressNotifications }
            : {}),
        })
        .where(and(eq(maintenanceWindows.id, windowId), eq(maintenanceWindows.organizationId, organizationId)));

      if (ids) {
        await tx.delete(maintenanceMonitors).where(eq(maintenanceMonitors.maintenanceWindowId, windowId));
        if (ids.length > 0) {
          await tx.insert(maintenanceMonitors).values(
            ids.map((monitorId) => ({ organizationId, maintenanceWindowId: windowId, monitorId })),
          );
        }
      }
    });

    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'maintenance_window.updated',
      entityType: 'maintenance_window',
      entityId: windowId,
      metadata: { fields: Object.keys(patch) },
    });

    return this.get(organizationId, windowId);
  }

  async remove(organizationId: string, windowId: string, actorUserId: string): Promise<void> {
    const deleted = await this.db
      .delete(maintenanceWindows)
      .where(and(eq(maintenanceWindows.id, windowId), eq(maintenanceWindows.organizationId, organizationId)))
      .returning({ id: maintenanceWindows.id });
    if (!deleted[0]) throw notFound('Maintenance window');
    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'maintenance_window.deleted',
      entityType: 'maintenance_window',
      entityId: windowId,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* Suppression lookups used by the probe and alert engines                 */
  /* ---------------------------------------------------------------------- */

  /** The active, notification-suppressing window for a monitor, if any. */
  async suppressingWindowForMonitor(
    organizationId: string,
    monitorId: string,
    at: Date = new Date(),
  ): Promise<MaintenanceWindow | null> {
    const rows = await this.db
      .select({ window: maintenanceWindows })
      .from(maintenanceMonitors)
      .innerJoin(
        maintenanceWindows,
        eq(maintenanceWindows.id, maintenanceMonitors.maintenanceWindowId),
      )
      .where(
        and(
          eq(maintenanceMonitors.organizationId, organizationId),
          eq(maintenanceMonitors.monitorId, monitorId),
          eq(maintenanceWindows.enabled, true),
          eq(maintenanceWindows.suppressNotifications, true),
        ),
      );

    for (const row of rows) {
      if (isActiveNow(row.window, at)) return row.window;
    }
    return null;
  }

  /** All windows that are currently active, used by the dashboard. */
  async activeWindows(organizationId: string, at: Date = new Date()) {
    const rows = await this.db
      .select()
      .from(maintenanceWindows)
      .where(and(eq(maintenanceWindows.organizationId, organizationId), eq(maintenanceWindows.enabled, true)))
      .orderBy(asc(maintenanceWindows.startsAt));

    const links = await this.db
      .select({ windowId: maintenanceMonitors.maintenanceWindowId })
      .from(maintenanceMonitors)
      .where(eq(maintenanceMonitors.organizationId, organizationId));

    return rows.filter((row) => isActiveNow(row, at)).map((row) => ({
      id: row.id,
      name: row.name,
      endsAt: row.endsAt.toISOString(),
      monitorCount: links.filter((link) => link.windowId === row.id).length,
    }));
  }

  private async assertMonitors(organizationId: string, monitorIds: string[]): Promise<string[]> {
    const unique = [...new Set(monitorIds)];
    if (unique.length === 0) {
      throw badRequest('Select at least one monitor for the maintenance window.');
    }
    const rows = await this.db
      .select({ id: monitors.id })
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), inArray(monitors.id, unique)));
    if (rows.length !== unique.length) {
      throw conflict('One or more selected monitors do not belong to this organization.');
    }
    return unique;
  }
}

/** Expands a stored window into the occurrence that contains `at`, if any. */
export function isActiveNow(window: MaintenanceWindow, at: Date): boolean {
  return (
    maintenanceOccurrences({
      startsAt: window.startsAt,
      endsAt: window.endsAt,
      timezone: window.timezone,
      recurrence: window.recurrence,
      from: new Date(at.getTime() - 1),
      to: new Date(at.getTime() + 1),
    }).length > 0
  );
}

export function occurrencesBetween(window: MaintenanceWindow, from: Date, to: Date): MaintenanceOccurrence[] {
  return maintenanceOccurrences({
    startsAt: window.startsAt,
    endsAt: window.endsAt,
    timezone: window.timezone,
    recurrence: window.recurrence,
    from,
    to,
  });
}

function summarize(
  row: MaintenanceWindow,
  links: Array<{ monitorId: string; name: string }>,
  now: Date,
): MaintenanceWindowSummary {
  const horizon = new Date(now.getTime() + 400 * 24 * 3_600_000);
  const upcoming = occurrencesBetween(row, now, horizon).filter((o) => o.start.getTime() > now.getTime());
  return {
    id: row.id,
    name: row.name,
    startsAt: row.startsAt.toISOString(),
    endsAt: row.endsAt.toISOString(),
    timezone: row.timezone,
    recurrence: row.recurrence ?? null,
    reason: row.reason,
    enabled: row.enabled,
    suppressNotifications: row.suppressNotifications,
    monitorIds: links.map((link) => link.monitorId),
    monitorNames: links.map((link) => link.name),
    activeNow: isActiveNow(row, now),
    nextOccurrenceAt: upcoming[0] ? upcoming[0].start.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

function validateWindow(input: {
  startsAt: Date;
  endsAt: Date;
  recurrence: RecurrenceInput | null;
}): void {
  if (Number.isNaN(input.startsAt.getTime()) || Number.isNaN(input.endsAt.getTime())) {
    throw badRequest('Enter valid start and end timestamps.');
  }
  if (!input.recurrence || input.recurrence.kind === 'none') {
    if (input.endsAt.getTime() <= input.startsAt.getTime()) {
      throw badRequest('The window must end after it starts.', { endsAt: ['Must be after the start'] });
    }
  }
}