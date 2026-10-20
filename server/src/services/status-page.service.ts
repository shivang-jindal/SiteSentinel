/**
 * Public status pages (Part F / F3.8, F6).
 *
 * The public payload is assembled here from an explicit allowlist: only the
 * selected monitors, only their public label (or the monitor name when no
 * label is set), the derived status and the incident history. Targets, monitor
 * ids, timings, latencies and internal notes never leave the tenant boundary.
 *
 * An unpublished page answers 404, exactly like a slug that does not exist, so
 * it cannot be discovered by guessing (Part F / F3.8).
 */

import { and, asc, desc, eq, gte, inArray, sql } from 'drizzle-orm';

import type {
  IncidentSeverity,
  IncidentStatus,
  PublicStatusPage,
  StatusPageSummary,
} from '@sitesentinel/shared';
import { UPTIME_METHOD_SHORT } from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import {
  incidentMonitors,
  incidents,
  monitorChecks,
  monitors,
  statusPageMonitors,
  statusPages,
} from '../db/schema.js';
import { conflict, notFound } from '../errors.js';
import { randomToken } from '../lib/crypto.js';
import type { AuditService } from './audit.service.js';

export type ComponentStatus = PublicStatusPage['overallStatus'];

export interface StatusPageMonitorInput {
  monitorId: string;
  publicLabel: string | null;
  sortOrder: number;
}

export interface CreateStatusPageInput {
  title: string;
  description: string | null;
  logoUrl: string | null;
  published: boolean;
  customDomain: string | null;
  monitors: StatusPageMonitorInput[];
}

export type UpdateStatusPageInput = Partial<Omit<CreateStatusPageInput, 'customDomain'>>;

export class StatusPageService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
    private readonly appUrl: string,
  ) {}

  async list(organizationId: string): Promise<StatusPageSummary[]> {
    const rows = await this.db
      .select()
      .from(statusPages)
      .where(eq(statusPages.organizationId, organizationId))
      .orderBy(asc(statusPages.createdAt));
    if (rows.length === 0) return [];
    const links = await this.links(rows.map((row) => row.id));
    return rows.map((row) => this.toSummary(row, links.get(row.id) ?? []));
  }

  async get(organizationId: string, pageId: string): Promise<StatusPageSummary> {
    const rows = await this.db
      .select()
      .from(statusPages)
      .where(and(eq(statusPages.id, pageId), eq(statusPages.organizationId, organizationId)))
      .limit(1);
    const row = rows[0];
    if (!row) throw notFound('Status page');
    const links = await this.links([row.id]);
    return this.toSummary(row, links.get(row.id) ?? []);
  }

  async create(input: {
    organizationId: string;
    actorUserId: string;
    page: CreateStatusPageInput;
    maxStatusPages: number;
  }): Promise<StatusPageSummary> {
    const existing = await this.db
      .select({ total: sql<number>`count(*)::int` })
      .from(statusPages)
      .where(eq(statusPages.organizationId, input.organizationId));
    if ((existing[0]?.total ?? 0) >= input.maxStatusPages) {
      throw conflict(
        `This organization already has its configured limit of ${input.maxStatusPages} status page(s).`,
        { limit: input.maxStatusPages },
      );
    }
    await this.assertMonitors(input.organizationId, input.page.monitors);

    // 32 characters of CSPRNG entropy: a published URL is not guessable.
    const slug = randomToken(24);

    const created = await this.db.transaction(async (tx) => {
      const inserted = await tx
        .insert(statusPages)
        .values({
          organizationId: input.organizationId,
          slug,
          title: input.page.title.trim(),
          description: input.page.description,
          logoUrl: input.page.logoUrl,
          published: input.page.published,
          customDomain: input.page.customDomain,
          customDomainVerified: false,
          createdBy: input.actorUserId,
        })
        .returning();
      const page = inserted[0]!;
      await tx.insert(statusPageMonitors).values(
        input.page.monitors.map((monitor) => ({
          organizationId: input.organizationId,
          statusPageId: page.id,
          monitorId: monitor.monitorId,
          publicLabel: monitor.publicLabel,
          sortOrder: monitor.sortOrder,
        })),
      );
      return page;
    });

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'status_page.created',
      entityType: 'status_page',
      entityId: created.id,
      metadata: { published: created.published, monitorCount: input.page.monitors.length },
    });

    return this.get(input.organizationId, created.id);
  }

  async update(input: {
    organizationId: string;
    pageId: string;
    actorUserId: string;
    patch: UpdateStatusPageInput;
  }): Promise<StatusPageSummary> {
    await this.get(input.organizationId, input.pageId);
    if (input.patch.monitors) {
      await this.assertMonitors(input.organizationId, input.patch.monitors);
    }

    await this.db.transaction(async (tx) => {
      await tx
        .update(statusPages)
        .set({
          ...(input.patch.title !== undefined ? { title: input.patch.title.trim() } : {}),
          ...(input.patch.description !== undefined ? { description: input.patch.description } : {}),
          ...(input.patch.logoUrl !== undefined ? { logoUrl: input.patch.logoUrl } : {}),
          ...(input.patch.published !== undefined ? { published: input.patch.published } : {}),
          updatedAt: new Date(),
        })
        .where(and(eq(statusPages.id, input.pageId), eq(statusPages.organizationId, input.organizationId)));

      if (input.patch.monitors) {
        await tx.delete(statusPageMonitors).where(eq(statusPageMonitors.statusPageId, input.pageId));
        await tx.insert(statusPageMonitors).values(
          input.patch.monitors.map((monitor) => ({
            organizationId: input.organizationId,
            statusPageId: input.pageId,
            monitorId: monitor.monitorId,
            publicLabel: monitor.publicLabel,
            sortOrder: monitor.sortOrder,
          })),
        );
      }
    });

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: input.patch.published === true ? 'status_page.published' : 'status_page.updated',
      entityType: 'status_page',
      entityId: input.pageId,
      metadata: { fields: Object.keys(input.patch) },
    });

    return this.get(input.organizationId, input.pageId);
  }

  async delete(organizationId: string, pageId: string, actorUserId: string): Promise<void> {
    const deleted = await this.db
      .delete(statusPages)
      .where(and(eq(statusPages.id, pageId), eq(statusPages.organizationId, organizationId)))
      .returning({ id: statusPages.id });
    if (!deleted[0]) throw notFound('Status page');
    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'status_page.deleted',
      entityType: 'status_page',
      entityId: pageId,
    });
  }

  /* ---------------------------------------------------------------------- */
  /* Public payload                                                          */
  /* ---------------------------------------------------------------------- */

  /**
   * The unauthenticated view. Throws the same 404 for an unpublished page and
   * for an unknown slug.
   */
  async publicView(slug: string, days: number): Promise<PublicStatusPage> {
    const rows = await this.db
      .select()
      .from(statusPages)
      .where(and(eq(statusPages.slug, slug), eq(statusPages.published, true)))
      .limit(1);
    const page = rows[0];
    if (!page) throw notFound('Status page');

    const links = await this.db
      .select({
        monitorId: statusPageMonitors.monitorId,
        publicLabel: statusPageMonitors.publicLabel,
        sortOrder: statusPageMonitors.sortOrder,
        name: monitors.name,
        currentState: monitors.currentState,
        enabled: monitors.enabled,
        lastCheckedAt: monitors.lastCheckedAt,
      })
      .from(statusPageMonitors)
      .innerJoin(monitors, eq(monitors.id, statusPageMonitors.monitorId))
      .where(eq(statusPageMonitors.statusPageId, page.id))
      .orderBy(asc(statusPageMonitors.sortOrder), asc(monitors.name));

    const windowDays = Math.min(Math.max(days, 1), page.historyDays || 90);
    const from = new Date(Date.now() - windowDays * 86_400_000);

    const uptimeRows =
      links.length === 0
        ? []
        : await this.db
            .select({
              monitorId: monitorChecks.monitorId,
              total: sql<number>`count(*)::int`,
              successful: sql<number>`count(*) filter (where ${monitorChecks.result} = 'success')::int`,
            })
            .from(monitorChecks)
            .where(
              and(
                eq(monitorChecks.organizationId, page.organizationId),
                inArray(
                  monitorChecks.monitorId,
                  links.map((link) => link.monitorId),
                ),
                gte(monitorChecks.checkedAt, from),
              ),
            )
            .groupBy(monitorChecks.monitorId);

    const uptimeMap = new Map(
      uptimeRows.map((row) => [
        row.monitorId,
        { checks: Number(row.total), successful: Number(row.successful) },
      ]),
    );

    const components: PublicStatusPage['components'] = links.map((link) => ({
      label: link.publicLabel ?? link.name,
      status: publicStatus(link.currentState, Boolean(link.enabled)),
      checkedAt: link.lastCheckedAt ? new Date(link.lastCheckedAt).toISOString() : null,
    }));

    const uptime: PublicStatusPage['uptime'] = links.map((link) => {
      const counts = uptimeMap.get(link.monitorId);
      return {
        label: link.publicLabel ?? link.name,
        uptimePercent:
          !counts || counts.checks === 0
            ? null
            : Math.round((counts.successful / counts.checks) * 10_000) / 100,
        windowDays,
        checks: counts?.checks ?? 0,
      };
    });

    const incidentRows =
      links.length === 0
        ? []
        : await this.db
            .select({
              id: incidents.id,
              title: incidents.title,
              status: incidents.status,
              severity: incidents.severity,
              startedAt: incidents.startedAt,
              resolvedAt: incidents.resolvedAt,
            })
            .from(incidentMonitors)
            .innerJoin(incidents, eq(incidents.id, incidentMonitors.incidentId))
            .where(
              and(
                eq(incidents.organizationId, page.organizationId),
                inArray(
                  incidentMonitors.monitorId,
                  links.map((link) => link.monitorId),
                ),
                gte(incidents.startedAt, from),
              ),
            )
            .orderBy(desc(incidents.startedAt))
            .limit(25);

    return {
      title: page.title,
      description: page.description,
      logoUrl: page.logoUrl,
      generatedAt: new Date().toISOString(),
      overallStatus: overallStatus(components),
      components,
      uptime,
      incidents: incidentRows.map((incident) => ({
        id: incident.id,
        title: incident.title,
        status: incident.status as IncidentStatus,
        severity: incident.severity as IncidentSeverity,
        startedAt: incident.startedAt.toISOString(),
        resolvedAt: incident.resolvedAt?.toISOString() ?? null,
      })),
      windowDays,
      method: UPTIME_METHOD_SHORT,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Internals                                                               */
  /* ---------------------------------------------------------------------- */

  private async links(pageIds: string[]) {
    const rows = await this.db
      .select({
        pageId: statusPageMonitors.statusPageId,
        monitorId: statusPageMonitors.monitorId,
        publicLabel: statusPageMonitors.publicLabel,
        sortOrder: statusPageMonitors.sortOrder,
        name: monitors.name,
      })
      .from(statusPageMonitors)
      .innerJoin(monitors, eq(monitors.id, statusPageMonitors.monitorId))
      .where(inArray(statusPageMonitors.statusPageId, pageIds))
      .orderBy(asc(statusPageMonitors.sortOrder));

    const map = new Map<
      string,
      Array<{ id: string; monitorId: string; name: string; publicLabel: string; sortOrder: number }>
    >();
    for (const row of rows) {
      const list = map.get(row.pageId) ?? [];
      list.push({
        id: `${row.pageId}:${row.monitorId}`,
        monitorId: row.monitorId,
        name: row.name,
        publicLabel: row.publicLabel ?? row.name,
        sortOrder: row.sortOrder,
      });
      map.set(row.pageId, list);
    }
    return map;
  }

  private toSummary(
    row: typeof statusPages.$inferSelect,
    links: Array<{
      id: string;
      monitorId: string;
      name: string;
      publicLabel: string;
      sortOrder: number;
    }>,
  ): StatusPageSummary {
    return {
      id: row.id,
      slug: row.slug,
      title: row.title,
      description: row.description,
      published: row.published,
      logoUrl: row.logoUrl,
      customDomain: row.customDomain,
      customDomainVerified: row.customDomainVerified,
      monitors: links.map((link) => ({
        id: link.id,
        monitorId: link.monitorId,
        name: link.name,
        publicLabel: link.publicLabel,
        sortOrder: link.sortOrder,
      })),
      publicUrl: `${this.appUrl}/status/${row.slug}`,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  private async assertMonitors(
    organizationId: string,
    entries: StatusPageMonitorInput[],
  ): Promise<void> {
    const ids = [...new Set(entries.map((entry) => entry.monitorId))];
    const rows = await this.db
      .select({ id: monitors.id })
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), inArray(monitors.id, ids)));
    if (rows.length !== ids.length) {
      throw conflict('One or more selected monitors do not belong to this organization.');
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Status derivation                                                          */
/* -------------------------------------------------------------------------- */

/**
 * `unknown` is the honest default: a monitor whose last check is missing or
 * stale is never reported as operational on a public page (Part F / F7).
 */
export function publicStatus(currentState: string, enabled: boolean): ComponentStatus {
  if (!enabled) return 'unknown';
  switch (currentState) {
    case 'up':
      return 'operational';
    case 'degraded':
      return 'degraded';
    case 'down':
      return 'major_outage';
    default:
      return 'unknown';
  }
}

export function overallStatus(components: PublicStatusPage['components']): ComponentStatus {
  if (components.length === 0) return 'unknown';
  const statuses = components.map((component) => component.status);
  const down = statuses.filter((status) => status === 'major_outage').length;
  if (down > 0) return down === statuses.length ? 'major_outage' : 'partial_outage';
  if (statuses.some((status) => status === 'degraded')) return 'degraded';
  if (statuses.some((status) => status === 'unknown')) return 'unknown';
  return 'operational';
}