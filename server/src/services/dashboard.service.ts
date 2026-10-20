/**
 * Dashboard summary (Part F / F3.1).
 *
 * Every figure comes from persisted rows and carries a documented definition.
 * Two rules are enforced here:
 *   - a monitor with no check, or with a stale check, is reported as `unknown`
 *     and never as healthy;
 *   - the coverage denominator is always returned next to the uptime figure so
 *     a partially-collected window cannot be read as "100% uptime".
 */

import { and, count, desc, eq, gte, isNull, sql } from 'drizzle-orm';

import type { DashboardSummary, MonitorState, PlatformWarning } from '@sitesentinel/shared';
import { MONITOR_STATES, TIME_RANGE_OPTIONS, UPTIME_METHOD_LABEL } from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import { emailMessages, monitorChecks, monitors } from '../db/schema.js';
import type { EmailAdapter } from '../integrations/email/types.js';
import type { IncidentService } from './incident.service.js';
import type { MaintenanceService } from './maintenance.service.js';
import { displayStateOf, isStale } from './monitor.service.js';
import type { OrganizationService } from './organization.service.js';
import type { ProbeService } from './probe.service.js';

export interface DashboardQuery {
  from?: string;
  to?: string;
  hours?: number;
}

export class DashboardService {
  constructor(
    private readonly db: AppDatabase,
    private readonly organizations: OrganizationService,
    private readonly incidents: IncidentService,
    private readonly maintenance: MaintenanceService,
    private readonly probes: ProbeService,
    private readonly emailAdapter: EmailAdapter,
  ) {}

  async summary(
    organizationId: string,
    query: DashboardQuery,
  ): Promise<DashboardSummary> {
    const now = new Date();
    const to = query.to ? new Date(query.to) : now;
    const from = query.from
      ? new Date(query.from)
      : new Date(to.getTime() - (query.hours ?? 24) * 3_600_000);
    const rangeLabel = labelFor(query, to, from);

    const monitorRows = await this.db
      .select()
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), isNull(monitors.archivedAt)));

    const stateCounts = Object.fromEntries(
      MONITOR_STATES.map((state) => [state, 0]),
    ) as Record<MonitorState, number>;

    let staleMonitorCount = 0;
    for (const row of monitorRows) {
      const state = displayStateOf(row, now);
      stateCounts[state] += 1;
      if (isStale(row, now)) staleMonitorCount += 1;
    }

    const totalRows = await this.db
      .select({
        total: sql<number>`count(*)::int`,
        successful: sql<number>`count(*) filter (where ${monitorChecks.result} = 'success')::int`,
        averageLatency: sql<number>`coalesce(avg(${monitorChecks.latencyMs}) filter (where ${monitorChecks.latencyMs} is not null), 0)::double precision`,
      })
      .from(monitorChecks)
      .where(
        and(
          eq(monitorChecks.organizationId, organizationId),
          gte(monitorChecks.checkedAt, from),
          sql`${monitorChecks.checkedAt} <= ${to}`,
        ),
      );

    const totalChecks = Number(totalRows[0]?.total ?? 0);
    const successfulChecks = Number(totalRows[0]?.successful ?? 0);

    const expectedRows = await this.db
      .select({
        id: monitors.id,
        intervalSeconds: monitors.intervalSeconds,
      })
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), isNull(monitors.archivedAt)));
    const windowSeconds = Math.max(1, Math.round((to.getTime() - from.getTime()) / 1_000));
    const expectedChecks = expectedRows.reduce(
      (total, row) => total + Math.floor(windowSeconds / Math.max(1, row.intervalSeconds)) + 1,
      0,
    );

    const slowestRows = await this.db
      .select({
        id: monitors.id,
        name: monitors.name,
        averageLatency: sql<number>`coalesce(avg(${monitorChecks.latencyMs}), 0)::double precision`,
        checks: sql<number>`count(*)::int`,
      })
      .from(monitorChecks)
      .innerJoin(monitors, eq(monitors.id, monitorChecks.monitorId))
      .where(
        and(
          eq(monitorChecks.organizationId, organizationId),
          gte(monitorChecks.checkedAt, from),
          sql`${monitorChecks.checkedAt} <= ${to}`,
          sql`${monitorChecks.latencyMs} is not null`,
        ),
      )
      .groupBy(monitors.id, monitors.name)
      .orderBy(desc(sql`avg(${monitorChecks.latencyMs})`))
      .limit(5);

    const activeMaintenance = await this.maintenance.activeWindows(organizationId, now);
    const expiringCertificates = await this.expiringCertificates(organizationId, now);

    const openIncidentCount = await this.incidents.openCount(organizationId);
    const incidentsLast24h = await this.incidents.countSince(organizationId, new Date(now.getTime() - 24 * 3_600_000));

    const probeHealth = await this.probes.health();
    const warnings = await this.warnings(organizationId, probeHealth.detail, staleMonitorCount);

    const dispatchRows = await this.db
      .select({ total: count() })
      .from(sql`background_jobs`)
      .where(sql`job_type = 'probes.dispatch' and status in ('queued','running')`);
    const intervalBucketSeconds = DISPATCH_BUCKET_SECONDS;

    const averageLatencyRaw = Number(totalRows[0]?.averageLatency ?? 0);

    return {
      from: from.toISOString(),
      to: to.toISOString(),
      rangeLabel,
      method: UPTIME_METHOD_LABEL,
      monitorCount: monitorRows.length,
      stateCounts,
      staleMonitorCount,
      openIncidentCount,
      incidentsLast24h,
      averageLatencyMs: averageLatencyRaw === 0 ? null : Math.round(averageLatencyRaw),
      organizationUptimePercent:
        totalChecks === 0 ? null : round2((successfulChecks / totalChecks) * 100),
      expectedChecks,
      totalChecks,
      coverage: expectedChecks === 0 ? null : Math.min(1, round2(totalChecks / expectedChecks)),
      slowestMonitors: slowestRows
        .filter((row) => Number(row.averageLatency) > 0)
        .map((row) => ({
          id: row.id,
          name: row.name,
          averageLatencyMs: Math.round(Number(row.averageLatency)),
          checks: Number(row.checks),
        })),
      recentIncidents: await this.incidents.recent(organizationId, 5),
      activeMaintenance,
      expiringCertificates,
      warnings,
      email: {
        provider: this.emailAdapter.name,
        deliversMessages: this.emailAdapter.deliversMessages,
        setupHint: this.emailAdapter.setupHint,
      },
      probe: {
        intervalBucketSeconds,
        dispatchJobId: dispatchRows[0] && (dispatchRows[0].total ?? 0) > 0 ? 'pending' : null,
      },
    };
  }

  private async expiringCertificates(organizationId: string, now: Date) {
    const rows = await this.db
      .select({
        id: monitors.id,
        name: monitors.name,
        expiresAt: monitorChecks.tlsExpiryAt,
        checkedAt: monitorChecks.checkedAt,
      })
      .from(monitors)
      .innerJoin(monitorChecks, eq(monitorChecks.monitorId, monitors.id))
      .where(
        and(
          eq(monitors.organizationId, organizationId),
          eq(monitors.monitorType, 'ssl_certificate'),
          sql`${monitorChecks.tlsExpiryAt} is not null`,
        ),
      )
      .orderBy(desc(monitorChecks.checkedAt))
      .limit(25);

    const seen = new Set<string>();
    const output: DashboardSummary['expiringCertificates'] = [];
    for (const row of rows) {
      if (seen.has(row.id) || !row.expiresAt) continue;
      seen.add(row.id);
      const expiresAt = new Date(row.expiresAt);
      const daysRemaining = Math.floor((expiresAt.getTime() - now.getTime()) / 86_400_000);
      if (daysRemaining > 45) continue;
      output.push({
        id: row.id,
        name: row.name,
        expiresAt: expiresAt.toISOString(),
        daysRemaining,
      });
      if (output.length >= 10) break;
    }
    return output;
  }

  private async warnings(
    organizationId: string,
    probeDetail: string,
    staleMonitorCount: number,
  ): Promise<PlatformWarning[]> {
    const warnings: PlatformWarning[] = [];

    if (!this.emailAdapter.deliversMessages) {
      warnings.push({
        level: 'info',
        code: 'email_not_configured',
        message: `${this.emailAdapter.name}: alerts are recorded but not delivered. ${this.emailAdapter.setupHint}`,
      });
    }

    const enabledRows = await this.db
      .select({ total: count() })
      .from(monitors)
      .where(
        and(
          eq(monitors.organizationId, organizationId),
          eq(monitors.enabled, true),
          isNull(monitors.archivedAt),
        ),
      );
    if ((enabledRows[0]?.total ?? 0) > 0) {
      const recentChecks = await this.db
        .select({ total: count() })
        .from(monitorChecks)
        .where(
          and(
            eq(monitorChecks.organizationId, organizationId),
            gte(monitorChecks.checkedAt, new Date(Date.now() - 10 * 60_000)),
          ),
        );
      if ((recentChecks[0]?.total ?? 0) === 0) {
        warnings.push({
          level: 'critical',
          code: 'probe_worker_not_running',
          message: `No check has been recorded in the last 10 minutes. Monitors are reported as unknown, never as down, because the probe worker may not be running. ${probeDetail}`,
        });
      }
    }

    if (staleMonitorCount > 0) {
      warnings.push({
        level: 'warning',
        code: 'stale_monitors',
        message: `${staleMonitorCount} monitor(s) have no recent check and are reported as "Unknown / stale" rather than healthy.`,
      });
    }

    const unconfiguredChannels = await this.db
      .select({ total: count() })
      .from(sql`alert_channels`)
      .where(sql`organization_id = ${organizationId} and last_test_status = 'never_tested'`);
    if ((unconfiguredChannels[0]?.total ?? 0) > 0) {
      warnings.push({
        level: 'info',
        code: 'alert_channels_untested',
        message: `${unconfiguredChannels[0]?.total} alert channel(s) have never been tested. Use "Send test" to verify a channel before relying on it.`,
      });
    }

    const emailRows = await this.db
      .select({ total: count() })
      .from(emailMessages)
      .where(and(eq(emailMessages.organizationId, organizationId), eq(emailMessages.status, 'failed')));
    if ((emailRows[0]?.total ?? 0) > 0) {
      warnings.push({
        level: 'warning',
        code: 'email_failures',
        message: `${emailRows[0]?.total} alert email(s) were rejected. Open Settings > Alerting to see the recorded reason.`,
      });
    }

    return warnings;
  }
}

function labelFor(query: DashboardQuery, to: Date, from: Date): string {
  if (query.from && query.to) {
    return `${from.toISOString()} to ${to.toISOString()}`;
  }
  const hours = query.hours ?? 24;
  const preset = TIME_RANGE_OPTIONS.find((option) => option.hours === hours);
  return preset?.label ?? `Last ${hours} hours`;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** The worker keeps at most one dispatch job queued per this many seconds. */
export const DISPATCH_BUCKET_SECONDS = 30;