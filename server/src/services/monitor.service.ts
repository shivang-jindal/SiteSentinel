/**
 * Monitors: CRUD, listing, check history and uptime reporting
 * (Part F / F3.2, F3.3, F3.4, F6).
 *
 * Two rules from the specification are enforced here rather than in the UI:
 *   - a monitor whose last check is missing or older than
 *     `max(2 minutes, 3 x interval)` is reported as `unknown`/stale, never as
 *     healthy (Part F / F7);
 *   - uptime is `successful / recorded` checks and the coverage is reported
 *     next to it, so a window with no probes reports "No data yet" instead of
 *     100% (Part F / F3.1).
 */

import { and, asc, count, desc, eq, gte, ilike, inArray, isNull, lte, or, sql, type SQL } from 'drizzle-orm';

import type {
  DomainCheckReport,
  MonitorCheck,
  MonitorDetail,
  MonitorListQuery,
  MonitorState,
  MonitorSummary,
  Paginated,
  SslCertificateReport,
  UptimePoint,
  UptimeReport,
} from '@sitesentinel/shared';
import {
  DOMAIN_CHECK_UNAVAILABLE_REASON,
  MIN_STALE_AFTER_MS,
  MONITOR_STATES,
  STALE_CHECK_INTERVAL_MULTIPLIER,
  UPTIME_METHOD_LABEL,
  ALLOWED_TCP_PORTS,
  checkHostnameTarget,
  checkTcpTarget,
  hostnameFromUrl,
  normalizeHostname,
} from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import {
  alertRules,
  domainChecks,
  incidentMonitors,
  incidents,
  monitorChecks,
  monitors,
  statusPageMonitors,
  type Monitor,
} from '../db/schema.js';
import { badRequest, conflict, notFound } from '../errors.js';
import { toIso } from '../lib/util.js';
import type { AuditService } from './audit.service.js';

export interface CreateMonitorInput {
  monitorType: 'http' | 'http_keyword' | 'tcp' | 'ssl_certificate';
  target: string;
  name: string;
  intervalSeconds: number;
  timeoutMs: number;
  enabled: boolean;
  tags: string[];
  expectedStatusCodes?: number[] | null;
  keywordMatch?: string | null;
  consecutiveFailureThreshold: number;
  recoverySuccessThreshold: number;
}

export type UpdateMonitorInput = Partial<Omit<CreateMonitorInput, 'monitorType'>>;

export interface MonitorAggregate {
  checksRecorded: number;
  successfulChecks: number;
  expectedChecks: number;
  uptimePercent: number | null;
  coverage: number | null;
  averageLatencyMs: number | null;
}

const EMPTY_AGGREGATE: MonitorAggregate = {
  checksRecorded: 0,
  successfulChecks: 0,
  expectedChecks: 0,
  uptimePercent: null,
  coverage: null,
  averageLatencyMs: null,
};

export class MonitorService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
  ) {}

  /* ---------------------------------------------------------------------- */
  /* Writes                                                                  */
  /* ---------------------------------------------------------------------- */

  async create(input: {
    organizationId: string;
    actorUserId: string;
    monitor: CreateMonitorInput;
    minIntervalSeconds: number;
    maxMonitors: number;
    defaultIntervalSeconds: number;
    defaultTimeoutMs: number;
    defaultFailureThreshold: number;
    defaultRecoveryThreshold: number;
  }): Promise<MonitorDetail> {
    const total = await this.countActive(input.organizationId);
    if (total >= input.maxMonitors) {
      throw conflict(
        `This organization already has ${total} monitors, which is its configured limit. Raise the limit in Settings before adding more.`,
        { limit: input.maxMonitors },
      );
    }

    const target = normalizeTarget(input.monitor.monitorType, input.monitor.target);
    if (input.monitor.intervalSeconds < input.minIntervalSeconds) {
      throw badRequest(`The shortest interval this organization allows is ${input.minIntervalSeconds} seconds.`, {
        intervalSeconds: [`Minimum ${input.minIntervalSeconds}`],
      });
    }

    const duplicate = await this.db
      .select({ id: monitors.id })
      .from(monitors)
      .where(
        and(
          eq(monitors.organizationId, input.organizationId),
          eq(monitors.targetUrlOrHost, target.value),
          eq(monitors.monitorType, input.monitor.monitorType),
          isNull(monitors.archivedAt),
        ),
      )
      .limit(1);
    if (duplicate[0]) {
      throw conflict('A monitor for that target already exists in this organization.', { field: 'target' });
    }

    const now = new Date();
    const inserted = await this.db
      .insert(monitors)
      .values({
        organizationId: input.organizationId,
        name: input.monitor.name.trim(),
        monitorType: input.monitor.monitorType,
        targetUrlOrHost: target.value,
        intervalSeconds: input.monitor.intervalSeconds || input.defaultIntervalSeconds,
        timeoutMs: input.monitor.timeoutMs || input.defaultTimeoutMs,
        expectedStatusCodes:
          input.monitor.monitorType === 'tcp' || input.monitor.monitorType === 'ssl_certificate'
            ? []
            : (input.monitor.expectedStatusCodes ?? [200]),
        keywordMatch: input.monitor.monitorType === 'http_keyword' ? input.monitor.keywordMatch ?? null : null,
        enabled: input.monitor.enabled,
        currentState: 'pending',
        tags: input.monitor.tags,
        consecutiveFailureThreshold: input.monitor.consecutiveFailureThreshold || input.defaultFailureThreshold,
        recoverySuccessThreshold: input.monitor.recoverySuccessThreshold || input.defaultRecoveryThreshold,
        createdBy: input.actorUserId,
        lastCheckedAt: null,
        nextCheckAt: now,
      })
      .returning();

    const row = inserted[0]!;
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'monitor.created',
      entityType: 'monitor',
      entityId: row.id,
      metadata: { monitorType: row.monitorType, intervalSeconds: row.intervalSeconds },
    });
    return this.detail(input.organizationId, row.id);
  }

  async update(input: {
    organizationId: string;
    monitorId: string;
    actorUserId: string;
    patch: UpdateMonitorInput;
    minIntervalSeconds: number;
  }): Promise<MonitorDetail> {
    const existing = await this.requireMonitor(input.organizationId, input.monitorId);

    if (input.patch.target !== undefined) {
      input.patch.target = normalizeTarget(
        existing.monitorType as 'http' | 'http_keyword' | 'tcp' | 'ssl_certificate',
        input.patch.target,
      ).value;
      const duplicate = await this.db
        .select({ id: monitors.id })
        .from(monitors)
        .where(
          and(
            eq(monitors.organizationId, input.organizationId),
            eq(monitors.targetUrlOrHost, input.patch.target),
            eq(monitors.monitorType, existing.monitorType),
            isNull(monitors.archivedAt),
          ),
        )
        .limit(1);
      if (duplicate[0]) {
        throw conflict('Another monitor in this organization already watches that target.', {
          field: 'target',
        });
      }
    }
    if (input.patch.intervalSeconds !== undefined && input.patch.intervalSeconds < input.minIntervalSeconds) {
      throw badRequest(`The shortest interval this organization allows is ${input.minIntervalSeconds} seconds.`, {
        intervalSeconds: [`Minimum ${input.minIntervalSeconds}`],
      });
    }
    if (input.patch.keywordMatch !== undefined && existing.monitorType !== 'http_keyword') {
      delete input.patch.keywordMatch;
    }

    const updated = await this.db
      .update(monitors)
      .set({
        ...(input.patch.name !== undefined ? { name: input.patch.name.trim() } : {}),
        ...(input.patch.target !== undefined ? { targetUrlOrHost: input.patch.target } : {}),
        ...(input.patch.intervalSeconds !== undefined ? { intervalSeconds: input.patch.intervalSeconds } : {}),
        ...(input.patch.timeoutMs !== undefined ? { timeoutMs: input.patch.timeoutMs } : {}),
        ...(input.patch.expectedStatusCodes !== undefined
          ? { expectedStatusCodes: input.patch.expectedStatusCodes ?? [200] }
          : {}),
        ...(input.patch.keywordMatch !== undefined ? { keywordMatch: input.patch.keywordMatch } : {}),
        ...(input.patch.tags !== undefined ? { tags: input.patch.tags } : {}),
        ...(input.patch.consecutiveFailureThreshold !== undefined
          ? { consecutiveFailureThreshold: input.patch.consecutiveFailureThreshold }
          : {}),
        ...(input.patch.recoverySuccessThreshold !== undefined
          ? { recoverySuccessThreshold: input.patch.recoverySuccessThreshold }
          : {}),
        ...(input.patch.enabled !== undefined
          ? {
              enabled: input.patch.enabled,
              currentState: input.patch.enabled ? existing.currentState : 'paused',
              nextCheckAt: input.patch.enabled ? new Date() : null,
            }
          : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(monitors.id, input.monitorId), eq(monitors.organizationId, input.organizationId)))
      .returning();

    if (!updated[0]) throw notFound('Monitor');
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'monitor.updated',
      entityType: 'monitor',
      entityId: input.monitorId,
      metadata: { fields: Object.keys(input.patch) },
    });
    return this.detail(input.organizationId, input.monitorId);
  }

  async setEnabled(input: {
    organizationId: string;
    monitorId: string;
    actorUserId: string;
    enabled: boolean;
    reason?: string | null;
  }): Promise<MonitorDetail> {
    const existing = await this.requireMonitor(input.organizationId, input.monitorId);
    if (existing.enabled === input.enabled) {
      return this.detail(input.organizationId, input.monitorId);
    }

    const updated = await this.db
      .update(monitors)
      .set({
        enabled: input.enabled,
        // A disabled monitor must never trigger "down" alerts (Part F / F7).
        currentState: input.enabled ? (existing.lastCheckedAt ? existing.currentState : 'pending') : 'paused',
        consecutiveFailures: input.enabled ? existing.consecutiveFailures : 0,
        nextCheckAt: input.enabled ? new Date() : null,
        updatedAt: new Date(),
      })
      .where(and(eq(monitors.id, input.monitorId), eq(monitors.organizationId, input.organizationId)))
      .returning();

    if (!updated[0]) throw notFound('Monitor');

    if (!input.enabled) {
      // Pausing stops monitoring: any open incident for this monitor is
      // resolved with an explicit, honest reason rather than left open.
      await this.resolveOpenIncidentsForPausedMonitor(
        input.organizationId,
        input.monitorId,
        input.reason?.trim() || 'Monitoring was paused, so the incident was closed.',
      );
    }

    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: input.enabled ? 'monitor.resumed' : 'monitor.paused',
      entityType: 'monitor',
      entityId: input.monitorId,
      metadata: input.reason ? { reason: input.reason.slice(0, 200) } : {},
    });
    return this.detail(input.organizationId, input.monitorId);
  }

  async setEnabledBulk(input: {
    organizationId: string;
    actorUserId: string;
    monitorIds: string[];
    enabled: boolean;
  }): Promise<{ changed: number }> {
    const ids = [...new Set(input.monitorIds)];
    const rows = await this.db
      .select({ id: monitors.id })
      .from(monitors)
      .where(and(eq(monitors.organizationId, input.organizationId), inArray(monitors.id, ids)));
    const owned = rows.map((row) => row.id);
    if (owned.length !== ids.length) {
      throw conflict('One or more selected monitors do not belong to this organization.');
    }
    let changed = 0;
    for (const id of owned) {
      const result = await this.setEnabled({
        organizationId: input.organizationId,
        monitorId: id,
        actorUserId: input.actorUserId,
        enabled: input.enabled,
      });
      void result;
      changed += 1;
    }
    return { changed };
  }

  /** Archiving keeps the check history but stops the monitor forever. */
  async archive(input: {
    organizationId: string;
    monitorId: string;
    actorUserId: string;
  }): Promise<{ id: string }> {
    await this.requireMonitor(input.organizationId, input.monitorId);
    await this.db
      .update(monitors)
      .set({ archivedAt: new Date(), enabled: false, currentState: 'paused', nextCheckAt: null, updatedAt: new Date() })
      .where(and(eq(monitors.id, input.monitorId), eq(monitors.organizationId, input.organizationId)));
    await this.resolveOpenIncidentsForPausedMonitor(
      input.organizationId,
      input.monitorId,
      'The monitor was archived, so the incident was closed.',
    );
    await this.audit.record({
      organizationId: input.organizationId,
      actorUserId: input.actorUserId,
      action: 'monitor.archived',
      entityType: 'monitor',
      entityId: input.monitorId,
    });
    return { id: input.monitorId };
  }

  async requireMonitor(organizationId: string, monitorId: string): Promise<Monitor> {
    const rows = await this.db
      .select()
      .from(monitors)
      .where(and(eq(monitors.id, monitorId), eq(monitors.organizationId, organizationId)))
      .limit(1);
    const row = rows[0];
    if (!row) throw notFound('Monitor');
    return row;
  }

  async countActive(organizationId: string): Promise<number> {
    const rows = await this.db
      .select({ total: count() })
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), isNull(monitors.archivedAt)));
    return rows[0]?.total ?? 0;
  }

  /* ---------------------------------------------------------------------- */
  /* Reads                                                                   */
  /* ---------------------------------------------------------------------- */

  async list(
    organizationId: string,
    query: MonitorListQuery,
    windowHours = 24,
  ): Promise<Paginated<MonitorSummary>> {
    const filters: SQL[] = [
      eq(monitors.organizationId, organizationId),
      isNull(monitors.archivedAt),
    ];
    if (query.q) {
      const search = or(
        ilike(monitors.name, `%${query.q}%`),
        ilike(monitors.targetUrlOrHost, `%${query.q}%`),
      );
      if (search) filters.push(search);
    }
    if (query.tag) filters.push(sql`${query.tag} = any(${monitors.tags})`);
    const where = and(...filters);

    const all = await this.db.select().from(monitors).where(where);
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowHours * 3_600_000);

    const aggregates = await this.aggregateWindow(organizationId, all.map((row) => row.id), windowStart, now);
    const openIncidentCounts = await this.openIncidentCounts(organizationId, all.map((row) => row.id));

    let rows = all.map((row) =>
      this.toSummary(
        row,
        aggregates.get(row.id) ?? EMPTY_AGGREGATE,
        openIncidentCounts.get(row.id) ?? 0,
        now,
      ),
    );

    if (query.state !== 'all') {
      rows = rows.filter((row) => (query.state === 'paused' ? !row.enabled : row.currentState === query.state));
    }
    if (query.type !== 'all') rows = rows.filter((row) => row.monitorType === query.type);

    const sorted = sortMonitors(rows, query.sort, query.order);
    const start = (query.page - 1) * query.pageSize;
    const items = sorted.slice(start, start + query.pageSize);

    return {
      items,
      page: query.page,
      pageSize: query.pageSize,
      total: sorted.length,
      totalPages: Math.max(1, Math.ceil(sorted.length / query.pageSize)),
    };
  }

  async detail(organizationId: string, monitorId: string): Promise<MonitorDetail> {
    const row = await this.requireMonitor(organizationId, monitorId);
    const now = new Date();
    const windowStart = new Date(now.getTime() - 24 * 3_600_000);

    const aggregates = await this.aggregateWindow(organizationId, [monitorId], windowStart, now);
    const openIncidentCounts = await this.openIncidentCounts(organizationId, [monitorId]);
    const summary = this.toSummary(
      row,
      aggregates.get(monitorId) ?? EMPTY_AGGREGATE,
      openIncidentCounts.get(monitorId) ?? 0,
      now,
    );

    const lastCheckRows = await this.db
      .select()
      .from(monitorChecks)
      .where(and(eq(monitorChecks.organizationId, organizationId), eq(monitorChecks.monitorId, monitorId)))
      .orderBy(desc(monitorChecks.checkedAt))
      .limit(1);

    const channelCount = await this.db
      .select({ total: count() })
      .from(alertRules)
      .where(and(eq(alertRules.organizationId, organizationId), eq(alertRules.monitorId, monitorId)));

    const pageRows = await this.db
      .select({ id: statusPageMonitors.id })
      .from(statusPageMonitors)
      .where(eq(statusPageMonitors.monitorId, monitorId))
      .limit(1);

    const lastSsl = await this.sslReport(organizationId, monitorId);
    const domainCheck = await this.domainReport(organizationId, monitorId);

    return {
      ...summary,
      expectedStatusCodes: row.expectedStatusCodes,
      keywordMatch: row.keywordMatch,
      consecutiveFailureThreshold: row.consecutiveFailureThreshold,
      recoverySuccessThreshold: row.recoverySuccessThreshold,
      alertChannelCount: channelCount[0]?.total ?? 0,
      onStatusPage: (pageRows[0]?.id ?? null) !== null,
      lastCheck: lastCheckRows[0] ? toCheckView(lastCheckRows[0]) : null,
      lastSsl,
      domainCheck,
    };
  }

  async checks(
    organizationId: string,
    monitorId: string,
    query: { page: number; pageSize: number; result: 'all' | 'success' | 'failure' },
  ): Promise<Paginated<MonitorCheck>> {
    await this.requireMonitor(organizationId, monitorId);
    const filters: SQL[] = [
      eq(monitorChecks.organizationId, organizationId),
      eq(monitorChecks.monitorId, monitorId),
    ];
    if (query.result !== 'all') filters.push(eq(monitorChecks.result, query.result));
    const where = and(...filters);

    const rows = await this.db
      .select()
      .from(monitorChecks)
      .where(where)
      .orderBy(desc(monitorChecks.checkedAt))
      .limit(query.pageSize)
      .offset((query.page - 1) * query.pageSize);
    const countRows = await this.db
      .select({ total: count() })
      .from(monitorChecks)
      .where(where);

    const total = countRows[0]?.total ?? 0;
    return {
      items: rows.map(toCheckView),
      page: query.page,
      pageSize: query.pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.pageSize)),
    };
  }

  /**
   * Uptime for one monitor. `uptimePercent` is `null` when nothing was
   * recorded, which the client renders as "No data yet" (Part F / F3.4).
   */
  async uptime(
    organizationId: string,
    monitorId: string,
    options: { from?: string; to?: string; buckets?: number },
  ): Promise<UptimeReport> {
    const monitor = await this.requireMonitor(organizationId, monitorId);
    const to = options.to ? new Date(options.to) : new Date();
    const from = options.from
      ? new Date(options.from)
      : new Date(to.getTime() - 24 * 3_600_000);
    if (from.getTime() >= to.getTime()) {
      throw badRequest('The start of the range must be before its end.', { from: ['Must be before "to"'] });
    }

    const rows = await this.db
      .select({
        checkedAt: monitorChecks.checkedAt,
        result: monitorChecks.result,
        latencyMs: monitorChecks.latencyMs,
        statusCode: monitorChecks.statusCode,
        failureType: monitorChecks.failureType,
      })
      .from(monitorChecks)
      .where(
        and(
          eq(monitorChecks.organizationId, organizationId),
          eq(monitorChecks.monitorId, monitorId),
          gte(monitorChecks.checkedAt, from),
          lte(monitorChecks.checkedAt, to),
        ),
      )
      .orderBy(asc(monitorChecks.checkedAt));

    const intervalSeconds = monitor.intervalSeconds;
    const expectedChecks = Math.max(
      0,
      Math.floor((to.getTime() - from.getTime()) / 1_000 / intervalSeconds) + 1,
    );
    const successful = rows.filter((row) => row.result === 'success');
    const latencies = successful
      .map((row) => row.latencyMs)
      .filter((value): value is number => typeof value === 'number')
      .sort((a, b) => a - b);

    const bucketCount = Math.min(options.buckets ?? 48, 200);
    const bucketMs = Math.max(1, Math.ceil((to.getTime() - from.getTime()) / bucketCount));
    const points: UptimePoint[] = [];
    for (let index = 0; index < bucketCount; index += 1) {
      const start = new Date(from.getTime() + index * bucketMs);
      const end = new Date(start.getTime() + bucketMs);
      const inBucket = rows.filter((row) => {
        const time = row.checkedAt.getTime();
        return time >= start.getTime() && (index === bucketCount - 1 ? time <= to.getTime() : time < end.getTime());
      });
      const ok = inBucket.filter((row) => row.result === 'success').length;
      const bucketLatencies = inBucket
        .filter((row) => row.result === 'success')
        .map((row) => row.latencyMs)
        .filter((value): value is number => typeof value === 'number');
      points.push({
        at: start.toISOString(),
        totalChecks: inBucket.length,
        successfulChecks: ok,
        uptimePercent: inBucket.length === 0 ? null : round2((ok / inBucket.length) * 100),
        averageLatencyMs:
          bucketLatencies.length === 0
            ? null
            : Math.round(bucketLatencies.reduce((sum, value) => sum + value, 0) / bucketLatencies.length),
      });
    }

    const statusCounts = new Map<number, number>();
    const failureCounts = new Map<string, number>();
    for (const row of rows) {
      if (row.statusCode !== null) statusCounts.set(row.statusCode, (statusCounts.get(row.statusCode) ?? 0) + 1);
      if (row.failureType) failureCounts.set(row.failureType, (failureCounts.get(row.failureType) ?? 0) + 1);
    }

    return {
      from: from.toISOString(),
      to: to.toISOString(),
      intervalSeconds,
      expectedChecks,
      totalChecks: rows.length,
      successfulChecks: successful.length,
      failedChecks: rows.length - successful.length,
      uptimePercent: rows.length === 0 ? null : round2((successful.length / rows.length) * 100),
      coverage: expectedChecks === 0 ? null : Math.min(1, round2(rows.length / expectedChecks)),
      averageLatencyMs:
        latencies.length === 0 ? null : Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length),
      p95LatencyMs: latencies.length === 0 ? null : percentile(latencies, 95),
      method: UPTIME_METHOD_LABEL,
      points,
      statusCodeDistribution: [...statusCounts.entries()]
        .map(([statusCode, value]) => ({ statusCode, count: value }))
        .sort((a, b) => a.statusCode - b.statusCode),
      failureBreakdown: [...failureCounts.entries()]
        .map(([failureType, value]) => ({ failureType, count: value }))
        .sort((a, b) => b.count - a.count),
    } as UptimeReport;
  }

  /* ---------------------------------------------------------------------- */
  /* SSL and domain reports                                                  */
  /* ---------------------------------------------------------------------- */

  /**
   * The most recent real TLS handshake for this monitor, or a truthful
   * "unavailable" report. Nothing is inferred from a missing check.
   */
  async sslReport(organizationId: string, monitorId: string): Promise<SslCertificateReport> {
    const monitor = await this.requireMonitor(organizationId, monitorId);
    const rows = await this.db
      .select()
      .from(monitorChecks)
      .where(
        and(
          eq(monitorChecks.organizationId, organizationId),
          eq(monitorChecks.monitorId, monitorId),
          sql`${monitorChecks.tlsExpiryAt} is not null`,
        ),
      )
      .orderBy(desc(monitorChecks.checkedAt))
      .limit(1);
    const row = rows[0];

    const host =
      hostnameFromUrl(monitor.targetUrlOrHost) ?? normalizeHostname(monitor.targetUrlOrHost.split(':')[0] ?? '');

    if (!row || !row.tlsExpiryAt) {
      return {
        host,
        checkedAt: row?.checkedAt.toISOString() ?? monitor.createdAt.toISOString(),
        available: false,
        expiresAt: null,
        daysRemaining: null,
        issuer: null,
        subject: null,
        serialNumber: null,
        protocol: null,
        chainValid: null,
        chainError: null,
        selfSigned: null,
        warningLevelDays: null,
        safeMessage:
          'No certificate information has been recorded yet. SiteSentinel only reports a real TLS handshake result, and never estimates an expiry date.',
      };
    }

    const daysRemaining = Math.floor((row.tlsExpiryAt.getTime() - row.checkedAt.getTime()) / 86_400_000);
    return {
      host,
      checkedAt: row.checkedAt.toISOString(),
      available: true,
      expiresAt: row.tlsExpiryAt.toISOString(),
      daysRemaining,
      issuer: row.tlsIssuer,
      subject: row.tlsSubject,
      serialNumber: row.tlsSerialNumber,
      protocol: row.tlsProtocol,
      chainValid: row.tlsChainValid,
      chainError: row.tlsChainError,
      selfSigned: row.tlsSelfSigned,
      warningLevelDays: warningLevelFor(daysRemaining),
      safeMessage: row.safeMessage ?? '',
    };
  }

  /**
   * Domain expiry. SiteSentinel ships without an RDAP/WHOIS source, so this
   * always reports `unavailable` rather than guessing a date (Part F / F1, F4).
   */
  async domainReport(organizationId: string, monitorId: string): Promise<DomainCheckReport | null> {
    const monitor = await this.requireMonitor(organizationId, monitorId);
    if (monitor.monitorType !== 'domain_expiry') return null;
    const rows = await this.db
      .select()
      .from(domainChecks)
      .where(and(eq(domainChecks.organizationId, organizationId), eq(domainChecks.monitorId, monitorId)))
      .orderBy(desc(domainChecks.checkedAt))
      .limit(1);
    const row = rows[0];
    return {
      host: normalizeHostname(monitor.targetUrlOrHost),
      checkedAt: (row?.checkedAt ?? monitor.createdAt).toISOString(),
      status: 'unavailable',
      expiresAt: null,
      source: null,
      safeMessage: row?.safeMessage ?? DOMAIN_CHECK_UNAVAILABLE_REASON,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Aggregates                                                              */
  /* ---------------------------------------------------------------------- */

  async aggregateWindow(
    organizationId: string,
    monitorIds: string[],
    from: Date,
    to: Date,
  ): Promise<Map<string, MonitorAggregate>> {
    const result = new Map<string, MonitorAggregate>();
    if (monitorIds.length === 0) return result;

    const intervals = await this.db
      .select({ id: monitors.id, intervalSeconds: monitors.intervalSeconds })
      .from(monitors)
      .where(eq(monitors.organizationId, organizationId));

    const rows = await this.db
      .select({
        monitorId: monitorChecks.monitorId,
        total: count(),
        successful: sql<number>`count(*) filter (where ${monitorChecks.result} = 'success')::int`,
        averageLatency: sql<number>`coalesce(avg(${monitorChecks.latencyMs}) filter (where ${monitorChecks.latencyMs} is not null), 0)::double precision`,
      })
      .from(monitorChecks)
      .where(
        and(
          eq(monitorChecks.organizationId, organizationId),
          inArray(monitorChecks.monitorId, monitorIds),
          gte(monitorChecks.checkedAt, from),
          lte(monitorChecks.checkedAt, to),
        ),
      )
      .groupBy(monitorChecks.monitorId);

    const intervalMap = new Map(intervals.map((row) => [row.id, row.intervalSeconds]));
    const windowSeconds = Math.max(1, Math.round((to.getTime() - from.getTime()) / 1_000));

    for (const row of rows) {
      const interval = intervalMap.get(row.monitorId) ?? 300;
      const expected = Math.floor(windowSeconds / interval) + 1;
      const total = Number(row.total);
      const successful = Number(row.successful);
      result.set(row.monitorId, {
        checksRecorded: total,
        successfulChecks: successful,
        expectedChecks: expected,
        uptimePercent: total === 0 ? null : round2((successful / total) * 100),
        coverage: Math.min(1, round2(total / expected)),
        averageLatencyMs:
          Number(row.averageLatency) === 0 ? null : Math.round(Number(row.averageLatency)),
      });
    }

    for (const id of monitorIds) {
      if (result.has(id)) continue;
      const interval = intervalMap.get(id) ?? 300;
      const expected = Math.floor(windowSeconds / interval) + 1;
      result.set(id, { ...EMPTY_AGGREGATE, expectedChecks: expected });
    }

    return result;
  }

  async openIncidentCounts(organizationId: string, monitorIds: string[]): Promise<Map<string, number>> {
    const result = new Map<string, number>();
    if (monitorIds.length === 0) return result;
    const rows = await this.db
      .select({
        monitorId: incidentMonitors.monitorId,
        total: sql<number>`count(*)::int`,
      })
      .from(incidentMonitors)
      .innerJoin(incidents, eq(incidents.id, incidentMonitors.incidentId))
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          inArray(incidentMonitors.monitorId, monitorIds),
          inArray(incidents.status, ['open', 'acknowledged']),
        ),
      )
      .groupBy(incidentMonitors.monitorId);
    for (const row of rows) result.set(row.monitorId, Number(row.total));
    return result;
  }

  /** Display state: disabled, stale and never-checked monitors are never green. */
  private toSummary(
    row: Monitor,
    aggregate: MonitorAggregate,
    openIncidentCount: number,
    now: Date,
  ): MonitorSummary {
    const displayState = displayStateOf(row, now);
    return {
      id: row.id,
      name: row.name,
      monitorType: row.monitorType as MonitorSummary['monitorType'],
      target: row.targetUrlOrHost,
      enabled: row.enabled,
      currentState: displayState,
      stale: isStale(row, now),
      consecutiveFailures: row.consecutiveFailures,
      consecutiveSuccesses: row.consecutiveSuccesses,
      lastCheckedAt: toIso(row.lastCheckedAt ?? null),
      nextCheckAt: toIso(row.nextCheckAt ?? null),
      lastLatencyMs: row.lastLatencyMs ?? null,
      uptimePercent: aggregate.uptimePercent ?? null,
      checksRecorded: aggregate.checksRecorded ?? 0,
      expectedChecks: aggregate.expectedChecks ?? 0,
      coverage: aggregate.coverage ?? null,
      averageLatencyMs: aggregate.averageLatencyMs ?? null,
      openIncidentCount,
      tags: row.tags,
      intervalSeconds: row.intervalSeconds,
      timeoutMs: row.timeoutMs,
      createdAt: row.createdAt.toISOString(),
      archivedAt: toIso(row.archivedAt),
    };
  }

  private async resolveOpenIncidentsForPausedMonitor(
    organizationId: string,
    monitorId: string,
    reason: string,
  ): Promise<void> {
    const open = await this.db
      .select({ id: incidents.id })
      .from(incidentMonitors)
      .innerJoin(incidents, eq(incidents.id, incidentMonitors.incidentId))
      .where(
        and(
          eq(incidents.organizationId, organizationId),
          eq(incidentMonitors.monitorId, monitorId),
          inArray(incidents.status, ['open', 'acknowledged']),
        ),
      );
    const at = new Date();
    for (const row of open) {
      await this.db
        .update(incidents)
        .set({ status: 'resolved', resolvedAt: at, resolutionReason: reason, updatedAt: at })
        .where(and(eq(incidents.id, row.id), inArray(incidents.status, ['open', 'acknowledged'])));
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** `null` when the monitor has never been checked or the check is too old. */
export function isStale(monitor: Monitor, now: Date): boolean {
  if (!monitor.lastCheckedAt) return true;
  const allowed = Math.max(
    MIN_STALE_AFTER_MS,
    monitor.intervalSeconds * STALE_CHECK_INTERVAL_MULTIPLIER * 1_000,
  );
  return now.getTime() - monitor.lastCheckedAt.getTime() > allowed;
}

export function displayStateOf(monitor: Monitor, now: Date): MonitorState {
  if (!monitor.enabled) return 'paused';
  if (!monitor.lastCheckedAt) return 'unknown';
  if (isStale(monitor, now)) return 'unknown';
  if (!MONITOR_STATES.includes(monitor.currentState as MonitorState)) return 'unknown';
  return monitor.currentState as MonitorState;
}

export function toCheckView(row: typeof monitorChecks.$inferSelect): MonitorCheck {
  return {
    id: row.id,
    checkedAt: row.checkedAt.toISOString(),
    finishedAt: toIso(row.finishedAt),
    result: row.result as MonitorCheck['result'],
    failureType: (row.failureType ?? null) as MonitorCheck['failureType'],
    statusCode: row.statusCode,
    latencyMs: row.latencyMs,
    dnsMs: row.dnsMs,
    responseSizeBytes: row.responseSizeBytes,
    safeMessage: row.safeMessage,
    probeLocation: row.probeLocation,
    probeVersion: row.probeVersion,
  };
}

export function warningLevelFor(daysRemaining: number): number | null {
  for (const level of [30, 14, 7, 3, 1]) {
    if (daysRemaining <= level) return level;
  }
  return null;
}

function normalizeTarget(
  monitorType: 'http' | 'http_keyword' | 'tcp' | 'ssl_certificate',
  raw: string,
): { value: string } {
  if (monitorType === 'http' || monitorType === 'http_keyword') {
    const parsed = new URL(raw.trim());
    parsed.hash = '';
    return { value: parsed.toString() };
  }
  if (monitorType === 'tcp') {
    const checked = checkTcpTarget(raw.trim(), ALLOWED_TCP_PORTS);
    if (!checked.ok) throw badRequest(checked.reason, { target: [checked.reason] });
    return { value: `${checked.hostname}:${checked.port}` };
  }
  const checked = checkHostnameTarget(raw.trim());
  if (!checked.ok) throw badRequest(checked.reason, { target: [checked.reason] });
  return { value: checked.hostname };
}

function sortMonitors(
  rows: MonitorSummary[],
  sort: MonitorListQuery['sort'],
  order: MonitorListQuery['order'],
): MonitorSummary[] {
  const direction = order === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    switch (sort) {
      case 'last_checked_at':
        return (Date.parse(a.lastCheckedAt ?? '0') - Date.parse(b.lastCheckedAt ?? '0')) * direction;
      case 'latency':
        return ((a.lastLatencyMs ?? Number.MAX_SAFE_INTEGER) - (b.lastLatencyMs ?? Number.MAX_SAFE_INTEGER)) * direction;
      case 'created_at':
        return (Date.parse(a.createdAt) - Date.parse(b.createdAt)) * direction;
      case 'name':
      default:
        return a.name.localeCompare(b.name) * direction;
    }
  });
}

function percentile(sortedAscending: number[], pct: number): number {
  if (sortedAscending.length === 0) return 0;
  const index = Math.min(
    sortedAscending.length - 1,
    Math.max(0, Math.ceil((pct / 100) * sortedAscending.length) - 1),
  );
  return sortedAscending[index] ?? 0;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}