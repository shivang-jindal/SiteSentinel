/**
 * CSV export (Part F / F3.9, Part A / A4).
 *
 * Exports are permission-checked, audit-logged and formula-injection escaped.
 * Only the caller's own organization data is ever written out.
 */

import { and, asc, desc, eq, gte, lte, sql } from 'drizzle-orm';

import { toCsv } from '@sitesentinel/shared';

import type { AppDatabase } from '../db/client.js';
import {
  alertChannels,
  alertDeliveries,
  incidentMonitors,
  incidents,
  monitorChecks,
  monitors,
} from '../db/schema.js';
import { badRequest } from '../errors.js';
import type { AuditService } from './audit.service.js';

export type ExportDataset = 'monitors' | 'checks' | 'incidents' | 'alert_deliveries';

export interface ExportRequest {
  dataset: ExportDataset;
  monitorId?: string;
  from?: string;
  to?: string;
}

export class ExportService {
  constructor(
    private readonly db: AppDatabase,
    private readonly audit: AuditService,
  ) {}

  async build(
    organizationId: string,
    request: ExportRequest,
    actorUserId: string,
    context: { requestId?: string | null } = {},
  ): Promise<{ filename: string; csv: string; rowCount: number }> {
    const result = await this.render(organizationId, request);
    await this.audit.record({
      organizationId,
      actorUserId,
      action: 'export.generated',
      entityType: 'organization',
      entityId: organizationId,
      metadata: { dataset: request.dataset, rowCount: result.rowCount, monitorId: request.monitorId ?? null },
      requestId: context.requestId ?? null,
    });
    return result;
  }

  private async render(
    organizationId: string,
    request: ExportRequest,
  ): Promise<{ filename: string; csv: string; rowCount: number }> {
    const stamp = new Date().toISOString().slice(0, 10);
    const suffix = request.monitorId ? `-${request.monitorId.slice(0, 8)}` : '';
    switch (request.dataset) {
      case 'monitors':
        return this.monitorsCsv(organizationId, `sitesentinel-monitors-${stamp}.csv`);
      case 'checks':
        return this.checksCsv(organizationId, `sitesentinel-checks-${stamp}${suffix}.csv`, request);
      case 'incidents':
        return this.incidentsCsv(organizationId, `sitesentinel-incidents-${stamp}.csv`, request);
      case 'alert_deliveries':
        return this.deliveriesCsv(organizationId, `sitesentinel-alert-deliveries-${stamp}.csv`, request);
      default:
        throw badRequest('Unknown export dataset.');
    }
  }

  private async monitorsCsv(organizationId: string, filename: string) {
    const rows = await this.db
      .select()
      .from(monitors)
      .where(and(eq(monitors.organizationId, organizationId), sql`${monitors.archivedAt} is null`))
      .orderBy(asc(monitors.name));

    return {
      filename,
      rowCount: rows.length,
      csv: toCsv(
        rows.map((row) => [
          row.name,
          row.monitorType,
          row.targetUrlOrHost,
          row.enabled ? 'enabled' : 'paused',
          row.currentState,
          row.intervalSeconds,
          row.timeoutMs,
          row.lastCheckedAt ? row.lastCheckedAt.toISOString() : '',
          row.lastLatencyMs ?? '',
          row.consecutiveFailures,
          row.tags.join(' '),
          row.createdAt.toISOString(),
        ]),
        [
          'name',
          'monitor_type',
          'target',
          'enabled',
          'current_state',
          'interval_seconds',
          'timeout_ms',
          'last_checked_at',
          'last_latency_ms',
          'consecutive_failures',
          'tags',
          'created_at',
        ],
      ),
    };
  }

  private async checksCsv(organizationId: string, filename: string, request: ExportRequest) {
    const filters = [eq(monitorChecks.organizationId, organizationId)];
    if (request.monitorId) filters.push(eq(monitorChecks.monitorId, request.monitorId));
    if (request.from) filters.push(gte(monitorChecks.checkedAt, new Date(request.from)));
    if (request.to) filters.push(lte(monitorChecks.checkedAt, new Date(request.to)));

    const rows = await this.db
      .select({
        checkedAt: monitorChecks.checkedAt,
        monitorName: monitors.name,
        result: monitorChecks.result,
        failureType: monitorChecks.failureType,
        statusCode: monitorChecks.statusCode,
        latencyMs: monitorChecks.latencyMs,
        dnsMs: monitorChecks.dnsMs,
        responseSizeBytes: monitorChecks.responseSizeBytes,
        safeMessage: monitorChecks.safeMessage,
        probeLocation: monitorChecks.probeLocation,
        tlsExpiresAt: monitorChecks.tlsExpiryAt,
      })
      .from(monitorChecks)
      .innerJoin(monitors, eq(monitors.id, monitorChecks.monitorId))
      .where(and(...filters))
      .orderBy(desc(monitorChecks.checkedAt))
      .limit(50_000);

    return {
      filename,
      rowCount: rows.length,
      csv: toCsv(
        rows.map((row) => [
          row.checkedAt.toISOString(),
          row.monitorName,
          row.result,
          row.failureType ?? '',
          row.statusCode ?? '',
          row.latencyMs ?? '',
          row.dnsMs ?? '',
          row.responseSizeBytes ?? '',
          row.tlsExpiresAt ? new Date(row.tlsExpiresAt).toISOString() : '',
          row.probeLocation,
          row.safeMessage ?? '',
        ]),
        [
          'checked_at',
          'monitor',
          'result',
          'failure_type',
          'status_code',
          'latency_ms',
          'dns_ms',
          'response_size_bytes',
          'tls_expires_at',
          'probe_location',
          'safe_message',
        ],
      ),
    };
  }

  private async incidentsCsv(organizationId: string, filename: string, request: ExportRequest) {
    const filters = [eq(incidents.organizationId, organizationId)];
    if (request.from) filters.push(gte(incidents.startedAt, new Date(request.from)));
    if (request.to) filters.push(lte(incidents.startedAt, new Date(request.to)));

    const rows = await this.db
      .select({
        startedAt: incidents.startedAt,
        title: incidents.title,
        severity: incidents.severity,
        status: incidents.status,
        acknowledgedAt: incidents.acknowledgedAt,
        resolvedAt: incidents.resolvedAt,
        durationSeconds: sql<number>`coalesce(extract(epoch from (${incidents.resolvedAt} - ${incidents.startedAt})), 0)::bigint`,
        resolutionReason: incidents.resolutionReason,
        maintenance: sql<boolean>`${incidents.maintenanceWindowId} is not null`,
      })
      .from(incidents)
      .where(and(...filters))
      .orderBy(desc(incidents.startedAt));

    const links = rows.length > 0 ? await this.monitorNames(rows.map((row) => row.title)) : new Map();

    return {
      filename,
      rowCount: rows.length,
      csv: toCsv(
        rows.map((row) => [
          row.startedAt.toISOString(),
          row.title,
          links.get(row.title) ?? '',
          row.severity,
          row.status,
          row.acknowledgedAt ? new Date(row.acknowledgedAt).toISOString() : '',
          row.resolvedAt ? new Date(row.resolvedAt).toISOString() : '',
          Number(row.durationSeconds),
          row.maintenance ? 'yes' : 'no',
          row.resolutionReason ?? '',
        ]),
        [
          'started_at',
          'title',
          'monitors',
          'severity',
          'status',
          'acknowledged_at',
          'resolved_at',
          'duration_seconds',
          'during_maintenance',
          'resolution_reason',
        ],
      ),
    };
  }

  private async deliveriesCsv(organizationId: string, filename: string, request: ExportRequest) {
    const filters = [eq(alertDeliveries.organizationId, organizationId)];
    if (request.monitorId) filters.push(eq(alertDeliveries.monitorId, request.monitorId));

    const rows = await this.db
      .select({
        createdAt: alertDeliveries.createdAt,
        sentAt: alertDeliveries.sentAt,
        eventType: alertDeliveries.eventType,
        status: alertDeliveries.status,
        attempts: alertDeliveries.attempts,
        failureCode: alertDeliveries.failureCode,
        safeMessage: alertDeliveries.safeMessage,
        channelName: alertChannels.name,
        channelType: alertChannels.channelType,
        monitorName: monitors.name,
      })
      .from(alertDeliveries)
      .innerJoin(alertChannels, eq(alertChannels.id, alertDeliveries.channelId))
      .leftJoin(monitors, eq(monitors.id, alertDeliveries.monitorId))
      .where(and(...filters))
      .orderBy(desc(alertDeliveries.createdAt))
      .limit(50_000);

    return {
      filename,
      rowCount: rows.length,
      csv: toCsv(
        rows.map((row) => [
          row.createdAt.toISOString(),
          row.monitorName ?? '',
          row.eventType,
          row.channelName,
          row.channelType,
          row.status,
          row.attempts,
          row.sentAt ? new Date(row.sentAt).toISOString() : '',
          row.failureCode ?? '',
          row.safeMessage ?? '',
        ]),
        [
          'created_at',
          'monitor',
          'event_type',
          'channel',
          'channel_type',
          'status',
          'attempts',
          'sent_at',
          'failure_code',
          'message',
        ],
      ),
    };
  }

  private async monitorNames(titles: string[]): Promise<Map<string, string>> {
    const rows = await this.db
      .select({ title: incidents.title, name: monitors.name })
      .from(incidentMonitors)
      .innerJoin(incidents, eq(incidents.id, incidentMonitors.incidentId))
      .innerJoin(monitors, eq(monitors.id, incidentMonitors.monitorId));
    const wanted = new Set(titles);
    const map = new Map<string, string[]>();
    for (const row of rows) {
      if (!wanted.has(row.title)) continue;
      const list = map.get(row.title) ?? [];
      list.push(row.name);
      map.set(row.title, list);
    }
    return new Map([...map.entries()].map(([title, names]) => [title, names.join('; ')]));
  }
}