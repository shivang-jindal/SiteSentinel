/**
 * The probe engine (Part F / F4, Part F / F7).
 *
 * This is the only place in the product that performs an outbound check, and
 * it is driven exclusively by the background worker through the database job
 * queue - never by an API request (Part F / F4 "Build a separate worker
 * process").
 *
 * For every enabled monitor, in order:
 *   1. calculate the next due time (`monitors.next_check_at`);
 *   2. claim the monitor with a database lease (`monitor_locks`) so two workers
 *      can never probe the same monitor concurrently;
 *   3. run a bounded request with a strict timeout;
 *   4. validate DNS again and pin the connection address (done inside the
 *      probe modules, re-applied on every redirect);
 *   5. persist result, category, latency, status code and a safe message;
 *   6. update the state using the configured consecutive-failure threshold;
 *   7. open or update an incident on the threshold crossing;
 *   8. queue alert jobs with idempotency keys;
 *   9. resolve the incident after enough consecutive successes;
 *  10. schedule the next check, with backoff for probe-infrastructure failures.
 *
 * A probe-infrastructure failure (blocked address, invalid target, DNS
 * problem) never counts towards "down": it reports `unknown`, because a probe
 * that could not run says nothing about the target (Part F / F4.11, F7).
 */

import { and, asc, eq, isNull, lte, or, sql } from 'drizzle-orm';

import type { FailureType, MonitorState } from '@sitesentinel/shared';
import {
  ALLOWED_HTTP_PORTS,
  ALLOWED_TCP_PORTS,
  MAX_KEYWORD_BODY_BYTES,
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  PROBE_INFRASTRUCTURE_FAILURES,
  checkHostnameTarget,
  hostnameFromUrl,
  normalizeHostname,
} from '@sitesentinel/shared';
import type { Logger } from 'pino';

import type { AppDatabase } from '../db/client.js';
import {
  domainChecks,
  monitorChecks,
  monitorLocks,
  monitors,
  type Monitor,
} from '../db/schema.js';
import { PROBE_VERSION, probeHttp } from '../probe/http.js';
import { probeSsl } from '../probe/ssl.js';
import { probeTcp } from '../probe/tcp.js';
import type { AlertService } from './alert.service.js';
import type { IncidentService } from './incident.service.js';
import type { MaintenanceService } from './maintenance.service.js';
import { warningLevelFor } from './monitor.service.js';
import type { OrganizationService } from './organization.service.js';

export interface CheckOutcome {
  monitorId: string;
  state: MonitorState;
  result: 'success' | 'failure';
  failureType: FailureType | null;
  incidentId: string | null;
  alertsQueued: number;
  skipped: boolean;
}

interface Observation {
  result: 'success' | 'failure';
  failureType: FailureType | null;
  safeMessage: string;
  statusCode: number | null;
  latencyMs: number | null;
  dnsMs: number | null;
  responseSizeBytes: number | null;
  tlsExpiresAt: Date | null;
  tlsIssuer: string | null;
  tlsSubject: string | null;
  tlsSerialNumber: string | null;
  tlsProtocol: string | null;
  tlsChainValid: boolean | null;
  tlsChainError: string | null;
  tlsSelfSigned: boolean | null;
}

const LEASE_MS = 60_000;

export class ProbeService {
  readonly maxRedirects = MAX_REDIRECTS;
  readonly maxResponseBytes = MAX_RESPONSE_BYTES;
  readonly allowedHttpPorts = ALLOWED_HTTP_PORTS;
  readonly allowedTcpPorts = ALLOWED_TCP_PORTS;

  private readonly workerId = `probe-${process.pid}`;

  constructor(
    private readonly db: AppDatabase,
    private readonly incidents: IncidentService,
    private readonly alerts: AlertService,
    private readonly maintenance: MaintenanceService,
    private readonly organizations: OrganizationService,
    private readonly logger: Logger,
  ) {}

  /* ---------------------------------------------------------------------- */
  /* Health                                                                  */
  /* ---------------------------------------------------------------------- */

  /**
   * Platform-level status of the probe worker itself. An unhealthy worker is a
   * warning on the dashboard - it never marks monitors down (Part F / F4.11).
   */
  async health(): Promise<{ detail: string }> {
    const stale = new Date(Date.now() - LEASE_MS * 2);
    const rows = await this.db
      .select({ total: sql<number>`count(*)::int` })
      .from(monitors)
      .where(and(sql`${monitors.enabled} = true`, isNull(monitors.archivedAt)));
    const enabled = rows[0]?.total ?? 0;

    const locked = await this.db
      .select({ total: sql<number>`count(*)::int` })
      .from(monitorLocks)
      .where(sql`${monitorLocks.leaseExpiresAt} > now()`);

    const last = await this.db
      .select({ at: sql<Date>`max(${monitorChecks.checkedAt})` })
      .from(monitorChecks)
      .where(sql`${monitorChecks.checkedAt} > ${stale}`);

    const lastCheck = last[0]?.at ?? null;
    if (enabled === 0) {
      return { detail: `${enabled} enabled monitors. Nothing to check yet.` };
    }
    if (!lastCheck) {
      return {
        detail: `${enabled} enabled monitors and no check recorded in the last ${Math.round(LEASE_MS * 2 / 1000)}s. Run the worker process (npm run dev:worker).`,
      };
    }
    return {
      detail: `${enabled} enabled monitors, ${locked[0]?.total ?? 0} leased, last check ${new Date(lastCheck).toISOString()}.`,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Dispatch                                                                */
  /* ---------------------------------------------------------------------- */

  /** Probes every monitor whose `next_check_at` has passed. Worker-only. */
  async dispatchDue(limit = 50): Promise<{ checked: number; skipped: number }> {
    const now = new Date();
    const due = await this.db
      .select({
        id: monitors.id,
        organizationId: monitors.organizationId,
      })
      .from(monitors)
      .where(
        and(
          eq(monitors.enabled, true),
          isNull(monitors.archivedAt),
          or(isNull(monitors.nextCheckAt), lte(monitors.nextCheckAt, now)),
        ),
      )
      .orderBy(asc(monitors.nextCheckAt))
      .limit(limit);

    let checked = 0;
    let skipped = 0;
    for (const candidate of due) {
      const claimed = await this.claimLease(candidate.id, candidate.organizationId);
      if (!claimed) {
        skipped += 1;
        continue;
      }
      try {
        await this.runCheck(candidate.id);
        checked += 1;
      } catch (error) {
        skipped += 1;
        this.logger.error(
          { err: error, monitorId: candidate.id },
          'probe failed to run; the monitor is not marked down for an engine error',
        );
      } finally {
        await this.releaseLease(candidate.id);
      }
    }
    return { checked, skipped };
  }

  /* ---------------------------------------------------------------------- */
  /* One check                                                               */
  /* ---------------------------------------------------------------------- */

  async runCheck(monitorId: string): Promise<CheckOutcome> {
    const rows = await this.db.select().from(monitors).where(eq(monitors.id, monitorId)).limit(1);
    const monitor = rows[0];
    if (!monitor || !monitor.enabled || monitor.archivedAt) {
      return {
        monitorId,
        state: monitor?.currentState ? (monitor.currentState as MonitorState) : 'unknown',
        result: 'failure',
        failureType: null,
        incidentId: null,
        alertsQueued: 0,
        skipped: true,
      };
    }

    const settings = await this.organizations.getSettings(monitor.organizationId);
    const observation = await this.observe(monitor, Math.min(monitor.timeoutMs, 60_000), settings.maxResponseBytes);
    const checkedAt = observation.checkedAt;

    const infrastructureFailure =
      observation.failureType !== null && PROBE_INFRASTRUCTURE_FAILURES.includes(observation.failureType);

    const insertedCheck = await this.db
      .insert(monitorChecks)
      .values({
        organizationId: monitor.organizationId,
        monitorId: monitor.id,
        checkedAt,
        finishedAt: new Date(),
        result: observation.result,
        failureType: observation.failureType,
        statusCode: observation.statusCode,
        latencyMs: observation.latencyMs,
        dnsMs: observation.dnsMs,
        tlsExpiryAt: observation.tlsExpiresAt,
        tlsIssuer: observation.tlsIssuer,
        tlsSubject: observation.tlsSubject,
        tlsSerialNumber: observation.tlsSerialNumber,
        tlsProtocol: observation.tlsProtocol,
        tlsChainValid: observation.tlsChainValid,
        tlsChainError: observation.tlsChainError,
        tlsSelfSigned: observation.tlsSelfSigned,
        responseSizeBytes: observation.responseSizeBytes,
        safeMessage: observation.safeMessage,
        probeLocation: settings.probeLocationLabel,
        probeVersion: PROBE_VERSION,
      })
      .returning({ id: monitorChecks.id });
    const checkId = insertedCheck[0]?.id ?? null;

    /* ---- state machine ---- */
    const succeeded = observation.result === 'success';
    const consecutiveFailures = succeeded ? 0 : infrastructureFailure ? 0 : monitor.consecutiveFailures + 1;
    const consecutiveSuccesses = succeeded ? monitor.consecutiveSuccesses + 1 : 0;

    let state: MonitorState;
    if (!monitor.enabled) state = 'paused';
    else if (infrastructureFailure) state = 'unknown';
    else if (succeeded) state = 'up';
    else state = consecutiveFailures >= monitor.consecutiveFailureThreshold ? 'down' : 'degraded';

    // Backoff only for probe-infrastructure failures: the target is fine, our
    // own probe is failing, so hammering it is pointless.
    const backoffMultiplier = infrastructureFailure ? Math.min(4, 2 ** Math.min(consecutiveFailures + 1, 2)) : 1;
    const nextCheckAt = new Date(Date.now() + monitor.intervalSeconds * backoffMultiplier * 1_000);

    await this.db
      .update(monitors)
      .set({
        currentState: state,
        consecutiveFailures,
        consecutiveSuccesses,
        lastCheckedAt: checkedAt,
        nextCheckAt,
        lastLatencyMs: observation.latencyMs,
        updatedAt: new Date(),
      })
      .where(eq(monitors.id, monitor.id));

    /* ---- incidents and alerts ---- */
    let incidentId: string | null = null;
    let alertsQueued = 0;

    const window = await this.maintenance.suppressingWindowForMonitor(
      monitor.organizationId,
      monitor.id,
      checkedAt,
    );

    if (!succeeded && !infrastructureFailure && consecutiveFailures >= monitor.consecutiveFailureThreshold) {
      const opened = await this.incidents.openForMonitor({
        organizationId: monitor.organizationId,
        monitorId: monitor.id,
        monitorName: monitor.name,
        checkId,
        failureType: observation.failureType,
        safeMessage: observation.safeMessage,
        maintenanceWindowId: window?.id ?? null,
      });
      incidentId = opened.incidentId;
      if (opened.created) {
        alertsQueued += await this.alerts.queueForIncident({
          organizationId: monitor.organizationId,
          incidentId: opened.incidentId,
          monitorId: monitor.id,
          eventType: 'incident_opened',
        });
      }
    } else if (succeeded && consecutiveSuccesses >= monitor.recoverySuccessThreshold) {
      const resolved = await this.incidents.resolveForMonitor({
        organizationId: monitor.organizationId,
        monitorId: monitor.id,
        checkId,
        reason: `Recovered after ${consecutiveSuccesses} consecutive successful check(s).`,
      });
      if (resolved) {
        incidentId = resolved.incidentId;
        alertsQueued += await this.alerts.queueForIncident({
          organizationId: monitor.organizationId,
          incidentId: resolved.incidentId,
          monitorId: monitor.id,
          eventType: 'incident_resolved',
        });
      }
    }

    /* ---- certificate expiry warnings ---- */
    if (monitor.monitorType === 'ssl_certificate' && observation.tlsExpiresAt) {
      const daysRemaining = Math.floor((observation.tlsExpiresAt.getTime() - checkedAt.getTime()) / 86_400_000);
      const level = warningLevelFor(daysRemaining);
      if (level !== null && observation.failureType === null) {
        const host = hostnameOf(monitor) ?? monitor.targetUrlOrHost;
        alertsQueued += await this.alerts.queueForCertificate({
          organizationId: monitor.organizationId,
          monitorId: monitor.id,
          monitorName: monitor.name,
          host,
          expiresAt: observation.tlsExpiresAt.toISOString(),
          daysRemaining,
          warningLevelDays: level,
        });
      }
    }

    /* ---- domain expiry: truthful "unavailable" ---- */
    if (monitor.monitorType === 'domain_expiry') {
      await this.db.insert(domainChecks).values({
        organizationId: monitor.organizationId,
        monitorId: monitor.id,
        source: null,
        checkedAt,
        status: 'unavailable',
        safeMessage:
          'SiteSentinel ships without an RDAP or WHOIS data source, so no expiry date was retrieved and none is estimated.',
      });
    }

    await this.pruneExpiredLocks(monitor.organizationId);

    return {
      monitorId: monitor.id,
      state,
      result: observation.result,
      failureType: observation.failureType,
      incidentId,
      alertsQueued,
      skipped: false,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Probes                                                                  */
  /* ---------------------------------------------------------------------- */

  private async observe(
    monitor: Monitor,
    timeoutMs: number,
    maxResponseBytes: number,
  ): Promise<Observation & { checkedAt: Date }> {
    const checkedAt = new Date();

    if (monitor.monitorType === 'http' || monitor.monitorType === 'http_keyword') {
      const outcome = await probeHttp({
        type: monitor.monitorType,
        target: monitor.targetUrlOrHost,
        timeoutMs,
        expectedStatusCodes: monitor.expectedStatusCodes.length > 0 ? monitor.expectedStatusCodes : [200],
        keywordMatch: monitor.keywordMatch,
        maxBodyBytes: Math.min(MAX_KEYWORD_BODY_BYTES, maxResponseBytes),
      });
      if (outcome.ok) {
        return {
          checkedAt,
          result: 'success',
          failureType: null,
          safeMessage: outcome.safeMessage,
          statusCode: outcome.statusCode,
          latencyMs: outcome.latencyMs,
          dnsMs: outcome.dnsMs,
          responseSizeBytes: outcome.responseSizeBytes,
          tlsExpiresAt: null,
          tlsIssuer: null,
          tlsSubject: null,
          tlsSerialNumber: null,
          tlsProtocol: null,
          tlsChainValid: null,
          tlsChainError: null,
          tlsSelfSigned: null,
        };
      }
      return {
        checkedAt,
        result: 'failure',
        failureType: outcome.failureType,
        safeMessage: outcome.safeMessage,
        statusCode: outcome.statusCode,
        latencyMs: outcome.latencyMs,
        dnsMs: outcome.dnsMs,
        responseSizeBytes: outcome.responseSizeBytes,
        tlsExpiresAt: null,
        tlsIssuer: null,
        tlsSubject: null,
        tlsSerialNumber: null,
        tlsProtocol: null,
        tlsChainValid: null,
        tlsChainError: null,
        tlsSelfSigned: null,
      };
    }

    if (monitor.monitorType === 'tcp') {
      const outcome = await probeTcp({ type: 'tcp', target: monitor.targetUrlOrHost, timeoutMs });
      return {
        checkedAt,
        result: outcome.ok ? 'success' : 'failure',
        failureType: outcome.failureType,
        safeMessage: outcome.safeMessage,
        statusCode: null,
        latencyMs: outcome.latencyMs,
        dnsMs: outcome.dnsMs,
        responseSizeBytes: null,
        tlsExpiresAt: null,
        tlsIssuer: null,
        tlsSubject: null,
        tlsSerialNumber: null,
        tlsProtocol: null,
        tlsChainValid: null,
        tlsChainError: null,
        tlsSelfSigned: null,
      };
    }

    if (monitor.monitorType === 'ssl_certificate') {
      const host = hostnameOf(monitor);
      if (!host) {
        return {
          checkedAt,
          result: 'failure',
          failureType: 'invalid_target',
          safeMessage: 'This SSL monitor has no valid hostname configured.',
          statusCode: null,
          latencyMs: null,
          dnsMs: null,
          responseSizeBytes: null,
          tlsExpiresAt: null,
          tlsIssuer: null,
          tlsSubject: null,
          tlsSerialNumber: null,
          tlsProtocol: null,
          tlsChainValid: null,
          tlsChainError: null,
          tlsSelfSigned: null,
        };
      }
      const outcome = await probeSsl({ host, port: 443, timeoutMs });
      return {
        checkedAt,
        result: outcome.available && outcome.failureType === null ? 'success' : 'failure',
        failureType: outcome.failureType,
        safeMessage: outcome.safeMessage,
        statusCode: null,
        latencyMs: outcome.latencyMs,
        dnsMs: null,
        responseSizeBytes: null,
        tlsExpiresAt: outcome.expiresAt,
        tlsIssuer: outcome.issuer,
        tlsSubject: outcome.subject,
        tlsSerialNumber: outcome.serialNumber,
        tlsProtocol: outcome.protocol,
        tlsChainValid: outcome.chainValid,
        tlsChainError: outcome.chainError,
        tlsSelfSigned: outcome.selfSigned,
      };
    }

    // domain_expiry cannot be created today; if one exists it must report
    // "unavailable" rather than an invented expiry date (Part F / F1).
    return {
      checkedAt,
      result: 'failure',
      failureType: 'invalid_target',
      safeMessage:
        'Domain expiry monitoring has no RDAP or WHOIS data source configured, so no expiry date is reported.',
      statusCode: null,
      latencyMs: null,
      dnsMs: null,
      responseSizeBytes: null,
      tlsExpiresAt: null,
      tlsIssuer: null,
      tlsSubject: null,
      tlsSerialNumber: null,
      tlsProtocol: null,
      tlsChainValid: null,
      tlsChainError: null,
      tlsSelfSigned: null,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Leases                                                                  */
  /* ---------------------------------------------------------------------- */

  /**
   * One atomic statement: take the lease when it is free or expired, and take
   * nothing when another worker still holds it. Returns `false` when skipped.
   */
  private async claimLease(monitorId: string, organizationId: string): Promise<boolean> {
    const result = await this.db.execute<{ monitor_id: string }>(sql`
      INSERT INTO monitor_locks (monitor_id, organization_id, worker_id, lease_expires_at, acquired_at)
      VALUES (${monitorId}, ${organizationId}, ${this.workerId}, now() + (${LEASE_MS} * interval '1 millisecond'), now())
      ON CONFLICT (monitor_id) DO UPDATE
        SET worker_id = EXCLUDED.worker_id,
            lease_expires_at = EXCLUDED.lease_expires_at,
            acquired_at = now()
        WHERE monitor_locks.lease_expires_at < now()
      RETURNING monitor_id
    `);
    return (result.rows[0]?.monitor_id ?? null) !== null;
  }

  private async releaseLease(monitorId: string): Promise<void> {
    await this.db
      .delete(monitorLocks)
      .where(and(eq(monitorLocks.monitorId, monitorId), eq(monitorLocks.workerId, this.workerId)));
  }

  private async pruneExpiredLocks(organizationId: string): Promise<void> {
    await this.db
      .delete(monitorLocks)
      .where(
        and(
          eq(monitorLocks.organizationId, organizationId),
          lte(monitorLocks.leaseExpiresAt, new Date()),
        ),
      );
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

export function hostnameOf(monitor: Monitor): string | null {
  if (monitor.monitorType === 'http' || monitor.monitorType === 'http_keyword') {
    return hostnameFromUrl(monitor.targetUrlOrHost);
  }
  const raw = monitor.targetUrlOrHost.trim();
  if (monitor.monitorType === 'tcp') {
    const withoutPort = raw.startsWith('[')
      ? raw.slice(1, raw.indexOf(']'))
      : raw.includes(':') && raw.indexOf(':') === raw.lastIndexOf(':')
        ? raw.slice(0, raw.lastIndexOf(':'))
        : raw;
    const checked = checkHostnameTarget(withoutPort);
    return checked.ok ? checked.hostname : normalizeHostname(withoutPort);
  }
  const checked = checkHostnameTarget(raw);
  return checked.ok ? checked.hostname : null;
}