/**
 * The monitor state machine (Part F / F4.6-9, F7).
 *
 * Everything here runs through the real `ProbeService.runCheck` against the
 * real database, so threshold crossing, incident dedupe, resolution and alert
 * queueing are the production code paths.
 *
 * Only the outbound socket is replaced. Targets on `*.stub.test` are answered by
 * a scripted outcome; every other target falls through to the *real* probe, which
 * is how the "a blocked address is never reported as down" case is proven without
 * any outbound network access.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { eq, count } from 'drizzle-orm';
import type { Express } from 'express';

import type { FailureType } from '@sitesentinel/shared';

import { createApp } from '../src/app.js';

function slugify(value: string): string {
  const base = value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return base || 'monitor';
}
import { alertDeliveries, backgroundJobs, incidents, monitorChecks, monitors } from '../src/db/schema.js';
import { drainOnce } from '../src/jobs/worker.js';
import {
  createMonitor,
  createTestContext,
  forceMonitorTarget,
  seedEmailAlertChannel,
  seedTenant,
  type TestContext,
} from './harness.js';

/** Scripted probe results for `*.stub.test` targets. */
const stub = vi.hoisted(() => ({
  result: {
    ok: true as boolean,
    statusCode: 200,
    latencyMs: 14,
    dnsMs: 4,
    responseSizeBytes: 512,
    redirects: 0,
    finalUrl: 'https://checkout.stub.test/',
    failureType: null as FailureType | null,
    safeMessage: 'HTTP 200.',
  },
}));

vi.mock('../src/probe/http.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/probe/http.js')>();
  return {
    PROBE_VERSION: actual.PROBE_VERSION,
    probeHttp: async (request: Parameters<typeof actual.probeHttp>[0]) => {
      // Only scripted hosts are stubbed; everything else is really probed.
      if (new URL(request.target).hostname.endsWith('.stub.test')) {
        return { ...stub.result };
      }
      return actual.probeHttp(request);
    },
  };
});

function stubSuccess(statusCode = 200, latencyMs = 14) {
  stub.result = {
    ok: true,
    statusCode,
    latencyMs,
    dnsMs: 4,
    responseSizeBytes: 512,
    redirects: 0,
    finalUrl: 'https://checkout.stub.test/',
    failureType: null,
    safeMessage: `HTTP ${statusCode}.`,
  };
}

function stubFailure(failureType: FailureType, statusCode: number | null = 503) {
  stub.result = {
    ok: false,
    statusCode,
    latencyMs: 21,
    dnsMs: 3,
    responseSizeBytes: null,
    redirects: 0,
    finalUrl: 'https://checkout.stub.test/',
    failureType,
    safeMessage: `Observed ${failureType}.`,
  };
}

let context: TestContext;
let app: Express;
let tenant: Awaited<ReturnType<typeof seedTenant>>;

beforeAll(async () => {
  context = await createTestContext();
  app = createApp(context.services);
  tenant = await seedTenant(context, {
    email: 'engine@test.local',
    organizationName: 'Engine Tenant',
  });
});

afterAll(async () => {
  await context.close();
});

beforeEach(() => {
  stubSuccess();
});

function stubTarget(name: string) {
  return `https://${slugify(name)}.stub.test/health`;
}

async function newMonitor(name: string, overrides: Parameters<typeof createMonitor>[2] = {}) {
  return createMonitor(context, tenant, {
    name,
    target: stubTarget(name),
    timeoutMs: 2_000,
    intervalSeconds: 300,
    consecutiveFailureThreshold: 2,
    recoverySuccessThreshold: 2,
    ...overrides,
  });
}

async function incidentsFor(_monitorId: string) {
  const rows = await context.handle.db
    .select()
    .from(incidents)
    .where(eq(incidents.organizationId, tenant.organization.id));
  return rows;
}

/* -------------------------------------------------------------------------- */

describe('a brand new monitor is unknown, never healthy', () => {
  it('reports unknown state and a null uptime until a probe has run', async () => {
    const monitor = await newMonitor('Never checked');

    expect(monitor.currentState).toBe('unknown');
    expect(monitor.uptimePercent).toBeNull();
    expect(monitor.checksRecorded).toBe(0);
    expect(monitor.coverage).toBeNull();
    expect(monitor.averageLatencyMs).toBeNull();
    expect(monitor.lastCheckedAt).toBeNull();
    expect(monitor.lastCheck).toBeNull();
    expect(monitor.stale).toBe(true);
    expect(monitor.openIncidentCount).toBe(0);
  });

  it('never counts "no data" as 100% uptime on the dashboard', async () => {
    const response = await agentGet(`/api/v1/${tenant.organization.id}/dashboard/summary`);
    expect(response.status).toBe(200);
    expect(response.body.totalChecks).toBeGreaterThanOrEqual(0);
    expect(response.body.method).toMatch(/never counted as success|No data yet/i);
    const neverChecked = response.body.stateCounts.unknown as number;
    expect(neverChecked).toBeGreaterThanOrEqual(1);
    expect(response.body.stateCounts.up ?? 0).toBe(0);
  });
});

describe('consecutive-failure threshold', () => {
  it('opens exactly one incident, however long the outage lasts', async () => {
    const monitor = await newMonitor('Outage target', { consecutiveFailureThreshold: 3 });
    stubFailure('unexpected_status', 503);

    const first = await context.services.probes.runCheck(monitor.id);
    expect(first.state).toBe('degraded');
    expect(first.incidentId).toBeNull();

    const second = await context.services.probes.runCheck(monitor.id);
    expect(second.state).toBe('degraded');
    expect(second.incidentId).toBeNull();

    const third = await context.services.probes.runCheck(monitor.id);
    expect(third.state).toBe('down');
    expect(third.incidentId).toBeTruthy();

    // Four more failing checks: the same outage, so still exactly one incident.
    let lastIncidentId = third.incidentId;
    for (let index = 0; index < 4; index += 1) {
      const outcome = await context.services.probes.runCheck(monitor.id);
      expect(outcome.state).toBe('down');
      lastIncidentId = outcome.incidentId;
    }

    const rows = await context.handle.db
      .select()
      .from(incidents)
      .where(eq(incidents.dedupeKey, `monitor:${monitor.id}`));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.status).toBe('open');
    expect(rows[0]!.id).toBe(third.incidentId);
    expect(lastIncidentId).toBe(third.incidentId);

    const checks = await context.handle.db
      .select()
      .from(monitorChecks)
      .where(eq(monitorChecks.monitorId, monitor.id));
    expect(checks.length).toBeGreaterThanOrEqual(7);
    expect(checks.every((check) => check.result === 'failure')).toBe(true);
  });

  it('records one check row per probe with a category and no response body', async () => {
    const monitor = await newMonitor('Check rows', { consecutiveFailureThreshold: 1 });
    stubFailure('unexpected_status', 500);
    await context.services.probes.runCheck(monitor.id);

    const rows = await context.handle.db
      .select()
      .from(monitorChecks)
      .where(eq(monitorChecks.monitorId, monitor.id));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.failureType).toBe('unexpected_status');
    expect(rows[0]!.statusCode).toBe(500);
    expect(rows[0]!.probeVersion).toBeTruthy();
    expect(rows[0]!.probeLocation).toBeTruthy();
    expect(rows[0]!.safeMessage).not.toMatch(/<html|<body/i);
  });
});

describe('recovery requires the configured number of successes', () => {
  it('does not resolve on a single success', async () => {
    const monitor = await newMonitor('Flapping target', {
      consecutiveFailureThreshold: 1,
      recoverySuccessThreshold: 2,
    });

    stubFailure('timeout', null);
    const down = await context.services.probes.runCheck(monitor.id);
    expect(down.state).toBe('down');
    const incidentId = down.incidentId!;

    stubSuccess();
    const recoveredOnce = await context.services.probes.runCheck(monitor.id);
    expect(recoveredOnce.state).toBe('up');
    // One success is not enough: the incident must still be open.
    expect((await incidentsFor(monitor.id)).find((row) => row.id === incidentId)?.status).toBe('open');

    stubSuccess();
    await context.services.probes.runCheck(monitor.id);
    const resolved = (await incidentsFor(monitor.id)).find((row) => row.id === incidentId);
    expect(resolved?.status).toBe('resolved');
    expect(resolved?.resolutionReason).toMatch(/2 consecutive successful/i);
    expect(resolved?.resolvedAt).not.toBeNull();
  });

  it('opens a new incident for a new outage after the first one is resolved', async () => {
    const monitor = await newMonitor('Second outage', {
      consecutiveFailureThreshold: 1,
      recoverySuccessThreshold: 1,
    });

    stubFailure('connection_refused', null);
    const first = await context.services.probes.runCheck(monitor.id);

    stubSuccess();
    await context.services.probes.runCheck(monitor.id);

    stubFailure('connection_refused', null);
    const second = await context.services.probes.runCheck(monitor.id);

    expect(second.incidentId).not.toBe(first.incidentId);
    const rows = await context.handle.db
      .select()
      .from(incidents)
      .where(eq(incidents.dedupeKey, `monitor:${monitor.id}`));
    expect(rows).toHaveLength(2);
    expect(rows.filter((row) => row.status === 'resolved')).toHaveLength(1);
  });
});

describe('a probe-infrastructure failure is never "down"', () => {
  it('reports unknown, resets the failure streak and opens no incident', async () => {
    const monitor = await newMonitor('Rebinding target', {
      target: 'https://example.com/',
      consecutiveFailureThreshold: 1,
    });

    // The saved target becomes private after it was accepted (DNS rebinding, or
    // a record that changed on disk). The real probe must refuse it.
    await forceMonitorTarget(context, monitor.id, 'http://127.0.0.1/');

    const outcomes = [];
    for (let index = 0; index < 4; index += 1) {
      outcomes.push(await context.services.probes.runCheck(monitor.id));
    }

    for (const outcome of outcomes) {
      expect(outcome.state).toBe('unknown');
      expect(outcome.result).toBe('failure');
      expect(outcome.failureType).toBe('blocked_address');
      expect(outcome.incidentId).toBeNull();
    }

    const rows = await context.handle.db
      .select()
      .from(monitors)
      .where(eq(monitors.id, monitor.id));
    expect(rows[0]!.consecutiveFailures).toBe(0);
    expect(rows[0]!.currentState).toBe('unknown');

    const incidentRows = await context.handle.db
      .select()
      .from(incidents)
      .where(eq(incidents.organizationId, tenant.organization.id));
    // Nothing at all was opened for this monitor.
    expect(incidentRows.some((row) => row.dedupeKey === `monitor:${monitor.id}`)).toBe(false);
  });

  it('records the refusal as a check so the reason is visible to an operator', async () => {
    const monitor = await newMonitor('Refusal reason', { target: 'https://example.com/' });
    await forceMonitorTarget(context, monitor.id, 'http://169.254.169.254/latest/meta-data/');
    await context.services.probes.runCheck(monitor.id);

    const rows = await context.handle.db
      .select()
      .from(monitorChecks)
      .where(eq(monitorChecks.monitorId, monitor.id));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.failureType).toBe('blocked_address');
    expect(rows[0]!.safeMessage).toMatch(/metadata/i);
  });

  it('backs off instead of hammering a target it cannot probe', async () => {
    const monitor = await newMonitor('Backoff target', {
      target: 'https://example.com/',
      intervalSeconds: 600,
      consecutiveFailureThreshold: 1,
    });
    await forceMonitorTarget(context, monitor.id, 'http://127.0.0.1/');
    await context.services.probes.runCheck(monitor.id);

    const rows = await context.handle.db
      .select()
      .from(monitors)
      .where(eq(monitors.id, monitor.id));
    const next = rows[0]!.nextCheckAt!.getTime();
    // One interval is 600 s; the infrastructure backoff multiplier is at least 2.
    expect(next).toBeGreaterThan(Date.now() + 600_000);
  });
});

describe('a paused monitor never raises a down alert', () => {
  it('closes the incident with an explicit reason instead of leaving it open', async () => {
    const monitor = await newMonitor('Pausing target', { consecutiveFailureThreshold: 1 });
    stubFailure('timeout', null);
    const opened = await context.services.probes.runCheck(monitor.id);
    expect(opened.state).toBe('down');

    await context.services.monitors.setEnabled({
      organizationId: tenant.organization.id,
      monitorId: monitor.id,
      actorUserId: tenant.user.id,
      enabled: false,
      reason: 'Planned maintenance by the operator',
    });

    const rows = await context.handle.db
      .select()
      .from(incidents)
      .where(eq(incidents.id, opened.incidentId!));
    expect(rows[0]!.status).toBe('resolved');
    expect(rows[0]!.resolutionReason).toBe('Planned maintenance by the operator');

    // A paused monitor is not probed at all.
    const outcome = await context.services.probes.runCheck(monitor.id);
    expect(outcome.skipped).toBe(true);
  });
});

describe('maintenance suppresses the alert, not the incident', () => {
  it('records a suppressed delivery and still opens the incident', async () => {
    const monitor = await newMonitor('Maintained target', { consecutiveFailureThreshold: 1 });
    await seedEmailAlertChannel(context, tenant, { monitorId: monitor.id });

    const now = Date.now();
    await context.services.maintenance.create({
      organizationId: tenant.organization.id,
      actorUserId: tenant.user.id,
      name: 'Nightly deploy',
      startsAt: new Date(now - 3_600_000),
      endsAt: new Date(now + 3_600_000),
      timezone: 'UTC',
      recurrence: null,
      reason: 'Deploying release 2.4',
      enabled: true,
      suppressNotifications: true,
      monitorIds: [monitor.id],
    });

    stubFailure('unexpected_status', 502);
    const outcome = await context.services.probes.runCheck(monitor.id);
    expect(outcome.state).toBe('down');
    expect(outcome.incidentId).toBeTruthy();

    const incidentRows = await context.handle.db
      .select()
      .from(incidents)
      .where(eq(incidents.id, outcome.incidentId!));
    expect(incidentRows[0]!.maintenanceWindowId).not.toBeNull();

    const deliveries = await context.handle.db
      .select()
      .from(alertDeliveries)
      .where(eq(alertDeliveries.incidentId, outcome.incidentId!));
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0]!.status).toBe('suppressed');
    expect(deliveries[0]!.safeMessage).toMatch(/maintenance/i);
    // Nothing was queued for delivery, so no job was created either.
    expect(deliveries[0]!.sentAt).toBeNull();

    const jobs = await context.handle.db
      .select()
      .from(backgroundJobs)
      .where(eq(backgroundJobs.jobType, 'alert.deliver'));
    const forThisIncident = jobs.filter(
      (job) => (job.payload as { incidentId?: string } | null)?.incidentId === outcome.incidentId,
    );
    expect(forThisIncident).toHaveLength(0);

    // Checks kept running: the check row exists and was not rewritten.
    const checks = await context.handle.db
      .select()
      .from(monitorChecks)
      .where(eq(monitorChecks.monitorId, monitor.id));
    expect(checks).toHaveLength(1);
    expect(checks[0]!.result).toBe('failure');
  });
});

describe('a failing alert is never recorded as sent', () => {
  it('queues, attempts, and records not_configured without retrying', async () => {
    const monitor = await newMonitor('Alert honesty', { consecutiveFailureThreshold: 1 });
    await seedEmailAlertChannel(context, tenant, { monitorId: monitor.id });

    stubFailure('unexpected_status', 500);
    const outcome = await context.services.probes.runCheck(monitor.id);
    expect(outcome.alertsQueued).toBe(1);

    const delivery = (await context.handle.db
      .select()
      .from(alertDeliveries)
      .where(eq(alertDeliveries.incidentId, outcome.incidentId!)))[0]!;
    expect(delivery.status).toBe('queued');
    expect(delivery.sentAt).toBeNull();

    // Run the real worker pass: one queued job is claimed and executed.
    const handled = await drainOnce(context.services, 'test-worker');
    expect(handled).toBeGreaterThanOrEqual(1);

    const after = (await context.handle.db
      .select()
      .from(alertDeliveries)
      .where(eq(alertDeliveries.id, delivery.id)))[0]!;
    expect(after.sentAt).toBeNull();
    expect(after.failureCode).toBe('not_configured');
    expect(after.attempts).toBe(1);

    const jobs = await context.handle.db
      .select()
      .from(backgroundJobs)
      .where(eq(backgroundJobs.idempotencyKey, `alert-deliver:${delivery.id}`));
    expect(jobs).toHaveLength(1);
    // A permanent configuration problem must not be retried on a backoff loop.
    expect(jobs[0]!.status).not.toBe('queued');

    const counts = await context.handle.db
      .select({ total: count() })
      .from(alertDeliveries)
      .where(eq(alertDeliveries.status, 'sent'));
    expect(counts[0]?.total).toBe(0);
  });

  it('reports "sent" for a webhook only when the endpoint accepts it', async () => {
    const monitor = await newMonitor('Webhook honesty', { consecutiveFailureThreshold: 1 });
    const channel = await context.services.alerts.createChannel({
      organizationId: tenant.organization.id,
      actorUserId: tenant.user.id,
      channel: {
        channelType: 'webhook',
        name: `Webhook ${Math.random().toString(36).slice(2, 8)}`,
        enabled: true,
        recipients: [],
        webhookUrl: 'https://hooks.stub.test/incoming',
      },
    });
    await context.services.alerts.createRule({
      organizationId: tenant.organization.id,
      actorUserId: tenant.user.id,
      rule: {
        monitorId: monitor.id,
        eventType: 'incident_opened',
        channelId: channel.summary.id,
        enabled: true,
        repeatMinutes: null,
        quietHours: null,
      },
    });

    stubFailure('unexpected_status', 500);
    const outcome = await context.services.probes.runCheck(monitor.id);
    await drainOnce(context.services, 'test-worker');

    const after = (await context.handle.db
      .select()
      .from(alertDeliveries)
      .where(eq(alertDeliveries.channelId, channel.summary.id)))[0]!;
    expect(after.status).not.toBe('sent');
    expect(after.sentAt).toBeNull();
    expect(after.failureCode).toBeTruthy();
    expect(outcome.incidentId).toBeTruthy();
  });
});

describe('dashboard never reports a never-checked monitor as healthy', () => {
  it('counts an unknown monitor under unknown, not up', async () => {
    // Ensure a clean slate by archiving any existing monitors
    const existingMonitors = await context.handle.db
      .select({ id: monitors.id })
      .from(monitors)
      .where(eq(monitors.organizationId, tenant.organization.id));
    for (const m of existingMonitors) {
      await context.services.monitors.archive({
        organizationId: tenant.organization.id,
        monitorId: m.id,
        actorUserId: tenant.user.id,
      });
    }

    await newMonitor('Dashboard unknown');
    const response = await agentGet(`/api/v1/${tenant.organization.id}/dashboard/summary`);
    const upCount = response.body.stateCounts.up as number;
    const unknownCount = response.body.stateCounts.unknown as number;
    expect(unknownCount).toBeGreaterThanOrEqual(1);
    expect(upCount).toBe(0);
  });
});

/* -------------------------------------------------------------------------- */

async function agentGet(path: string) {
  const { default: request } = await import('supertest');
  const agent = request.agent(app);
  await agent.post('/api/v1/auth/login').send({ email: 'engine@test.local', password: 'a-very-long-test-password' });
  return agent.get(path);
}