/**
 * Test harness.
 *
 * Every integration test runs against a real PostgreSQL engine (PGlite) with the
 * production migrations applied, so schema, constraints, transactions and
 * tenant scoping behave exactly as they will in production.
 *
 * Nothing here talks to the public internet. The probe engine is exercised
 * either against targets it must refuse (loopback, link-local, RFC1918,
 * unsupported protocol) or with the outbound socket swapped for a controlled
 * stub - see `probe.test.ts` and `engine.test.ts`.
 */

import type { Express } from 'express';
import { sql } from 'drizzle-orm';
import request from 'supertest';

import { loadConfig, type AppConfig } from '../src/config.js';
import { createServices, type Services } from '../src/container.js';
import { createDatabase, runMigrations, type DatabaseHandle } from '../src/db/client.js';
import { createLogger } from '../src/logger.js';

export const TEST_PASSWORD = 'a-very-long-test-password';

/**
 * Test-only 32-byte key. It exists so the encrypted-alert-channel path can be
 * covered; it is never used outside the in-memory test database. Pass
 * `ENCRYPTION_KEY: ''` to `createTestContext` to exercise the unconfigured
 * path instead.
 */
export const TEST_ENCRYPTION_KEY = '9f'.repeat(32);

export interface TestContext {
  handle: DatabaseHandle;
  services: Services;
  config: AppConfig;
  close: () => Promise<void>;
}

export async function createTestContext(
  overrides: Record<string, string> = {},
): Promise<TestContext> {
  const config = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    EMAIL_PROVIDER: 'disabled',
    WORKER_ENABLED: 'false',
    SESSION_COOKIE_NAME: 'sitesentinel_test',
    ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
    // Generous budgets: several tests deliberately hammer auth and public routes.
    RATE_LIMIT_MAX: '100000',
    AUTH_RATE_LIMIT_MAX: '100000',
    ...overrides,
  } as NodeJS.ProcessEnv);

  const handle = await createDatabase({ memory: true });
  await runMigrations(handle);

  const services = createServices({
    db: handle.db,
    config,
    logger: createLogger({ level: 'silent', isProduction: false, name: 'test' }),
  });

  return {
    handle,
    services,
    config,
    close: async () => {
      await handle.close();
    },
  };
}

export interface SeededTenant {
  user: { id: string; email: string; displayName: string | null };
  organization: { id: string; name: string; slug: string };
}

export async function seedTenant(
  context: TestContext,
  input: { email: string; organizationName: string; password?: string; timezone?: string },
): Promise<SeededTenant> {
  const password = input.password ?? TEST_PASSWORD;
  const { user } = await context.services.auth.register({
    email: input.email,
    password,
    displayName: 'Test Owner',
  });
  const organization = await context.services.organizations.create({
    name: input.organizationName,
    countryCode: 'US',
    timezone: input.timezone ?? 'UTC',
    baseCurrency: 'USD',
    ownerId: user.id,
  });
  return { user, organization };
}

/** A signed-in supertest agent, as the browser would have after `/auth/login`. */
export async function loginAgent(
  app: Express,
  email: string,
  password = TEST_PASSWORD,
): Promise<request.Agent> {
  const agent = request.agent(app);
  await agent.post('/api/v1/auth/login').send({ email, password }).expect(200);
  return agent;
}

/**
 * Creates a monitor through the real service layer, filling every required
 * field from the organization's stored defaults so tests only state what they
 * actually care about.
 */
export async function createMonitor(
  context: TestContext,
  tenant: SeededTenant,
  overrides: Partial<{
    monitorType: 'http' | 'http_keyword' | 'tcp' | 'ssl_certificate';
    target: string;
    name: string;
    intervalSeconds: number;
    timeoutMs: number;
    expectedStatusCodes: number[] | null;
    keywordMatch: string | null;
    consecutiveFailureThreshold: number;
    recoverySuccessThreshold: number;
    enabled: boolean;
    tags: string[];
  }> = {},
) {
  const defaults = await context.services.organizations.defaults(tenant.organization.id);
  return context.services.monitors.create({
    organizationId: tenant.organization.id,
    actorUserId: tenant.user.id,
    minIntervalSeconds: defaults.minIntervalSeconds,
    maxMonitors: defaults.maxMonitors,
    defaultIntervalSeconds: defaults.intervalSeconds,
    defaultTimeoutMs: defaults.timeoutMs,
    defaultFailureThreshold: defaults.consecutiveFailureThreshold,
    defaultRecoveryThreshold: defaults.recoverySuccessThreshold,
    monitor: {
      monitorType: overrides.monitorType ?? 'http',
      target: overrides.target ?? 'https://example.com/',
      name: overrides.name ?? 'Test Monitor',
      intervalSeconds: overrides.intervalSeconds ?? defaults.intervalSeconds,
      timeoutMs: overrides.timeoutMs ?? defaults.timeoutMs,
      enabled: overrides.enabled ?? true,
      tags: overrides.tags ?? [],
      expectedStatusCodes:
        overrides.expectedStatusCodes === undefined ? [200] : overrides.expectedStatusCodes,
      ...(overrides.keywordMatch !== undefined ? { keywordMatch: overrides.keywordMatch } : {}),
      consecutiveFailureThreshold: overrides.consecutiveFailureThreshold ?? defaults.consecutiveFailureThreshold,
      recoverySuccessThreshold: overrides.recoverySuccessThreshold ?? defaults.recoverySuccessThreshold,
    },
  });
}

/**
 * Rewrites a monitor's stored target directly.
 *
 * Used to model a target that has *become* private (DNS rebinding, a record that
 * changed after it was saved) - the probe must still refuse to reach it. The
 * API refuses such a target at creation time; this bypasses that so the probe
 * engine's own defence can be tested.
 */
export async function forceMonitorTarget(
  context: TestContext,
  monitorId: string,
  target: string,
): Promise<void> {
  await context.handle.db.execute(sql`
    UPDATE monitors SET target_url_or_host = ${target} WHERE id = ${monitorId}
  `);
}

/** Creates an enabled email alert channel plus one `incident_opened` rule. */
export async function seedEmailAlertChannel(
  context: TestContext,
  tenant: SeededTenant,
  options: { name?: string; monitorId?: string | null; repeatMinutes?: number | null } = {},
): Promise<{ channelId: string; ruleId: string }> {
  const { summary } = await context.services.alerts.createChannel({
    organizationId: tenant.organization.id,
    actorUserId: tenant.user.id,
    channel: {
      channelType: 'email',
      name: options.name ?? `Email channel ${Math.random().toString(36).slice(2, 8)}`,
      enabled: true,
      recipients: ['oncall@sitesentinel.test'],
      webhookUrl: null,
    },
  });
  const rule = await context.services.alerts.createRule({
    organizationId: tenant.organization.id,
    actorUserId: tenant.user.id,
    rule: {
      monitorId: options.monitorId ?? null,
      eventType: 'incident_opened',
      channelId: summary.id,
      enabled: true,
      repeatMinutes: options.repeatMinutes ?? null,
      quietHours: null,
    },
  });
  return { channelId: summary.id, ruleId: rule.id };
}