/**
 * Development / demo seed (`npm run db:seed`).
 *
 * Seed data is only ever created by this explicit command (Part A / A4.5). A
 * production account always starts empty.
 *
 * The demo organization deliberately targets only real, publicly reachable
 * hosts. Nothing here fabricates a check result: probes are performed by the
 * worker, exactly as they are in production.
 */

import { eq } from 'drizzle-orm';

import { loadConfig } from '../config.js';
import { createDatabase, runMigrations } from './client.js';
import { createServices } from '../container.js';
import { createLogger } from '../logger.js';
import { users } from './schema.js';

const DEMO_EMAIL = process.env.SEED_EMAIL ?? 'demo@sitesentinel.test';
const DEMO_PASSWORD = process.env.SEED_PASSWORD ?? 'sitesentinel-demo-1234';

async function main(): Promise<void> {
  const config = loadConfig();
  if (config.isProduction) {
    throw new Error(
      'Refusing to seed a production database. Run the seed command against a development database.',
    );
  }

  const database = await createDatabase({
    databaseUrl: config.databaseUrl,
    pgliteDataDir: config.pgliteDataDir,
  });
  await runMigrations(database);

  const logger = createLogger({ level: 'info', isProduction: false, name: 'seed' });
  const services = createServices({ db: database.db, config, logger });

  try {
    const existing = await database.db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, DEMO_EMAIL))
      .limit(1);

    if (existing[0]) {
      console.log(`[db:seed] ${DEMO_EMAIL} already exists; nothing to do.`);
      return;
    }

    const { user } = await services.auth.register({
      email: DEMO_EMAIL,
      password: DEMO_PASSWORD,
      displayName: 'Demo Owner',
    });

    const organization = await services.organizations.create({
      name: 'Demo Operations',
      countryCode: 'US',
      timezone: 'America/New_York',
      baseCurrency: 'USD',
      ownerId: user.id,
    });

    await services.organizations.updateSettings(organization.id, user.id, {
      defaultIntervalSeconds: 300,
      minIntervalSeconds: 60,
      consecutiveFailureThreshold: 2,
      recoverySuccessThreshold: 2,
      probeLocationLabel: 'demo-region',
    });

    const defaults = await services.organizations.defaults(organization.id);

    const created = await services.monitors.create({
      organizationId: organization.id,
      actorUserId: user.id,
      minIntervalSeconds: defaults.minIntervalSeconds,
      maxMonitors: defaults.maxMonitors,
      defaultIntervalSeconds: defaults.intervalSeconds,
      defaultTimeoutMs: defaults.timeoutMs,
      defaultFailureThreshold: defaults.consecutiveFailureThreshold,
      defaultRecoveryThreshold: defaults.recoverySuccessThreshold,
      monitor: {
        monitorType: 'http',
        name: 'example.com (demo)',
        target: 'https://example.com/',
        intervalSeconds: 300,
        timeoutMs: 10_000,
        enabled: true,
        tags: ['demo', 'website'],
        expectedStatusCodes: [200],
        consecutiveFailureThreshold: 2,
        recoverySuccessThreshold: 2,
      },
    });

    const keyword = await services.monitors.create({
      organizationId: organization.id,
      actorUserId: user.id,
      minIntervalSeconds: defaults.minIntervalSeconds,
      maxMonitors: defaults.maxMonitors,
      defaultIntervalSeconds: defaults.intervalSeconds,
      defaultTimeoutMs: defaults.timeoutMs,
      defaultFailureThreshold: defaults.consecutiveFailureThreshold,
      defaultRecoveryThreshold: defaults.recoverySuccessThreshold,
      monitor: {
        monitorType: 'http_keyword',
        name: 'example.com keyword (demo)',
        target: 'https://example.com/',
        intervalSeconds: 600,
        timeoutMs: 10_000,
        enabled: true,
        tags: ['demo'],
        expectedStatusCodes: [200],
        keywordMatch: 'Example Domain',
        consecutiveFailureThreshold: 3,
        recoverySuccessThreshold: 2,
      },
    });

    const certificate = await services.monitors.create({
      organizationId: organization.id,
      actorUserId: user.id,
      minIntervalSeconds: defaults.minIntervalSeconds,
      maxMonitors: defaults.maxMonitors,
      defaultIntervalSeconds: defaults.intervalSeconds,
      defaultTimeoutMs: defaults.timeoutMs,
      defaultFailureThreshold: defaults.consecutiveFailureThreshold,
      defaultRecoveryThreshold: defaults.recoverySuccessThreshold,
      monitor: {
        monitorType: 'ssl_certificate',
        name: 'example.com certificate (demo)',
        target: 'example.com',
        intervalSeconds: 21_600,
        timeoutMs: 10_000,
        enabled: true,
        tags: ['demo', 'ssl'],
        consecutiveFailureThreshold: 2,
        recoverySuccessThreshold: 1,
      },
    });

    const page = await services.statusPages.create({
      organizationId: organization.id,
      actorUserId: user.id,
      maxStatusPages: defaults.maxStatusPages,
      page: {
        title: 'Demo Operations status',
        description: 'Public availability of the demo services.',
        logoUrl: null,
        published: false,
        customDomain: null,
        monitors: [
          { monitorId: created.id, publicLabel: 'Website', sortOrder: 0 },
          { monitorId: keyword.id, publicLabel: 'Content check', sortOrder: 1 },
          { monitorId: certificate.id, publicLabel: 'TLS certificate', sortOrder: 2 },
        ],
      },
    });

    console.log('[db:seed] demo workspace created.');
    console.log(`           email:        ${DEMO_EMAIL}`);
    console.log(`           password:     ${DEMO_PASSWORD}`);
    console.log(`           organization: ${organization.name} (${organization.slug})`);
    console.log(`           monitors:     ${created.id}, ${keyword.id}, ${certificate.id}`);
    console.log(`           status page:  ${page.slug} (unpublished - publish it in Settings > Status page)`);
    console.log('');
    console.log('No check results were invented. Run the worker to perform real probes:');
    console.log('           npm run dev:worker');
  } finally {
    await database.close();
  }
}

main().catch((error: unknown) => {
  console.error('[db:seed] failed:', error instanceof Error ? error.message : error);
  process.exitCode = 1;
});