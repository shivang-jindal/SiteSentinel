/**
 * SSRF defence (Part A / A5, Part F / F7).
 *
 * This is the single most important security rule in the product: a monitor is
 * a URL fetcher driven by the server, so a user must never be able to point it
 * at loopback, RFC1918, link-local or cloud-metadata addresses.
 *
 * Everything here runs without outbound internet access: the blocked targets are
 * refused by the parser itself, before any socket is opened.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { count, eq } from 'drizzle-orm';
import type { Express } from 'express';
import request from 'supertest';

import {
  ALLOWED_HTTP_PORTS,
  ALLOWED_TCP_PORTS,
  checkHostnameTarget,
  checkHttpTarget,
  checkTcpTarget,
  classifyAddress,
} from '@sitesentinel/shared';

import { createApp } from '../src/app.js';
import { monitors as monitorsTable } from '../src/db/schema.js';
import { createTestContext, loginAgent, seedTenant, type TestContext } from './harness.js';

let context: TestContext;
let app: Express;
let tenant: Awaited<ReturnType<typeof seedTenant>>;
let agent: request.Agent;

beforeAll(async () => {
  context = await createTestContext();
  app = createApp(context.services);
  tenant = await seedTenant(context, { email: 'ssrf@test.local', organizationName: 'SSRF Tenant' });
  agent = await loginAgent(app, 'ssrf@test.local');
});

afterAll(async () => {
  await context.close();
});

/* -------------------------------------------------------------------------- */
/* Address classification                                                       */
/* -------------------------------------------------------------------------- */

describe('address classification', () => {
  const blocked: Array<[string, RegExp]> = [
    ['127.0.0.1', /loopback/i],
    ['127.1.2.3', /loopback/i],
    ['10.0.0.5', /private IPv4 range 10\.0\.0\.0\/8/i],
    ['172.16.9.9', /private IPv4 range 172\.16\.0\.0\/12/i],
    ['192.168.1.10', /private IPv4 range 192\.168\.0\.0\/16/i],
    ['169.254.169.254', /metadata/i],
    ['169.254.1.1', /link-local/i],
    ['100.64.0.1', /carrier-grade NAT/i],
    ['0.0.0.0', /unspecified/i],
    ['192.0.2.10', /documentation/i],
    ['198.18.0.1', /benchmark/i],
    ['224.0.0.1', /multicast/i],
    ['255.255.255.255', /reserved/i],
    ['::1', /loopback/i],
    ['::', /unspecified/i],
    ['fe80::1', /link-local/i],
    ['fc00::1', /unique-local/i],
    ['fd00:ec2::254', /metadata/i],
    ['2001:db8::1', /documentation/i],
    ['ff02::1', /multicast/i],
    ['::ffff:127.0.0.1', /IPv4-mapped/i],
    ['::ffff:10.0.0.1', /IPv4-mapped/i],
    ['64:ff9b::127.0.0.1', /NAT64/i],
    ['2002:7f00:0001::', /6to4/i],
  ];

  it.each(blocked)('refuses %s with an explanation', (address, reason) => {
    const verdict = classifyAddress(address);
    expect(verdict.allowed).toBe(false);
    expect(verdict.category).not.toBe('public');
    expect(verdict.reason).toMatch(reason);
  });

  it.each(['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111'])(
    'allows the globally routable address %s',
    (address) => {
      const verdict = classifyAddress(address);
      expect(verdict.allowed).toBe(true);
      expect(verdict.category).toBe('public');
      expect(verdict.reason).toBeNull();
    },
  );

  it('rejects octal-looking IPv4 values instead of normalising them', () => {
    // `0177.0.0.1` is 127.0.0.1 for some parsers and a hostname for others.
    expect(classifyAddress('0177.0.0.1').allowed).toBe(false);
  });
});

/* -------------------------------------------------------------------------- */
/* Target validation                                                            */
/* -------------------------------------------------------------------------- */

describe('http target validation', () => {
  it('refuses loopback, link-local, private and metadata literals', () => {
    for (const target of [
      'http://127.0.0.1/',
      'http://127.0.0.1:8080/health',
      'http://169.254.169.254/latest/meta-data/iam/',
      'http://169.254.170.2/',
      'http://100.100.100.200/',
      'http://10.0.0.1/',
      'http://172.20.0.1/',
      'http://192.168.0.1/',
      'http://[::1]/',
      'http://[fd00::1]/',
      'http://[::ffff:169.254.169.254]/',
    ]) {
      const result = checkHttpTarget(target, ALLOWED_HTTP_PORTS);
      expect(result.ok, `${target} must be refused`).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('blocked_address');
        expect(result.reason).toMatch(/blocked/i);
      }
    }
  });

  it('refuses a bare hostname with no dot, including "localhost"', () => {
    for (const target of ['http://localhost:8080/', 'http://localhost/', 'http://intranet/']) {
      const result = checkHttpTarget(target, ALLOWED_HTTP_PORTS);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('invalid_hostname');
    }
  });

  it('refuses schemes other than http and https', () => {
    for (const target of [
      'file:///etc/passwd',
      'ftp://example.com/',
      'gopher://example.com/',
      'ws://example.com/',
      'javascript:alert(1)',
    ]) {
      const result = checkHttpTarget(target, ALLOWED_HTTP_PORTS);
      expect(result.ok, `${target} must be refused`).toBe(false);
      if (!result.ok) expect(result.code).toBe('unsupported_protocol');
    }
  });

  it('refuses credentials embedded in the URL', () => {
    const result = checkHttpTarget('https://admin:hunter2@example.com/', ALLOWED_HTTP_PORTS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('credentials_in_url');
  });

  it('restricts the port to the allowlist so a monitor cannot become a scanner', () => {
    const ok = checkHttpTarget('https://example.com:8443/health', ALLOWED_HTTP_PORTS);
    expect(ok.ok).toBe(true);

    for (const port of [22, 25, 3306, 5432, 6379, 11211, 27017]) {
      const result = checkHttpTarget(`https://example.com:${port}/`, ALLOWED_HTTP_PORTS);
      expect(result.ok, `port ${port} must be refused`).toBe(false);
      if (!result.ok) expect(result.code).toBe('port_not_allowed');
    }
  });

  it('normalises an accepted target', () => {
    const result = checkHttpTarget('https://Example.COM:443/health#frag', ALLOWED_HTTP_PORTS);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.hostname).toBe('example.com');
      expect(result.url).toBe('https://example.com/health');
      expect(result.literal).toBe(false);
    }
  });
});

describe('tcp and hostname target validation', () => {
  it('refuses blocked addresses for TCP monitors', () => {
    const result = checkTcpTarget('127.0.0.1:22', ALLOWED_TCP_PORTS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('blocked_address');
  });

  it('refuses a TCP monitor on a port outside the allowlist', () => {
    const result = checkTcpTarget('example.com:31337', ALLOWED_TCP_PORTS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('port_not_allowed');
  });

  it('refuses a URL where a bare host:port is required', () => {
    const result = checkTcpTarget('https://example.com/', ALLOWED_TCP_PORTS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('invalid_url');
  });

  it('refuses blocked addresses for SSL and hostname monitors', () => {
    for (const target of ['169.254.169.254', '10.1.2.3', '[::1]']) {
      const result = checkHostnameTarget(target);
      expect(result.ok, `${target} must be refused`).toBe(false);
      if (!result.ok) expect(result.code).toBe('blocked_address');
    }

    const metadata = checkHostnameTarget('169.254.169.254');
    expect(metadata.ok).toBe(false);
    if (!metadata.ok) expect(metadata.code).toBe('blocked_address');

    const good = checkHostnameTarget('example.com');
    expect(good.ok).toBe(true);
    if (good.ok) expect(good.hostname).toBe('example.com');
  });
});

/* -------------------------------------------------------------------------- */
/* The API refuses these targets at creation                                   */
/* -------------------------------------------------------------------------- */

function monitorBody(overrides: Record<string, unknown> = {}) {
  return {
    monitorType: 'http',
    target: 'https://example.com/',
    name: 'SSRF probe',
    ...overrides,
  };
}

describe('monitor creation refuses unsafe targets', () => {
  const cases: Array<[string, string, RegExp]> = [
    ['loopback', 'http://127.0.0.1/', /blocked/i],
    ['loopback IPv6', 'http://[::1]/', /blocked|loopback/i],
    ['cloud metadata', 'http://169.254.169.254/latest/meta-data/', /metadata/i],
    ['ECS task metadata', 'http://169.254.170.2/v2/credentials', /metadata/i],
    ['RFC1918 10/8', 'http://10.0.0.1/', /private IPv4 range 10/i],
    ['RFC1918 172.16/12', 'http://172.16.5.4/', /private IPv4 range 172\.16/i],
    ['RFC1918 192.168/16', 'https://192.168.0.1/', /private IPv4 range 192\.168/i],
    ['link-local', 'http://169.254.1.1/', /link-local/i],
    ['IPv6 unique-local', 'http://[fd00::1]/', /unique-local/i],
    ['IPv4-mapped loopback', 'http://[::ffff:127.0.0.1]/', /IPv4-mapped|loopback/i],
    ['file scheme', 'file:///etc/passwd', /http:\/\/ and https:\/\//i],
    ['ftp scheme', 'ftp://example.com/', /http:\/\/ and https:\/\//i],
    ['embedded credentials', 'https://admin:hunter2@example.com/', /username\/password/i],
    ['non-allowlisted port', 'https://example.com:22/', /allowlist/i],
  ];

  it.each(cases)('rejects an http monitor on %s', async (_label, target, reason) => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ target }))
      .expect(400);

    expect(response.body.error.code).toBe('VALIDATION_ERROR');
    const fieldErrors = response.body.error.fields?.target ?? [];
    expect(fieldErrors.join(' ')).toMatch(reason);
  });

  it('rejects a keyword monitor on loopback too', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ monitorType: 'http_keyword', target: 'http://127.0.0.1:8080/', keywordMatch: 'ok' }))
      .expect(400);
    expect(response.body.error.fields.target.join(' ')).toMatch(/blocked|loopback/i);
  });

  it('rejects a TCP monitor on a blocked address', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ monitorType: 'tcp', target: '10.0.0.7:22', expectedStatusCodes: null }))
      .expect(400);
    expect(response.body.error.fields.target.join(' ')).toMatch(/blocked|private/i);
  });

  it('rejects an SSL monitor on a blocked address', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ monitorType: 'ssl_certificate', target: '169.254.169.254', expectedStatusCodes: null }))
      .expect(400);
    expect(response.body.error.fields.target.join(' ')).toMatch(/metadata/i);
  });

  it('persists nothing when a target is refused', async () => {
    const rows = await context.handle.db
      .select({ total: count() })
      .from(monitorsTable)
      .where(eq(monitorsTable.organizationId, tenant.organization.id));
    expect(rows[0]?.total).toBe(0);
  });

  it('accepts an ordinary public target so the rules are not simply "reject everything"', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ target: 'https://example.com/health', name: 'Public target' }))
      .expect(201);
    expect(response.body.monitor.target).toBe('https://example.com/health');

    await agent
      .post(`/api/v1/${tenant.organization.id}/monitors/${response.body.monitor.id}/archive`)
      .send({ confirmation: 'ARCHIVE' })
      .expect(200);
  });
});

/**
 * KNOWN DEFECT, encoded so it cannot be forgotten.
 *
 * `createMonitorSchema` runs the SSRF policy (`targetProblem`) but
 * `updateMonitorSchema` only validates `target` as a non-empty string, and
 * `MonitorService.normalizeTarget` re-parses it with `new URL(...)` without
 * re-running `checkHttpTarget`. The stored target can therefore be moved to a
 * blocked address through PATCH even though POST refuses it.
 *
 * It is not a live SSRF - `probeHttp` re-validates every target before opening a
 * socket, and `engine.test.ts` proves the probe reports `blocked_address`
 * instead of connecting - but the API's own rule is inconsistently enforced.
 *
 * Delete this test (or invert it) once `updateMonitorSchema` validates the
 * target with the same policy as create.
 */
describe('known defect: monitor update does not re-run the SSRF policy', () => {
  it.fails('KNOWN BUG: PATCH must refuse loopback exactly like POST does', async () => {
    const created = await agent
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ target: 'https://example.com/', name: 'Update policy probe' }))
      .expect(201);

    const patched = await agent
      .patch(`/api/v1/${tenant.organization.id}/monitors/${created.body.monitor.id}`)
      .send({ target: 'http://127.0.0.1/' });

    // This is what the API *should* answer, with the same reason POST gives.
    expect(patched.status).toBe(400);
    expect(patched.body.error?.fields?.target?.join(' ')).toMatch(/blocked/i);
  });
});

describe('webhook destinations are validated too', () => {
  it('refuses a webhook pointed at the metadata service', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/alert-channels`)
      .send({
        channelType: 'webhook',
        name: 'Metadata webhook',
        enabled: true,
        recipients: [],
        webhookUrl: 'http://169.254.169.254/latest/meta-data/',
      })
      .expect(400);
    expect(response.body.error.fields.webhookUrl.join(' ')).toMatch(/metadata/i);
  });

  it('refuses a webhook on a non-allowlisted port', async () => {
    const response = await agent
      .post(`/api/v1/${tenant.organization.id}/alert-channels`)
      .send({
        channelType: 'webhook',
        name: 'Port scanner webhook',
        enabled: true,
        recipients: [],
        webhookUrl: 'https://example.com:22/hook',
      })
      .expect(400);
    expect(response.body.error.fields.webhookUrl.join(' ')).toMatch(/allowlist/i);
  });
});

describe('anonymous callers cannot use the API to probe the SSRF policy', () => {
  it('answers 401 before any validation happens', async () => {
    const response = await request(app)
      .post(`/api/v1/${tenant.organization.id}/monitors`)
      .send(monitorBody({ target: 'http://127.0.0.1/' }))
      .expect(401);
    expect(response.body.error.code).toBe('UNAUTHENTICATED');
  });
});