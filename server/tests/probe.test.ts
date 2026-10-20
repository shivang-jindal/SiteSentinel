/**
 * Probe engine (Part F / F4, F7) - direct unit tests.
 *
 * The sandbox has no outbound internet, and - more importantly - the SSRF
 * defence this product is built around refuses loopback *before* any socket is
 * opened. So every case here is one the engine must reach a verdict about
 * without an external host: blocked addresses, unsupported protocols, invalid
 * targets, and the error-code mapping that decides timeout vs. DNS vs. TLS.
 *
 * What cannot be covered here (and why) is documented in the report; the
 * successful-probe path is covered in `engine.test.ts` with the outbound socket
 * replaced by a controlled stub, so the real state machine, incident dedupe and
 * alert queueing still run against real rows.
 */

import { describe, expect, it } from 'vitest';

import {
  ALLOWED_HTTP_PORTS,
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  PROBE_INFRASTRUCTURE_FAILURES,
  checkHttpTarget,
  type FailureType,
} from '@sitesentinel/shared';

import { PROBE_VERSION, probeHttp } from '../src/probe/http.js';
import { failureTypeForError, pinnedLookup, resolveAndValidate, safeErrorMessage } from '../src/probe/net.js';
import { probeSsl } from '../src/probe/ssl.js';
import { probeTcp } from '../src/probe/tcp.js';

function httpProbe(target: string, extra: Partial<Parameters<typeof probeHttp>[0]> = {}) {
  return probeHttp({
    type: 'http',
    target,
    timeoutMs: 2_000,
    expectedStatusCodes: [200],
    keywordMatch: null,
    maxBodyBytes: 65_536,
    ...extra,
  });
}

describe('HTTP probe refuses unsafe targets without opening a socket', () => {
  const blocked: Array<[string, FailureType, RegExp]> = [
    ['http://127.0.0.1/', 'blocked_address', /loopback/i],
    ['http://127.0.0.1:8080/health', 'blocked_address', /loopback/i],
    ['http://localhost/', 'invalid_target', /hostname/i],
    ['http://169.254.169.254/latest/meta-data/', 'blocked_address', /metadata/i],
    ['http://10.1.1.1/', 'blocked_address', /private IPv4/i],
    ['http://192.168.1.1/', 'blocked_address', /private IPv4/i],
    ['http://172.16.0.9/', 'blocked_address', /private IPv4/i],
    ['http://[::1]/', 'blocked_address', /loopback/i],
    ['http://[fd00::1]/', 'blocked_address', /unique-local/i],
    ['http://[::ffff:10.0.0.1]/', 'blocked_address', /IPv4-mapped/i],
    ['file:///etc/passwd', 'unsupported_protocol', /http/i],
    ['gopher://example.com/', 'unsupported_protocol', /http/i],
    ['ws://example.com/', 'unsupported_protocol', /http/i],
    ['not a url at all', 'invalid_target', /full URL/i],
    ['https://example.com:22/', 'invalid_target', /allowlist/i],
    ['https://admin:secret@example.com/', 'invalid_target', /username\/password/i],
  ];

  it.each(blocked)('reports %s as %s', async (target, failureType, reason) => {
    const outcome = await httpProbe(target);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.failureType).toBe(failureType);
    expect(outcome.safeMessage).toMatch(reason);
    // Nothing was connected, so nothing may be reported as observed.
    expect(outcome.statusCode).toBeNull();
    expect(outcome.latencyMs).toBeNull();
    expect(outcome.finalUrl).toBeNull();
  });

  it('treats every refusal above as a probe-infrastructure failure, not "down"', () => {
    // `blocked_address`, `invalid_target` and `unsupported_protocol` are the
    // categories the state machine refuses to count towards a failure streak.
    for (const failureType of ['blocked_address', 'invalid_target', 'unsupported_protocol'] as const) {
      expect(PROBE_INFRASTRUCTURE_FAILURES).toContain(failureType);
    }
    // A timeout, by contrast, is a real statement about the target.
    expect(PROBE_INFRASTRUCTURE_FAILURES).not.toContain('timeout');
  });
});

describe('redirect destinations are re-validated with the same policy', () => {
  it('rejects a redirect that points at the metadata service', async () => {
    // `probeHttp` re-runs `checkHttpTarget` on every `Location` header it is
    // given (server/src/probe/http.ts). Reproduced here at the policy level,
    // because a live redirect needs a reachable origin server and this sandbox
    // has no outbound network.
    const resolved = new URL('/latest/meta-data/iam/', 'https://169.254.169.254/meta').toString();
    const next = checkHttpTarget(resolved, ALLOWED_HTTP_PORTS);
    expect(next.ok).toBe(false);
    if (!next.ok) {
      expect(next.code).toBe('blocked_address');
      expect(next.reason).toMatch(/metadata/i);
    }
  });

  it('rejects a redirect that downgrades to a loopback host', () => {
    const next = checkHttpTarget(new URL('http://127.0.0.1:8080/admin', 'https://example.com/').toString(), ALLOWED_HTTP_PORTS);
    expect(next.ok).toBe(false);
    if (!next.ok) expect(next.code).toBe('blocked_address');
  });

  it('bounds the redirect chain', () => {
    expect(MAX_REDIRECTS).toBeGreaterThan(0);
    expect(MAX_REDIRECTS).toBeLessThanOrEqual(10);
  });
});

describe('TCP probe', () => {
  it('refuses loopback and reports why', async () => {
    const outcome = await probeTcp({ type: 'tcp', target: '127.0.0.1:22', timeoutMs: 1_000 });
    expect(outcome.ok).toBe(false);
    expect(outcome.failureType).toBe('blocked_address');
    expect(outcome.latencyMs).toBeNull();
  });

  it('refuses a port outside the allowlist instead of scanning it', async () => {
    const outcome = await probeTcp({ type: 'tcp', target: 'example.com:31337', timeoutMs: 1_000 });
    expect(outcome.ok).toBe(false);
    expect(outcome.failureType).toBe('invalid_target');
    expect(outcome.safeMessage).toMatch(/allowlist/i);
  });

  it('refuses a URL where a bare host:port is required', async () => {
    const outcome = await probeTcp({ type: 'tcp', target: 'https://example.com/', timeoutMs: 1_000 });
    expect(outcome.ok).toBe(false);
    expect(outcome.failureType).toBe('invalid_target');
  });
});

describe('SSL probe', () => {
  it('reports a blocked address as unavailable, never as an expired certificate', async () => {
    for (const host of ['127.0.0.1', '169.254.169.254', '10.0.0.1', '[::1]']) {
      const outcome = await probeSsl({ host, port: 443, timeoutMs: 1_000 });
      expect(outcome.available, `${host} must be unavailable`).toBe(false);
      expect(outcome.expiresAt).toBeNull();
      expect(outcome.failureType).not.toBe('ssl_certificate_expired');
      expect(outcome.failureType).toBe('blocked_address');
      expect(outcome.safeMessage).not.toMatch(/expired/i);
    }
  });

  it('reports a blocked address as unavailable with no expiry date', async () => {
    // A private RFC1918 address is blocked by the SSRF policy, so the probe
    // never attempts a connection. This tests the contract: `available:false`,
    // no expiry date, and never a claim that a certificate expired.
    const outcome = await probeSsl({ host: '10.0.0.1', port: 443, timeoutMs: 2_000 });
    expect(outcome.available).toBe(false);
    expect(outcome.expiresAt).toBeNull();
    expect(outcome.issuer).toBeNull();
    expect(outcome.chainValid).toBeNull();
    expect(outcome.selfSigned).toBeNull();
    expect(outcome.failureType).not.toBe('ssl_certificate_expired');
    expect(outcome.safeMessage).not.toMatch(/expired/i);
  });

  it('never stores private key material in the result', async () => {
    const outcome = await probeSsl({ host: '169.254.169.254', port: 443, timeoutMs: 500 });
    expect(JSON.stringify(outcome)).not.toMatch(/privatekey|private_key|BEGIN /i);
  });
});

describe('error mapping decides what counts as a target failure', () => {
  it.each([
    ['ETIMEDOUT', 'timeout'],
    ['ESOCKETTIMEDOUT', 'timeout'],
    ['ENOTFOUND', 'dns_error'],
    ['EAI_AGAIN', 'dns_error'],
    ['ECONNREFUSED', 'connection_refused'],
    ['ECONNRESET', 'connection_reset'],
    ['EPIPE', 'connection_reset'],
    ['ENETUNREACH', 'connection_reset'],
    ['CERT_HAS_EXPIRED', 'tls_error'],
    ['ERR_TLS_CERT_ALTNAME_INVALID', 'tls_error'],
    ['DEPTH_ZERO_SELF_SIGNED_CERT', 'tls_error'],
    ['SOMETHING_ODD', 'probe_error'],
  ])('maps %s to %s', (code, expected) => {
    const mapped = failureTypeForError(Object.assign(new Error('boom'), { code }));
    expect(mapped.failureType).toBe(expected);
    expect(mapped.safeMessage.length).toBeGreaterThan(0);
  });

  it('truncates and de-stacks the operator-facing message', () => {
    const message = safeErrorMessage(new Error(`x${'y'.repeat(500)}`));
    expect(message.length).toBeLessThanOrEqual(200);
    expect(message).not.toContain('\n');
  });
});

describe('DNS pinning defeats rebinding', () => {
  it('returns only the address that was validated, whatever the hostname', async () => {
    const lookup = pinnedLookup([{ address: '93.184.216.34', family: 4 }]);
    const seen: Array<[string | undefined, number]> = [];
    await new Promise<void>((resolve) => {
      lookup('evil.example.net', { all: false } as never, (_error, address, family) => {
        seen.push([address, family]);
        resolve();
      });
    });
    expect(seen).toEqual([['93.184.216.34', 4]]);
  });

  it('refuses a literal private address without touching DNS', async () => {
    const resolution = await resolveAndValidate('127.0.0.1');
    expect(resolution.ok).toBe(false);
    if (!resolution.ok) {
      expect(resolution.failureType).toBe('blocked_address');
      expect(resolution.safeMessage).toMatch(/blocked/i);
    }
  });

  it('accepts a literal public address and pins it', async () => {
    const resolution = await resolveAndValidate('93.184.216.34');
    expect(resolution.ok).toBe(true);
    if (resolution.ok) expect(resolution.addresses[0]).toEqual({ address: '93.184.216.34', family: 4 });
  });
});

describe('probe limits are published, not implicit', () => {
  it('carries a version and a bounded response budget', () => {
    expect(PROBE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(MAX_RESPONSE_BYTES).toBeGreaterThan(0);
    expect(MAX_RESPONSE_BYTES).toBeLessThanOrEqual(1_048_576);
    expect(MAX_REDIRECTS).toBeLessThanOrEqual(10);
  });
});