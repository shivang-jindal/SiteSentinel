/**
 * HTTP / HTTPS probe (Part F / F4.3-4, F7).
 *
 * - Safe methods only (`GET` / `HEAD`); no request body is ever sent.
 * - Redirects are followed manually, with a hard bound, and every hop repeats
 *   the full protocol / host / DNS / pinned-address validation.
 * - The response body is never stored. For a keyword check at most
 *   `MAX_KEYWORD_BODY_BYTES` are read into memory, used for a substring test
 *   and then discarded.
 * - No JavaScript is executed; the probe is a plain HTTP client.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { IncomingMessage, OutgoingHttpHeaders } from 'node:http';

import { MAX_REDIRECTS, type FailureType, type MonitorType } from '@sitesentinel/shared';
import { checkHttpTarget, ALLOWED_HTTP_PORTS } from '@sitesentinel/shared';

import { clampMessage, failureTypeForError, pinnedLookup, resolveAndValidate, safeErrorMessage } from './net.js';

export const PROBE_VERSION = '1.0.0';
const USER_AGENT = `SiteSentinel/${PROBE_VERSION} (+uptime-monitor)`;

export interface HttpProbeRequest {
  type: Extract<MonitorType, 'http' | 'http_keyword'>;
  target: string;
  timeoutMs: number;
  expectedStatusCodes: number[];
  keywordMatch: string | null;
  maxBodyBytes: number;
}

export interface HttpProbeResult {
  ok: true;
  statusCode: number;
  latencyMs: number;
  dnsMs: number;
  responseSizeBytes: number | null;
  redirects: number;
  finalUrl: string;
  failureType: null;
  safeMessage: string;
}

export interface HttpProbeFailure {
  ok: false;
  failureType: FailureType;
  safeMessage: string;
  latencyMs: number | null;
  dnsMs: number | null;
  statusCode: number | null;
  responseSizeBytes: number | null;
  redirects: number;
  finalUrl: string | null;
}

export type HttpProbeOutcome = HttpProbeResult | HttpProbeFailure;

export async function probeHttp(request: HttpProbeRequest): Promise<HttpProbeOutcome> {
  const target = checkHttpTarget(request.target, ALLOWED_HTTP_PORTS);
  if (!target.ok) {
    return {
      ok: false,
      failureType: target.code === 'unsupported_protocol' ? 'unsupported_protocol' : target.code === 'blocked_address' ? 'blocked_address' : 'invalid_target',
      safeMessage: target.reason,
      latencyMs: null,
      dnsMs: null,
      statusCode: null,
      responseSizeBytes: null,
      redirects: 0,
      finalUrl: null,
    };
  }

  const started = Date.now();
  let currentUrl = target.url;
  let redirects = 0;
  let totalDnsMs = 0;

  for (;;) {
    const attempt = await attemptOnce(currentUrl, request);
    if (!attempt.transportOk) {
      return {
        ok: false,
        failureType: attempt.failureType,
        safeMessage: attempt.safeMessage,
        latencyMs: Date.now() - started,
        dnsMs: totalDnsMs + (attempt.dnsMs ?? 0),
        statusCode: null,
        responseSizeBytes: null,
        redirects,
        finalUrl: currentUrl,
      };
    }

    totalDnsMs += attempt.dnsMs ?? 0;

    if (attempt.kind === 'redirect') {
      if (redirects >= MAX_REDIRECTS) {
        return {
          ok: false,
          failureType: 'too_many_redirects',
          safeMessage: `Stopped after ${MAX_REDIRECTS} redirects.`,
          latencyMs: Date.now() - started,
          dnsMs: totalDnsMs,
          statusCode: attempt.statusCode,
          responseSizeBytes: null,
          redirects,
          finalUrl: currentUrl,
        };
      }
      const next = checkHttpTarget(new URL(attempt.location as string, currentUrl).toString(), ALLOWED_HTTP_PORTS);
      if (!next.ok) {
        return {
          ok: false,
          failureType: next.code === 'blocked_address' ? 'redirect_blocked' : 'redirect_blocked',
          safeMessage: `Redirect blocked: ${next.reason}`,
          latencyMs: Date.now() - started,
          dnsMs: totalDnsMs,
          statusCode: attempt.statusCode,
          responseSizeBytes: null,
          redirects,
          finalUrl: currentUrl,
        };
      }
      currentUrl = next.url;
      redirects += 1;
      continue;
    }

    const latencyMs = Date.now() - started;
    const statusCode = attempt.statusCode as number;

    if (!request.expectedStatusCodes.includes(statusCode)) {
      return {
        ok: false,
        failureType: 'unexpected_status',
        safeMessage: `Expected ${request.expectedStatusCodes.join('/')} but received ${statusCode}.`,
        latencyMs,
        dnsMs: totalDnsMs,
        statusCode,
        responseSizeBytes: attempt.responseSizeBytes,
        redirects,
        finalUrl: currentUrl,
      };
    }

    if (request.type === 'http_keyword') {
      const body = attempt.body ?? '';
      const keyword = request.keywordMatch ?? '';
      if (!keyword) {
        return {
          ok: false,
          failureType: 'invalid_target',
          safeMessage: 'This keyword check has no keyword configured.',
          latencyMs,
          dnsMs: totalDnsMs,
          statusCode,
          responseSizeBytes: attempt.responseSizeBytes,
          redirects,
          finalUrl: currentUrl,
        };
      }
      if (!body.includes(keyword)) {
        return {
          ok: false,
          failureType: 'keyword_mismatch',
          // The keyword and the body itself are never echoed back.
          safeMessage: `The response did not contain the expected keyword within the first ${request.maxBodyBytes} bytes.`,
          latencyMs,
          dnsMs: totalDnsMs,
          statusCode,
          responseSizeBytes: attempt.responseSizeBytes,
          redirects,
          finalUrl: currentUrl,
        };
      }
    }

    return {
      ok: true,
      statusCode,
      latencyMs,
      dnsMs: totalDnsMs,
      responseSizeBytes: attempt.responseSizeBytes,
      redirects,
      finalUrl: currentUrl,
      failureType: null,
      safeMessage:
        redirects > 0
          ? `HTTP ${statusCode} after ${redirects} redirect(s).`
          : `HTTP ${statusCode}.`,
    };
  }
}

interface AttemptOk {
  transportOk: true;
  kind: 'response' | 'redirect';
  statusCode: number;
  location?: string | null;
  body?: string;
  responseSizeBytes: number | null;
  dnsMs: number;
}

interface AttemptTransportFailure {
  transportOk: false;
  failureType: FailureType;
  safeMessage: string;
  dnsMs: number | null;
}

type Attempt = AttemptOk | AttemptTransportFailure;

async function attemptOnce(rawUrl: string, request: HttpProbeRequest): Promise<Attempt> {
  const url = new URL(rawUrl);
  const resolution = await resolveAndValidate(url.hostname);
  if (!resolution.ok) {
    return {
      transportOk: false,
      failureType: resolution.failureType,
      safeMessage: resolution.safeMessage,
      dnsMs: 0,
    };
  }

  const isHttps = url.protocol === 'https:';
  const headers: OutgoingHttpHeaders = {
    'user-agent': USER_AGENT,
    accept: '*/*',
    // Ask for an identity encoding so the byte budget is meaningful.
    'accept-encoding': 'identity',
    connection: 'close',
    host: url.host,
  };

  return new Promise<Attempt>((resolve) => {
    let settled = false;
    const finish = (value: Attempt) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const send = isHttps ? httpsRequest : httpRequest;
    const requestOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port === '' ? (isHttps ? 443 : 80) : Number(url.port),
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers,
      agent: false,
      timeout: request.timeoutMs,
      // Pin the validated address: no second DNS answer can be substituted.
      lookup: pinnedLookup(resolution.addresses),
      ...(isHttps
        ? {
            servername: /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) ? undefined : url.hostname,
          }
        : {}),
    };

    const timer = setTimeout(() => {
      clientRequest.destroy(Object.assign(new Error('probe timeout'), { code: 'ETIMEDOUT' }));
    }, request.timeoutMs);

    const clientRequest = send(requestOptions, (response: IncomingMessage) => handleResponse(response, resolution.dnsMs, request, finish));

    clientRequest.on('timeout', () => {
      clientRequest.destroy(Object.assign(new Error('probe timeout'), { code: 'ETIMEDOUT' }));
    });
    clientRequest.on('error', (error: unknown) => {
      const mapped = failureTypeForError(error);
      finish({
        transportOk: false,
        failureType: mapped.failureType,
        safeMessage: clampMessage(mapped.safeMessage),
        dnsMs: resolution.dnsMs,
      });
    });
  });
}

function handleResponse(
  response: IncomingMessage,
  dnsMs: number,
  request: HttpProbeRequest,
  finish: (value: Attempt) => void,
): void {
  const statusCode = response.statusCode ?? 0;
  const contentLengthHeader = response.headers['content-length'];
  const declaredLength = typeof contentLengthHeader === 'string' ? Number(contentLengthHeader) : null;

  if ([301, 302, 303, 307, 308].includes(statusCode) && response.headers.location) {
    response.resume();
    finish({
      transportOk: true,
      kind: 'redirect',
      statusCode,
      location: response.headers.location,
      responseSizeBytes: null,
      dnsMs,
    });
    return;
  }

  if (request.type !== 'http_keyword') {
    // The body is never needed and never stored: stop reading immediately.
    response.destroy();
    finish({
      transportOk: true,
      kind: 'response',
      statusCode,
      responseSizeBytes: declaredLength !== null && Number.isFinite(declaredLength) ? declaredLength : null,
      dnsMs,
    });
    return;
  }

  const chunks: Buffer[] = [];
  let received = 0;
  let tooLarge = false;

  response.on('data', (chunk: Buffer) => {
    received += chunk.length;
    if (received > request.maxBodyBytes) {
      tooLarge = true;
      response.destroy();
      return;
    }
    chunks.push(chunk);
  });
  response.on('aborted', () => {
    if (tooLarge) {
      finish({
        transportOk: false,
        failureType: 'response_too_large',
        safeMessage: `The response exceeded the ${request.maxBodyBytes} byte limit set for keyword checks; the body was discarded without being stored.`,
        dnsMs,
      });
      return;
    }
    finish({
      transportOk: true,
      kind: 'response',
      statusCode,
      body: Buffer.concat(chunks).toString('utf8'),
      responseSizeBytes: received,
      dnsMs,
    });
  });
  response.on('error', (error: unknown) => {
    if (tooLarge) {
      finish({
        transportOk: false,
        failureType: 'response_too_large',
        safeMessage: `The response exceeded the ${request.maxBodyBytes} byte limit set for keyword checks; the body was discarded without being stored.`,
        dnsMs,
      });
      return;
    }
    finish({
      transportOk: true,
      kind: 'response',
      statusCode,
      body: Buffer.concat(chunks).toString('utf8'),
      responseSizeBytes: received,
      dnsMs,
    });
    void safeErrorMessage(error);
  });
  response.on('end', () => {
    if (tooLarge) {
      finish({
        transportOk: false,
        failureType: 'response_too_large',
        safeMessage: `The response exceeded the ${request.maxBodyBytes} byte limit set for keyword checks; the body was discarded without being stored.`,
        dnsMs,
      });
      return;
    }
    finish({
      transportOk: true,
      kind: 'response',
      statusCode,
      body: Buffer.concat(chunks).toString('utf8'),
      responseSizeBytes: received,
      dnsMs,
    });
  });
}
