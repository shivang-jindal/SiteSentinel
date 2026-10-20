/**
 * A minimal, SSRF-hardened JSON POST used for outbound alert webhooks
 * (Part F / F3.6, F7).
 *
 * The same rules as the probe engine apply: the hostname is resolved, every
 * answer must be globally routable, and the socket is pinned to the validated
 * address so a second DNS answer cannot be substituted.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

import { checkHttpTarget, ALLOWED_HTTP_PORTS } from '@sitesentinel/shared';

import { pinnedLookup, resolveAndValidate, safeErrorMessage } from '../probe/net.js';

export interface JsonPostResult {
  ok: boolean;
  /** HTTP status returned by the receiver, when a response was received. */
  statusCode: number | null;
  failureCode: string | null;
  message: string;
}

export async function postSignedJson(input: {
  url: string;
  body: string;
  signatureHeader: string;
  signature: string;
  timestampHeader: string;
  timestamp: string;
  timeoutMs: number;
}): Promise<JsonPostResult> {
  const target = checkHttpTarget(input.url, ALLOWED_HTTP_PORTS);
  if (!target.ok) {
    return { ok: false, statusCode: null, failureCode: 'blocked_target', message: target.reason };
  }

  const url = new URL(target.url);
  const resolution = await resolveAndValidate(url.hostname);
  if (!resolution.ok) {
    return { ok: false, statusCode: null, failureCode: 'blocked_target', message: resolution.safeMessage };
  }

  const isHttps = url.protocol === 'https:';
  const payload = Buffer.from(input.body, 'utf8');

  return new Promise<JsonPostResult>((resolve) => {
    let settled = false;
    const finish = (value: JsonPostResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const send = isHttps ? httpsRequest : httpRequest;
    const clientRequest = send(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port === '' ? (isHttps ? 443 : 80) : Number(url.port),
        path: `${url.pathname}${url.search}`,
        method: 'POST',
        agent: false,
        timeout: input.timeoutMs,
        lookup: pinnedLookup(resolution.addresses),
        headers: {
          'content-type': 'application/json',
          'content-length': String(payload.byteLength),
          'user-agent': 'SiteSentinel-Webhook/1.0',
          [input.signatureHeader]: input.signature,
          [input.timestampHeader]: input.timestamp,
        },
      },
      (response) => {
        const statusCode = response.statusCode ?? 0;
        // The receiver's body is never stored: drain and discard.
        response.resume();
        if (statusCode >= 200 && statusCode < 300) {
          finish({
            ok: true,
            statusCode,
            failureCode: null,
            message: `The endpoint accepted the alert with HTTP ${statusCode}.`,
          });
          return;
        }
        finish({
          ok: false,
          statusCode,
          failureCode: statusCode >= 500 || statusCode === 429 ? 'temporary' : 'permanent',
          message: `The endpoint answered HTTP ${statusCode}.`,
        });
      },
    );

    const timer = setTimeout(() => {
      clientRequest.destroy(Object.assign(new Error('webhook timeout'), { code: 'ETIMEDOUT' }));
      finish({
        ok: false,
        statusCode: null,
        failureCode: 'temporary',
        message: `The endpoint did not answer within ${input.timeoutMs} ms.`,
      });
    }, input.timeoutMs);

    clientRequest.on('timeout', () => {
      clientRequest.destroy(Object.assign(new Error('webhook timeout'), { code: 'ETIMEDOUT' }));
    });
    clientRequest.on('error', (error: unknown) => {
      const code = ((error as NodeJS.ErrnoException).code ?? '') as string;
      finish({
        ok: false,
        statusCode: null,
        failureCode: code === 'ETIMEDOUT' || code === 'ECONNRESET' ? 'temporary' : 'provider_error',
        message: safeErrorMessage(error),
      });
    });

    clientRequest.end(payload);
  });
}