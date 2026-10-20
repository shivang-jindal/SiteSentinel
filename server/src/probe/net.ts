/**
 * Network primitives for the probe engine (Part F / F4, F7).
 *
 * Every outgoing connection in SiteSentinel goes through this module:
 *
 *   1. the hostname is parsed and, for IP literals, classified immediately;
 *   2. DNS is resolved once and **every** returned address is validated - a
 *      single private answer fails the whole probe (fail closed);
 *   3. the connection is made with a pinned `lookup` that returns exactly the
 *      address that was validated, so a second DNS answer cannot be swapped in
 *      between the check and the connection (DNS-rebinding defence);
 *   4. redirects are followed manually and each hop repeats steps 1-3.
 */

import { promises as dns } from 'node:dns';
import type { LookupAddress, LookupOptions } from 'node:dns';
import { isIP } from 'node:net';

import {
  addressFamilyOf,
  classifyAddress,
  normalizeHostname,
  type FailureType,
} from '@sitesentinel/shared';

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type ResolutionResult =
  | { ok: true; addresses: ResolvedAddress[]; dnsMs: number }
  | { ok: false; failureType: FailureType; safeMessage: string };

/**
 * Resolves a hostname and refuses the whole probe when any answer is not a
 * globally routable address.
 */
export async function resolveAndValidate(rawHostname: string): Promise<ResolutionResult> {
  const hostname = normalizeHostname(rawHostname);
  const started = Date.now();

  const literalFamily = addressFamilyOf(hostname);
  if (literalFamily) {
    const verdict = classifyAddress(hostname);
    if (!verdict.allowed) {
      return {
        ok: false,
        failureType: 'blocked_address',
        safeMessage: `Target address ${hostname} is blocked: ${verdict.reason}.`,
      };
    }
    return { ok: true, addresses: [{ address: hostname, family: literalFamily }], dnsMs: 0 };
  }

  let answers: LookupAddress[];
  try {
    answers = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? '';
    const dnsMs = Date.now() - started;
    if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NONAME') {
      return {
        ok: false,
        failureType: 'dns_error',
        safeMessage: `DNS lookup for ${hostname} failed (${code || 'ENOTFOUND'}) after ${dnsMs} ms.`,
      };
    }
    return {
      ok: false,
      failureType: 'dns_error',
      safeMessage: `DNS lookup for ${hostname} failed: ${safeErrorMessage(error)}`,
    };
  }

  const dnsMs = Date.now() - started;
  const usable: ResolvedAddress[] = [];
  for (const answer of answers) {
    const family = answer.family === 6 ? 6 : 4;
    const verdict = classifyAddress(answer.address);
    if (!verdict.allowed) {
      // Fail closed: a host that answers with one public and one private
      // address is exactly the DNS-rebinding case we must refuse.
      return {
        ok: false,
        failureType: 'blocked_address',
        safeMessage: `DNS for ${hostname} resolved to ${answer.address}, which is blocked: ${verdict.reason}.`,
      };
    }
    if (isIP(answer.address) === 0) continue;
    usable.push({ address: answer.address, family });
  }

  if (usable.length === 0) {
    return {
      ok: false,
      failureType: 'dns_error',
      safeMessage: `DNS for ${hostname} returned no usable address.`,
    };
  }

  return { ok: true, addresses: usable, dnsMs };
}

/**
 * Signature-compatible with Node's `net.LookupFunction`, so the same pinned
 * resolver can be handed to `http.request`, `net.connect` and `tls.connect`.
 */
export type PinnedLookup = (
  hostname: string,
  options: LookupOptions,
  callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void,
) => void;

/**
 * Builds a `lookup` implementation that always returns the already-validated
 * address. Passing this to `http.request`, `https.request`, `net.connect` or
 * `tls.connect` removes the second resolution entirely.
 */
export function pinnedLookup(addresses: ResolvedAddress[]): PinnedLookup {
  const pinned = addresses;
  return (hostname, options, callback) => {
    const wantsAll = Boolean((options as { all?: boolean } | undefined)?.all);
    if (wantsAll) {
      const allCallback = callback as unknown as (
        error: NodeJS.ErrnoException | null,
        address: LookupAddress[],
      ) => void;
      allCallback(null, pinned as unknown as LookupAddress[]);
      return;
    }
    const first = pinned[0];
    if (!first) {
      callback(Object.assign(new Error('no pinned address'), { code: 'ENOTFOUND' }), '', 4);
      return;
    }
    callback(null, first.address, first.family);
  };
}

/** Maps a Node socket/TLS error code onto a persisted failure category. */
export function failureTypeForError(error: unknown): { failureType: FailureType; safeMessage: string } {
  const code = ((error as NodeJS.ErrnoException | undefined)?.code ?? '') as string;
  const name = (error as { name?: string } | undefined)?.name ?? '';

  if (name === 'AbortError' || code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || code === 'UND_ERR_HEADERS_TIMEOUT') {
    return { failureType: 'timeout', safeMessage: 'The probe timed out before the target responded.' };
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NONAME') {
    return { failureType: 'dns_error', safeMessage: `DNS lookup failed (${code}).` };
  }
  if (code === 'ECONNREFUSED') {
    return { failureType: 'connection_refused', safeMessage: 'The target refused the connection.' };
  }
  if (code === 'ECONNRESET' || code === 'EPIPE' || code === 'ECONNABORTED') {
    return { failureType: 'connection_reset', safeMessage: 'The connection was reset before the response completed.' };
  }
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH' || code === 'EACCES') {
    return { failureType: 'connection_reset', safeMessage: `The target was unreachable (${code}).` };
  }
  if (
    code.startsWith('ERR_TLS') ||
    code.startsWith('CERT_') ||
    code.startsWith('UNABLE_TO_') ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'ERR_SSL'
  ) {
    return { failureType: 'tls_error', safeMessage: `TLS verification failed: ${safeErrorMessage(error)}` };
  }
  return { failureType: 'probe_error', safeMessage: `Probe error: ${safeErrorMessage(error)}` };
}

/** Error text without a stack trace and never with a full response body. */
export function safeErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown error';
  const message = error.message.replace(/\s+/g, ' ').trim();
  return message.length > 200 ? `${message.slice(0, 197)}...` : message;
}

/** Truncates any operator-facing string before it reaches the database. */
export function clampMessage(value: string, max = 300): string {
  const collapsed = value.replace(/\s+/g, ' ').trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 3)}...` : collapsed;
}
