/**
 * SSL certificate probe (Part F / F3.3, F4 "For SSL", F7).
 *
 * The connection is made with `rejectUnauthorized: false` on purpose: an
 * expired or self-signed certificate still completes the handshake, which is
 * the only way to report *when* it expires. A handshake that cannot be
 * completed at all is reported as `available: false` - never as "expired".
 *
 * The same DNS pinning used by the HTTP and TCP probes applies here, so a
 * private address can never be reached through a certificate check.
 */

import { isIP } from 'node:net';
import { connect, type DetailedPeerCertificate, type TLSSocket } from 'node:tls';

import type { FailureType } from '@sitesentinel/shared';

import { clampMessage, failureTypeForError, pinnedLookup, resolveAndValidate, safeErrorMessage } from './net.js';

export interface SslProbeRequest {
  host: string;
  port: number;
  timeoutMs: number;
}

export interface SslProbeResult {
  /** `false` when the handshake could not be completed at all. */
  available: boolean;
  failureType: FailureType | null;
  safeMessage: string;
  latencyMs: number | null;
  expiresAt: Date | null;
  issuer: string | null;
  subject: string | null;
  serialNumber: string | null;
  protocol: string | null;
  chainValid: boolean | null;
  chainError: string | null;
  selfSigned: boolean | null;
}

export async function probeSsl(request: SslProbeRequest): Promise<SslProbeResult> {
  const resolution = await resolveAndValidate(request.host);
  if (!resolution.ok) {
    return unavailable(resolution.failureType, resolution.safeMessage, null);
  }

  return new Promise<SslProbeResult>((resolve) => {
    const started = Date.now();
    let settled = false;

    const finish = (value: SslProbeResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };

    const socket: TLSSocket = connect({
      host: request.host,
      port: request.port,
      servername: isIP(request.host) ? undefined : request.host,
      // We validate and describe the chain ourselves below.
      rejectUnauthorized: false,
      lookup: pinnedLookup(resolution.addresses),
    });

    const timer = setTimeout(() => {
      finish(
        unavailable(
          'timeout',
          `The TLS handshake to ${request.host}:${request.port} timed out after ${request.timeoutMs} ms.`,
          request.timeoutMs,
        ),
      );
    }, request.timeoutMs);

    socket.once('secureConnect', () => {
      const latencyMs = Date.now() - started;
      try {
        finish(describe(socket, latencyMs));
      } catch (error) {
        finish(
          unavailable('probe_error', `The TLS handshake succeeded but the certificate could not be read: ${safeErrorMessage(error)}`, latencyMs),
        );
      }
    });

    socket.once('error', (error: unknown) => {
      const mapped = failureTypeForError(error);
      finish(
        unavailable(
          mapped.failureType === 'probe_error' ? 'tls_error' : mapped.failureType,
          clampMessage(`TLS handshake with ${request.host}:${request.port} failed: ${mapped.safeMessage}`),
          Date.now() - started,
        ),
      );
    });
  });
}

function describe(socket: TLSSocket, latencyMs: number): SslProbeResult {
  const peer = socket.getPeerCertificate(true) as DetailedPeerCertificate | undefined;
  if (!peer || !peer.valid_to) {
    return unavailable('tls_error', 'The peer presented no certificate.', latencyMs);
  }

  const expiresAt = new Date(peer.valid_to);
  const issuer = subjectOf(peer.issuer);
  const subject = subjectOf(peer.subject);
  const chainValid = Boolean(socket.authorized);
  const chainError = chainValid ? null : (socket.authorizationError ? String(socket.authorizationError) : 'chain not verified');
  const selfSigned = issuer !== null && subject !== null ? issuer === subject : null;
  const expired = Number.isNaN(expiresAt.getTime()) ? null : expiresAt.getTime() < Date.now();

  const daysRemaining = Number.isNaN(expiresAt.getTime())
    ? null
    : Math.floor((expiresAt.getTime() - Date.now()) / 86_400_000);

  const parts = [
    `Certificate expires at ${expiresAt.toISOString()}.`,
    daysRemaining !== null ? `Days remaining: ${daysRemaining}.` : '',
    expired ? 'The certificate is expired.' : '',
    chainValid ? '' : `Chain validation failed: ${chainError}.`,
  ].filter(Boolean);

  return {
    available: true,
    failureType: expired ? 'ssl_certificate_expired' : null,
    safeMessage: clampMessage(parts.join(' '), 300),
    latencyMs,
    expiresAt,
    issuer,
    subject,
    serialNumber: peer.serialNumber ?? null,
    protocol: socket.getProtocol() ?? null,
    chainValid,
    chainError,
    selfSigned,
  };
}

function subjectOf(subject: DetailedPeerCertificate['subject'] | undefined): string | null {
  if (!subject) return null;
  const parts = [subject.CN, ...(subject.O ?? [])].filter((part): part is string => typeof part === 'string' && part.length > 0);
  return parts.length > 0 ? parts.join(' / ') : null;
}

function unavailable(failureType: FailureType, safeMessage: string, latencyMs: number | null): SslProbeResult {
  return {
    available: false,
    failureType,
    safeMessage: clampMessage(safeMessage, 300),
    latencyMs,
    expiresAt: null,
    issuer: null,
    subject: null,
    serialNumber: null,
    protocol: null,
    chainValid: null,
    chainError: null,
    selfSigned: null,
  };
}