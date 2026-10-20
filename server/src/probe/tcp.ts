/**
 * TCP connect probe (Part F / F3.3, F7).
 *
 * Only a connection is opened: no bytes are written, nothing is read and no
 * payload is attempted. The port is restricted to the shared allowlist so a
 * monitor can never become a port scanner.
 */

import { connect } from 'node:net';

import { ALLOWED_TCP_PORTS, type FailureType, type MonitorType } from '@sitesentinel/shared';
import { checkTcpTarget } from '@sitesentinel/shared';

import { clampMessage, failureTypeForError, pinnedLookup, resolveAndValidate } from './net.js';

export interface TcpProbeRequest {
  type: Extract<MonitorType, 'tcp'>;
  target: string;
  timeoutMs: number;
}

export interface TcpProbeOutcome {
  ok: boolean;
  failureType: FailureType | null;
  statusCode: null;
  latencyMs: number | null;
  dnsMs: number | null;
  responseSizeBytes: null;
  safeMessage: string;
}

export async function probeTcp(request: TcpProbeRequest): Promise<TcpProbeOutcome> {
  const target = checkTcpTarget(request.target, ALLOWED_TCP_PORTS);
  if (!target.ok) {
    return {
      ok: false,
      failureType: target.code === 'blocked_address' ? 'blocked_address' : 'invalid_target',
      statusCode: null,
      latencyMs: null,
      dnsMs: null,
      responseSizeBytes: null,
      safeMessage: target.reason,
    };
  }

  const resolution = await resolveAndValidate(target.hostname);
  if (!resolution.ok) {
    return {
      ok: false,
      failureType: resolution.failureType,
      statusCode: null,
      latencyMs: null,
      dnsMs: 0,
      responseSizeBytes: null,
      safeMessage: resolution.safeMessage,
    };
  }

  return new Promise<TcpProbeOutcome>((resolve) => {
    const started = Date.now();
    let settled = false;
    const finish = (value: TcpProbeOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };

    const socket = connect({
      host: target.hostname,
      port: target.port,
      lookup: pinnedLookup(resolution.addresses),
      // Nothing is ever sent or received.
      allowHalfOpen: false,
    });

    const timer = setTimeout(() => {
      finish({
        ok: false,
        failureType: 'timeout',
        statusCode: null,
        latencyMs: request.timeoutMs,
        dnsMs: resolution.dnsMs,
        responseSizeBytes: null,
        safeMessage: `TCP connect to ${target.hostname}:${target.port} timed out after ${request.timeoutMs} ms.`,
      });
    }, request.timeoutMs);

    socket.once('connect', () => {
      finish({
        ok: true,
        failureType: null,
        statusCode: null,
        latencyMs: Date.now() - started,
        dnsMs: resolution.dnsMs,
        responseSizeBytes: null,
        safeMessage: `Connected to ${target.hostname}:${target.port}.`,
      });
    });

    socket.once('error', (error: unknown) => {
      const mapped = failureTypeForError(error);
      finish({
        ok: false,
        failureType: mapped.failureType,
        statusCode: null,
        latencyMs: Date.now() - started,
        dnsMs: resolution.dnsMs,
        responseSizeBytes: null,
        safeMessage: clampMessage(
          `TCP connect to ${target.hostname}:${target.port} failed: ${mapped.safeMessage}`,
        ),
      });
    });
  });
}
