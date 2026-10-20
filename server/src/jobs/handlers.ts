/**
 * Job handlers (Part A / A2, Part F / F4).
 *
 * Every handler is idempotent and reports whether a failure is worth retrying,
 * so the queue can distinguish a transient provider outage from a permanent
 * configuration problem. Nothing here claims an external action succeeded
 * unless the provider confirmed it.
 */

import { and, eq, inArray, isNotNull, isNull, lt } from 'drizzle-orm';

import type { Services } from '../container.js';
import {
  backgroundJobs,
  monitorChecks,
  organizationSettings,
  organizations,
  passwordResetTokens,
  sessions,
} from '../db/schema.js';

export interface JobOutcome {
  retryable: boolean;
  code: string;
  message: string;
}

export type JobHandler = (
  services: Services,
  payload: Record<string, unknown>,
) => Promise<JobOutcome>;

const ok = (message: string): JobOutcome => ({ retryable: false, code: 'ok', message });

/** Sessions and reset tokens that can never be used again. */
const RETENTION_DEFAULTS = { resetTokenDays: 7, revokedSessionDays: 30, completedJobDays: 7 };

const handlers: Record<string, JobHandler> = {
  /**
   * Probe every monitor whose next check is due.
   *
   * Monitors are claimed with a database lease, so two workers - or two job
   * runners of the same queue - can never probe the same monitor at once. An
   * API request never triggers a probe; only this job does.
   */
  'probes.dispatch': async (services) => {
    const result = await services.probes.dispatchDue(50);
    return ok(
      `Checked ${result.checked} monitor(s); ${result.skipped} skipped (leased by another worker or engine error).`,
    );
  },

  /** Deliver one queued alert, through email or a signed webhook. */
  'alert.deliver': async (services, payload) => {
    const deliveryId = String(payload.deliveryId ?? '');
    if (!deliveryId) return { retryable: false, code: 'bad_payload', message: 'deliveryId is required' };

    const subject = typeof payload.subject === 'string' ? payload.subject : 'SiteSentinel alert';
    const text = typeof payload.text === 'string' ? payload.text : '';
    const json = typeof payload.json === 'string' ? payload.json : JSON.stringify({ event: payload.eventType });

    const outcome = await services.alerts.deliver({ deliveryId, content: { subject, text, json } });
    return { retryable: outcome.retryable, code: outcome.code, message: outcome.message };
  },

  /** Repeat notifications for still-open incidents, per rule repeat interval. */
  'alerts.repeat': async (services, payload) => {
    const organizationId = String(payload.organizationId ?? '');
    if (!organizationId) return ok('No organization supplied; nothing to repeat.');
    const queued = await services.alerts.queueRepeats(organizationId);
    return ok(`Queued ${queued} repeat alert(s).`);
  },

  /**
   * Housekeeping: expired sessions, old jobs and check history beyond the
   * organization's retention window.
   */
  'maintenance.cleanup': async (services) => {
    const now = Date.now();

    const removedJobs = await services.db
      .delete(backgroundJobs)
      .where(
        and(
          inArray(backgroundJobs.status, ['succeeded', 'cancelled']),
          lt(backgroundJobs.completedAt, new Date(now - RETENTION_DEFAULTS.completedJobDays * 86_400_000)),
        ),
      )
      .returning({ id: backgroundJobs.id });

    const removedExpiredSessions = await services.db
      .delete(sessions)
      .where(lt(sessions.expiresAt, new Date(now)))
      .returning({ id: sessions.id });

    const removedRevokedSessions = await services.db
      .delete(sessions)
      .where(
        and(
          isNotNull(sessions.revokedAt),
          lt(sessions.revokedAt, new Date(now - RETENTION_DEFAULTS.revokedSessionDays * 86_400_000)),
        ),
      )
      .returning({ id: sessions.id });

    const removedTokens = await services.db
      .delete(passwordResetTokens)
      .where(
        lt(passwordResetTokens.expiresAt, new Date(now - RETENTION_DEFAULTS.resetTokenDays * 86_400_000)),
      )
      .returning({ id: passwordResetTokens.id });

    // Check history is bounded by each organization's retention window.
    const settings = await services.db
      .select({
        organizationId: organizationSettings.organizationId,
        retentionDays: organizationSettings.retentionDays,
      })
      .from(organizationSettings);

    let prunedChecks = 0;
    for (const setting of settings) {
      const cutoff = new Date(now - (setting.retentionDays || 90) * 86_400_000);
      const deleted = await services.db
        .delete(monitorChecks)
        .where(and(eq(monitorChecks.organizationId, setting.organizationId), lt(monitorChecks.checkedAt, cutoff)))
        .returning({ id: monitorChecks.id });
      prunedChecks += deleted.length;
    }

    return ok(
      `Cleanup complete: ${removedJobs.length} job(s), ${removedExpiredSessions.length + removedRevokedSessions.length} session(s), ${removedTokens.length} reset token(s), ${prunedChecks} check row(s) removed.`,
    );
  },
};

export function resolveHandler(jobType: string): JobHandler | null {
  return handlers[jobType] ?? null;
}

export function knownJobTypes(): string[] {
  return Object.keys(handlers);
}

/** Utility used by the worker: does an organization still exist? */
export async function organizationExists(services: Services, organizationId: string): Promise<boolean> {
  const rows = await services.db
    .select({ id: organizations.id })
    .from(organizations)
    .where(and(eq(organizations.id, organizationId), isNull(organizations.deletedAt)))
    .limit(1);
  return Boolean(rows[0]);
}