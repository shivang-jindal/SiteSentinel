/**
 * Background worker (Part A / A2, Part F / F4).
 *
 * Runs as its own process (`npm run dev:worker`). It claims jobs from the
 * database queue with `FOR UPDATE SKIP LOCKED`, applies bounded exponential
 * backoff to retryable failures and leaves permanently failed jobs visible.
 *
 * The worker never probes a monitor directly from an HTTP request: it keeps at
 * most one `probes.dispatch` job queued, and that job claims monitors through
 * the `monitor_locks` lease table.
 */

import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { and, eq, inArray, isNull, sql } from 'drizzle-orm';

import type { Services } from '../container.js';
import { backgroundJobs, organizations } from '../db/schema.js';
import { resolveHandler, type JobOutcome } from './handlers.js';

/** How often the recurring per-organization jobs are enqueued. */
const RECURRING_INTERVAL_MS = 15 * 60_000;

/** One dispatch job per bucket, so restarts cannot fan out probes. */
const DISPATCH_BUCKET_MS = 30_000;

export interface WorkerHandle {
  stop: () => Promise<void>;
  readonly workerId: string;
}

export async function startWorker(
  services: Services,
  options: { once?: boolean } = {},
): Promise<WorkerHandle> {
  const workerId = `worker-${randomUUID().slice(0, 8)}`;
  let stopping = false;
  let processed = 0;
  services.logger.info({ workerId }, 'worker started');

  const reapTimer = setInterval(() => {
    void services.jobs.reapStale().catch((error: unknown) => {
      services.logger.warn({ err: error }, 'could not reap stale job leases');
    });
  }, 60_000);
  reapTimer.unref();

  const recurringTimer = setInterval(() => {
    void enqueueRecurring(services).catch((error: unknown) => {
      services.logger.warn({ err: error }, 'could not enqueue recurring jobs');
    });
  }, RECURRING_INTERVAL_MS);
  recurringTimer.unref();

  await enqueueRecurring(services);

  do {
    const handled = await drainOnce(services, workerId);
    processed += handled;
    if (!handled && !options.once) {
      await sleep(services.config.worker.pollIntervalMs);
    }
  } while (!stopping && !options.once);

  clearInterval(reapTimer);
  clearInterval(recurringTimer);

  if (options.once) {
    services.logger.info({ workerId, processed }, 'worker run finished');
  }

  return {
    workerId,
    stop: async () => {
      stopping = true;
      clearInterval(reapTimer);
      clearInterval(recurringTimer);
      services.logger.info({ workerId, processed }, 'worker stopped');
    },
  };
}

/** Claim and run jobs until the queue is empty for this pass. */
export async function drainOnce(services: Services, workerId: string): Promise<number> {
  const parallel: Array<Promise<boolean>> = [];

  for (let index = 0; index < services.config.worker.concurrency; index += 1) {
    parallel.push(
      (async () => {
        const job = await services.jobs.claimNext(workerId);
        if (!job) return false;

        const handler = resolveHandler(job.jobType);
        if (!handler) {
          await services.jobs.markFailed(
            job.id,
            { code: 'unknown_job_type', message: `No handler for ${job.jobType}` },
            { retryable: false },
          );
          services.logger.error({ jobId: job.id, jobType: job.jobType }, 'unknown job type');
          return true;
        }

        try {
          const outcome: JobOutcome = await handler(services, job.payload ?? {});
          if (outcome.retryable) {
            await services.jobs.markFailed(
              job.id,
              { code: outcome.code, message: outcome.message },
              { retryable: true, baseDelayMs: 30_000 },
            );
            services.logger.warn(
              { jobId: job.id, jobType: job.jobType, code: outcome.code },
              outcome.message,
            );
            return true;
          }
          await services.jobs.markSucceeded(job.id);
          services.logger.debug(
            { jobId: job.id, jobType: job.jobType, message: outcome.message },
            'job completed',
          );
        } catch (error) {
          const code = error instanceof Error ? error.name || 'error' : 'error';
          const message = error instanceof Error ? error.message : String(error);
          services.logger.warn({ jobId: job.id, jobType: job.jobType, code }, 'job failed');
          await services.jobs.markFailed(job.id, { code, message }, { retryable: true });
        }
        return true;
      })(),
    );
  }

  const results = await Promise.all(parallel);
  let processed = 0;
  for (const result of results) if (result) processed += 1;
  return processed;
}

/**
 * Keeps exactly one `probes.dispatch` job queued at a time and re-enqueues the
 * recurring per-organization jobs. Every key includes a time bucket, so a
 * restart can never produce duplicates.
 */
export async function enqueueRecurring(services: Services): Promise<void> {
  const bucket = Math.floor(Date.now() / RECURRING_INTERVAL_MS);
  const dispatchBucket = Math.floor(Date.now() / DISPATCH_BUCKET_MS);

  await ensureDispatchJob(services, dispatchBucket);

  await services.jobs.enqueue({
    jobType: 'maintenance.cleanup',
    payload: {},
    idempotencyKey: `maintenance.cleanup:${bucket}`,
  });

  const orgs = await services.db
    .select({ id: organizations.id })
    .from(organizations)
    .where(isNull(organizations.deletedAt));

  for (const organization of orgs) {
    await services.jobs.enqueue({
      jobType: 'alerts.repeat',
      organizationId: organization.id,
      payload: { organizationId: organization.id },
      idempotencyKey: `alerts.repeat:${organization.id}:${bucket}`,
    });
  }
}

/**
 * Enqueues one dispatch job unless one is already queued or running. The
 * monitors themselves are still claimed through `monitor_locks`, so even a
 * duplicated dispatch job cannot produce a duplicated probe.
 */
async function ensureDispatchJob(services: Services, dispatchBucket: number): Promise<void> {
  const pending = await services.db
    .select({ id: backgroundJobs.id })
    .from(backgroundJobs)
    .where(
      and(
        eq(backgroundJobs.jobType, 'probes.dispatch'),
        inArray(backgroundJobs.status, ['queued', 'running']),
      ),
    )
    .limit(1);
  if (pending[0]) return;

  await services.jobs.enqueue({
    jobType: 'probes.dispatch',
    payload: { bucket: dispatchBucket },
    idempotencyKey: `probes.dispatch:${dispatchBucket}`,
  });
}

/** Exposed for tests and for the `verify` script. */
export async function queueStats(services: Services): Promise<Record<string, number>> {
  const rows = await services.db
    .select({ status: backgroundJobs.status, total: sql<number>`count(*)::int` })
    .from(backgroundJobs)
    .groupBy(backgroundJobs.status);
  return Object.fromEntries(rows.map((row) => [row.status, Number(row.total)]));
}