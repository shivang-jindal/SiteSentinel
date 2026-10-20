import { Router } from 'express';
import { z } from 'zod';

import {
  bulkPauseSchema,
  checkListQuerySchema,
  createMonitorSchema,
  monitorListQuerySchema,
  pauseMonitorSchema,
  updateMonitorSchema,
  uptimeQuerySchema,
} from '@sitesentinel/shared';
import type { MonitorType } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

const archiveBody = z.object({ confirmation: z.literal('ARCHIVE') });

export function monitorRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    validate({ query: monitorListQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as Parameters<typeof services.monitors.list>[1];
      res.json(await services.monitors.list(req.organization!.id, query));
    }),
  );

  router.post(
    '/',
    requirePermission('monitor.create'),
    validate({ body: createMonitorSchema }),
    asyncHandler(async (req, res) => {
      const defaults = await services.organizations.defaults(req.organization!.id);
      const body = req.body as {
        monitorType: MonitorType;
        target: string;
        name: string;
        intervalSeconds: number;
        timeoutMs: number;
        enabled: boolean;
        tags: string[];
        expectedStatusCodes?: number[] | null;
        keywordMatch?: string | null;
        consecutiveFailureThreshold: number;
        recoverySuccessThreshold: number;
      };

      const monitor = await services.monitors.create({
        organizationId: req.organization!.id,
        actorUserId: req.principal!.user.id,
        minIntervalSeconds: defaults.minIntervalSeconds,
        maxMonitors: defaults.maxMonitors,
        defaultIntervalSeconds: defaults.intervalSeconds,
        defaultTimeoutMs: defaults.timeoutMs,
        defaultFailureThreshold: defaults.consecutiveFailureThreshold,
        defaultRecoveryThreshold: defaults.recoverySuccessThreshold,
        monitor: {
          monitorType: body.monitorType as 'http' | 'http_keyword' | 'tcp' | 'ssl_certificate',
          target: body.target,
          name: body.name,
          intervalSeconds: body.intervalSeconds,
          timeoutMs: body.timeoutMs,
          enabled: body.enabled,
          tags: body.tags,
          ...(body.expectedStatusCodes ? { expectedStatusCodes: body.expectedStatusCodes } : {}),
          ...(body.keywordMatch !== undefined ? { keywordMatch: body.keywordMatch } : {}),
          consecutiveFailureThreshold: body.consecutiveFailureThreshold,
          recoverySuccessThreshold: body.recoverySuccessThreshold,
        },
      });
      res.status(201).json({ monitor });
    }),
  );

  /**
   * Bulk pause/resume. Requires the typed confirmation from
   * `bulkPauseSchema` so it cannot happen from a stray click (Part F / F3.2).
   */
  router.post(
    '/bulk',
    requirePermission('monitor.pause'),
    validate({ body: bulkPauseSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as { monitorIds: string[]; enabled: boolean };
      res.json(
        await services.monitors.setEnabledBulk({
          organizationId: req.organization!.id,
          actorUserId: req.principal!.user.id,
          monitorIds: body.monitorIds,
          enabled: body.enabled,
        }),
      );
    }),
  );

  router.get(
    '/:monitorId',
    validate({ params: withOrganization({ monitorId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      res.json({
        monitor: await services.monitors.detail(req.organization!.id, req.params.monitorId as string),
      });
    }),
  );

  router.patch(
    '/:monitorId',
    requirePermission('monitor.edit'),
    validate({ params: withOrganization({ monitorId: idParamSchema }), body: updateMonitorSchema }),
    asyncHandler(async (req, res) => {
      const defaults = await services.organizations.defaults(req.organization!.id);
      const monitor = await services.monitors.update({
        organizationId: req.organization!.id,
        monitorId: req.params.monitorId as string,
        actorUserId: req.principal!.user.id,
        minIntervalSeconds: defaults.minIntervalSeconds,
        patch: req.body as Record<string, never>,
      });
      res.json({ monitor });
    }),
  );

  router.post(
    '/:monitorId/pause',
    requirePermission('monitor.pause'),
    validate({ params: withOrganization({ monitorId: idParamSchema }), body: pauseMonitorSchema }),
    asyncHandler(async (req, res) => {
      const monitor = await services.monitors.setEnabled({
        organizationId: req.organization!.id,
        monitorId: req.params.monitorId as string,
        actorUserId: req.principal!.user.id,
        enabled: false,
        reason: (req.body as { reason?: string }).reason ?? null,
      });
      res.json({ monitor });
    }),
  );

  router.post(
    '/:monitorId/resume',
    requirePermission('monitor.pause'),
    validate({ params: withOrganization({ monitorId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      const monitor = await services.monitors.setEnabled({
        organizationId: req.organization!.id,
        monitorId: req.params.monitorId as string,
        actorUserId: req.principal!.user.id,
        enabled: true,
      });
      res.json({ monitor });
    }),
  );

  router.post(
    '/:monitorId/archive',
    requirePermission('monitor.delete'),
    validate({ params: withOrganization({ monitorId: idParamSchema }), body: archiveBody }),
    asyncHandler(async (req, res) => {
      const result = await services.monitors.archive({
        organizationId: req.organization!.id,
        monitorId: req.params.monitorId as string,
        actorUserId: req.principal!.user.id,
      });
      res.json(result);
    }),
  );

  router.get(
    '/:monitorId/checks',
    validate({ params: withOrganization({ monitorId: idParamSchema }), query: checkListQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as { page: number; pageSize: number; result: 'all' | 'success' | 'failure' };
      res.json(
        await services.monitors.checks(req.organization!.id, req.params.monitorId as string, query),
      );
    }),
  );

  router.get(
    '/:monitorId/uptime',
    validate({ params: withOrganization({ monitorId: idParamSchema }), query: uptimeQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as { from?: string; to?: string; buckets: number };
      res.json(
        await services.monitors.uptime(req.organization!.id, req.params.monitorId as string, {
          ...(query.from ? { from: query.from } : {}),
          ...(query.to ? { to: query.to } : {}),
          buckets: query.buckets,
        }),
      );
    }),
  );

  return router;
}