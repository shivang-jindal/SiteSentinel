import { Router } from 'express';

import {
  createMaintenanceWindowSchema,
  maintenanceListQuerySchema,
  updateMaintenanceWindowSchema,
} from '@sitesentinel/shared';
import type { MaintenanceRecurrence } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

interface MaintenanceBody {
  name: string;
  startsAt: string;
  endsAt: string;
  timezone: string;
  recurrence: MaintenanceRecurrence | null;
  reason: string | null;
  enabled: boolean;
  suppressNotifications: boolean;
  monitorIds: string[];
}

export function maintenanceRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    validate({ query: maintenanceListQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as { includeInactive: boolean };
      const windows = await services.maintenance.list(req.organization!.id, query.includeInactive);
      res.json({
        windows,
        timezone: req.organization!.timezone,
        note: 'A maintenance window suppresses notifications only. Checks keep running and recorded results are never rewritten.',
      });
    }),
  );

  router.post(
    '/',
    requirePermission('maintenance.manage'),
    validate({ body: createMaintenanceWindowSchema }),
    asyncHandler(async (req, res) => {
      const defaults = await services.organizations.defaults(req.organization!.id);
      if (defaults.maxMaintenanceWindows <= 0) {
        res.status(403).json({
          error: {
            code: 'FORBIDDEN',
            message: 'Maintenance windows are disabled for this organization.',
            requestId: req.requestId,
          },
        });
        return;
      }
      const body = req.body as MaintenanceBody;
      const window = await services.maintenance.create({
        organizationId: req.organization!.id,
        actorUserId: req.principal!.user.id,
        ...body,
        startsAt: new Date(body.startsAt),
        endsAt: new Date(body.endsAt),
      });
      res.status(201).json({ window });
    }),
  );

  router.get(
    '/:windowId',
    validate({ params: withOrganization({ windowId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      res.json({
        window: await services.maintenance.get(req.organization!.id, req.params.windowId as string),
      });
    }),
  );

  router.patch(
    '/:windowId',
    requirePermission('maintenance.manage'),
    validate({ params: withOrganization({ windowId: idParamSchema }), body: updateMaintenanceWindowSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as Partial<Omit<MaintenanceBody, 'startsAt' | 'endsAt'>> & {
        startsAt?: string;
        endsAt?: string;
      };
      const window = await services.maintenance.update(
        req.organization!.id,
        req.params.windowId as string,
        req.principal!.user.id,
        {
          ...(body.name !== undefined ? { name: body.name } : {}),
          ...(body.timezone !== undefined ? { timezone: body.timezone } : {}),
          ...(body.recurrence !== undefined ? { recurrence: body.recurrence } : {}),
          ...(body.reason !== undefined ? { reason: body.reason } : {}),
          ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
          ...(body.suppressNotifications !== undefined
            ? { suppressNotifications: body.suppressNotifications }
            : {}),
          ...(body.monitorIds !== undefined ? { monitorIds: body.monitorIds } : {}),
          ...(body.startsAt ? { startsAt: new Date(body.startsAt) } : {}),
          ...(body.endsAt ? { endsAt: new Date(body.endsAt) } : {}),
        },
      );
      res.json({ window });
    }),
  );

  router.delete(
    '/:windowId',
    requirePermission('maintenance.manage'),
    validate({ params: withOrganization({ windowId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      await services.maintenance.remove(
        req.organization!.id,
        req.params.windowId as string,
        req.principal!.user.id,
      );
      res.status(204).end();
    }),
  );

  return router;
}