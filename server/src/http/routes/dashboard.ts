import { Router } from 'express';

import { dashboardQuerySchema } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler } from '../middleware.js';
import { validate } from '../validate.js';

export function dashboardRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/summary',
    validate({ query: dashboardQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as { from?: string; to?: string; hours?: number };
      res.json(
        await services.dashboard.summary(req.organization!.id, {
          ...(query.from ? { from: query.from } : {}),
          ...(query.to ? { to: query.to } : {}),
          ...(query.hours !== undefined ? { hours: query.hours } : {}),
        }),
      );
    }),
  );

  return router;
}