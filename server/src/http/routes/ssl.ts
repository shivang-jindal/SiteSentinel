import { Router } from 'express';

import type { Services } from '../../container.js';
import { asyncHandler } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

/**
 * `GET /ssl/:monitorId` and `GET /domain-checks/:monitorId`.
 *
 * The same router is mounted at both paths. Nothing here triggers a probe: it
 * only reports what the worker actually observed, and says "unavailable" when
 * no reliable source or handshake exists (Part F / F4, F7).
 */
export function sslRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/:monitorId',
    validate({ params: withOrganization({ monitorId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      const monitorId = req.params.monitorId as string;
      const monitor = await services.monitors.requireMonitor(req.organization!.id, monitorId);
      res.json({
        ssl: await services.monitors.sslReport(req.organization!.id, monitorId),
        monitor: { id: monitor.id, name: monitor.name, monitorType: monitor.monitorType },
        note: 'Certificate details come from a real TLS handshake. An unavailable probe is reported as unavailable, never as an expired certificate.',
      });
    }),
  );

  return router;
}