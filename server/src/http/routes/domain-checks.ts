import { Router } from 'express';

import type { Services } from '../../container.js';
import { asyncHandler } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

/**
 * `GET /domain-checks/:monitorId`.
 *
 * SiteSentinel ships without an RDAP or WHOIS data source, so this endpoint
 * reports `unavailable` with the reason instead of an estimated expiry date
 * (Part F / F1, F4).
 */
export function domainCheckRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/:monitorId',
    validate({ params: withOrganization({ monitorId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      const monitorId = req.params.monitorId as string;
      const monitor = await services.monitors.requireMonitor(req.organization!.id, monitorId);
      const report = await services.monitors.domainReport(req.organization!.id, monitorId);
      res.json({
        domainCheck:
          report ?? {
            host: monitor.targetUrlOrHost,
            checkedAt: monitor.createdAt.toISOString(),
            status: 'unavailable' as const,
            expiresAt: null,
            source: null,
            safeMessage:
              'Domain expiry monitoring has no RDAP or WHOIS data source configured, so no expiry date is reported and none is estimated.',
          },
        note: 'This endpoint only reports data a real RDAP or WHOIS source provided. SiteSentinel never guesses an expiry date.',
      });
    }),
  );

  return router;
}