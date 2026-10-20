import { Router } from 'express';

import { createExportSchema } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';

type ExportDataset = 'monitors' | 'checks' | 'incidents' | 'alert_deliveries';

export function exportRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    asyncHandler(async (req, res) => {
      res.json({
        datasets: [
          { id: 'monitors', label: 'Monitors' },
          { id: 'checks', label: 'Check history' },
          { id: 'incidents', label: 'Incidents' },
          { id: 'alert_deliveries', label: 'Alert delivery history' },
        ],
        note: 'Exports contain only this organization\'s data, are audit-logged and are formula-injection escaped.',
      });
    }),
  );

  router.post(
    '/',
    requirePermission('report.export'),
    validate({ body: createExportSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as {
        dataset: ExportDataset;
        monitorId?: string;
        from?: string;
        to?: string;
      };
      const result = await services.exports.build(
        req.organization!.id,
        { dataset: body.dataset, ...(body.monitorId ? { monitorId: body.monitorId } : {}), ...(body.from ? { from: body.from } : {}), ...(body.to ? { to: body.to } : {}) },
        req.principal!.user.id,
        { requestId: req.requestId },
      );
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      res.setHeader('X-Row-Count', String(result.rowCount));
      res.send(result.csv);
    }),
  );

  return router;
}