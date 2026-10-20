import { Router } from 'express';

import {
  acknowledgeIncidentSchema,
  incidentListQuerySchema,
  incidentNoteSchema,
  incidentUpdateSchema,
  resolveIncidentSchema,
} from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

export function incidentRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    validate({ query: incidentListQuerySchema }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as Parameters<typeof services.incidents.list>[1];
      res.json(await services.incidents.list(req.organization!.id, query));
    }),
  );

  router.get(
    '/:incidentId',
    validate({ params: withOrganization({ incidentId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      res.json({
        incident: await services.incidents.detail(req.organization!.id, req.params.incidentId as string),
      });
    }),
  );

  router.post(
    '/:incidentId/acknowledge',
    requirePermission('incident.manage'),
    validate({ params: withOrganization({ incidentId: idParamSchema }), body: acknowledgeIncidentSchema }),
    asyncHandler(async (req, res) => {
      const incidentId = req.params.incidentId as string;
      const incident = await services.incidents.acknowledge({
        organizationId: req.organization!.id,
        incidentId,
        actorUserId: req.principal!.user.id,
        note: (req.body as { note?: string }).note ?? null,
      });

      // Only a first acknowledgement notifies; a repeat is deduplicated by the
      // delivery idempotency key.
      const monitorId = incident.affectedMonitors[0]?.id;
      let alertsQueued = 0;
      if (monitorId && incident.status === 'acknowledged') {
        alertsQueued = await services.alerts.queueForIncident({
          organizationId: req.organization!.id,
          incidentId,
          monitorId,
          eventType: 'incident_acknowledged',
        });
      }
      res.json({ incident, alertsQueued });
    }),
  );

  router.post(
    '/:incidentId/notes',
    requirePermission('incident.manage'),
    validate({ params: withOrganization({ incidentId: idParamSchema }), body: incidentNoteSchema }),
    asyncHandler(async (req, res) => {
      const incident = await services.incidents.addNote({
        organizationId: req.organization!.id,
        incidentId: req.params.incidentId as string,
        actorUserId: req.principal!.user.id,
        message: (req.body as { message: string }).message,
      });
      res.status(201).json({ incident });
    }),
  );

  router.patch(
    '/:incidentId',
    requirePermission('incident.manage'),
    validate({ params: withOrganization({ incidentId: idParamSchema }), body: incidentUpdateSchema }),
    asyncHandler(async (req, res) => {
      const incident = await services.incidents.update({
        organizationId: req.organization!.id,
        incidentId: req.params.incidentId as string,
        actorUserId: req.principal!.user.id,
        ...(req.body as Record<string, never>),
      });
      res.json({ incident });
    }),
  );

  router.post(
    '/:incidentId/resolve',
    requirePermission('incident.manage'),
    validate({ params: withOrganization({ incidentId: idParamSchema }), body: resolveIncidentSchema }),
    asyncHandler(async (req, res) => {
      const incidentId = req.params.incidentId as string;
      const reason = (req.body as { reason: string }).reason;
      const incident = await services.incidents.resolve({
        organizationId: req.organization!.id,
        incidentId,
        actorUserId: req.principal!.user.id,
        reason,
      });

      const monitorId = incident.affectedMonitors[0]?.id;
      let alertsQueued = 0;
      if (monitorId) {
        alertsQueued = await services.alerts.queueForIncident({
          organizationId: req.organization!.id,
          incidentId,
          monitorId,
          eventType: 'incident_resolved',
        });
      }
      res.json({ incident, alertsQueued });
    }),
  );

  return router;
}