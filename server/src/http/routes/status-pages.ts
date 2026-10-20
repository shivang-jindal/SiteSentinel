import { Router } from 'express';
import { z } from 'zod';

import { createStatusPageSchema, updateStatusPageSchema } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

const deleteBody = z.object({ confirmation: z.literal('DELETE') });

export function statusPageRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    asyncHandler(async (req, res) => {
      res.json({
        pages: await services.statusPages.list(req.organization!.id),
        note: 'A public page exposes only the monitors you select and only their public label. Unpublished pages answer 404 so they cannot be discovered by guessing the slug.',
      });
    }),
  );

  router.post(
    '/',
    requirePermission('status_page.manage'),
    validate({ body: createStatusPageSchema }),
    asyncHandler(async (req, res) => {
      const defaults = await services.organizations.defaults(req.organization!.id);
      const body = req.body as {
        title: string;
        description: string | null;
        logoUrl: string | null;
        published: boolean;
        customDomain: string | null;
        monitors: Array<{ monitorId: string; publicLabel: string | null; sortOrder: number }>;
      };
      const page = await services.statusPages.create({
        organizationId: req.organization!.id,
        actorUserId: req.principal!.user.id,
        maxStatusPages: defaults.maxStatusPages,
        page: body,
      });
      res.status(201).json({
        page,
        customDomainVerification:
          'Custom domains are not verified in this build. The page is served from its generated slug URL until DNS verification is implemented.',
      });
    }),
  );

  router.get(
    '/:pageId',
    validate({ params: withOrganization({ pageId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      res.json({ page: await services.statusPages.get(req.organization!.id, req.params.pageId as string) });
    }),
  );

  router.patch(
    '/:pageId',
    requirePermission('status_page.manage'),
    validate({ params: withOrganization({ pageId: idParamSchema }), body: updateStatusPageSchema }),
    asyncHandler(async (req, res) => {
      const page = await services.statusPages.update({
        organizationId: req.organization!.id,
        pageId: req.params.pageId as string,
        actorUserId: req.principal!.user.id,
        patch: req.body as Record<string, never>,
      });
      res.json({ page });
    }),
  );

  router.delete(
    '/:pageId',
    requirePermission('status_page.manage'),
    validate({ params: withOrganization({ pageId: idParamSchema }), body: deleteBody }),
    asyncHandler(async (req, res) => {
      await services.statusPages.delete(
        req.organization!.id,
        req.params.pageId as string,
        req.principal!.user.id,
      );
      res.status(204).end();
    }),
  );

  return router;
}