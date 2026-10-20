import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';

import { publicStatusQuerySchema } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler } from '../middleware.js';
import { validate } from '../validate.js';

/**
 * Unauthenticated, read-only routes (Part F / F3.8, F7).
 *
 * - the status page answers only for a published slug; an unpublished page is
 *   indistinguishable from a slug that does not exist;
 * - nothing internal leaks: no monitor id, target, latency, keyword or note;
 * - the route is rate limited far more tightly than the authenticated API.
 */
export function publicRouter(services: Services): Router {
  const router = Router();

  const publicLimit = rateLimit({
    windowMs: services.config.rateLimit.windowMs,
    limit: Math.max(30, Math.floor(services.config.rateLimit.max / 4)),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many status page requests. Please slow down.',
          requestId: (res.req as { requestId?: string }).requestId ?? '',
        },
      });
    },
  });

  const statusParams = z.object({ slug: z.string().trim().min(8).max(64) });

  router.get(
    '/status/:slug',
    publicLimit,
    validate({ params: statusParams, query: publicStatusQuerySchema }),
    asyncHandler(async (req, res) => {
      const { slug } = req.params as { slug: string };
      const query = req.query as unknown as { days: number };
      const page = await services.statusPages.publicView(slug, query.days);
      res.set('Cache-Control', 'no-store');
      res.json(page);
    }),
  );

  return router;
}