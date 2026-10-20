/**
 * API router assembly (Part A / A7): everything lives under `/api/v1`.
 */

import { Router, type ErrorRequestHandler, type RequestHandler } from 'express';

import type { Services } from '../../container.js';
import { AppError } from '../../errors.js';
import { asyncHandler, requireAuth, requireAuthenticated, requireOrganization } from '../middleware.js';
import { alertChannelRouter } from './alert-channels.js';
import { authRouter } from './auth.js';
import { dashboardRouter } from './dashboard.js';
import { domainCheckRouter } from './domain-checks.js';
import { exportRouter } from './exports.js';
import { healthRouter } from './health.js';
import { incidentRouter } from './incidents.js';
import { maintenanceRouter } from './maintenance.js';
import { monitorRouter } from './monitors.js';
import { organizationRouter } from './organization.js';
import { publicRouter } from './public.js';
import { sslRouter } from './ssl.js';
import { statusPageRouter } from './status-pages.js';

export function createApiRouter(services: Services): Router {
  const router = Router();

  router.use('/health', healthRouter(services));

  // Public routes are deliberately mounted before authentication and have their
  // own, much tighter rate limit (Part F / F3.8).
  router.use('/public', publicRouter(services));

  /**
   * `requireAuth` only resolves the session when one is present; it never
   * rejects. It must run before the auth router so the protected endpoints
   * mounted inside it (profile, password change, organization creation) see a
   * populated `req.principal`.
   */
  router.use(requireAuth(services));

  router.use('/auth', authRouter(services));

  // Everything below requires a session.
  router.use(requireAuthenticated());

  router.get(
    '/session/context',
    asyncHandler(async (req, res) => {
      res.json({
        user: req.principal!.user,
        memberships: await services.auth.membershipsFor(req.principal!.user.id),
        activeOrganizationId: req.principal!.activeOrganizationId,
      });
    }),
  );

  /**
   * `mergeParams` is required: the sub-routers validate `organizationId`, and
   * without it `req.params.organizationId` is undefined and every tenant-scoped
   * request fails with "organizationId: Required".
   */
  const organizationScoped = Router({ mergeParams: true });
  organizationScoped.use(requireOrganization(services));

  organizationScoped.use('/monitors', monitorRouter(services));
  organizationScoped.use('/incidents', incidentRouter(services));
  organizationScoped.use('/alert-channels', alertChannelRouter(services));
  organizationScoped.use('/maintenance-windows', maintenanceRouter(services));
  organizationScoped.use('/status-pages', statusPageRouter(services));
  organizationScoped.use('/ssl', sslRouter(services));
  organizationScoped.use('/domain-checks', domainCheckRouter(services));
  organizationScoped.use('/exports', exportRouter(services));
  organizationScoped.use('/dashboard', dashboardRouter(services));
  organizationScoped.use('/', organizationRouter(services));

  router.use('/:organizationId', organizationScoped);

  return router;
}

export function notFoundHandler(): RequestHandler {
  return (req, res) => {
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: `No route matches ${req.method} ${req.path}.`,
        requestId: req.requestId,
      },
    });
  };
}

/** One error shape for the whole API; stack traces stay in the log only. */
export function errorHandler(services: Services): ErrorRequestHandler {
  return (error, req, res, _next) => {
    if (res.headersSent) return;

    if (error instanceof AppError) {
      if (error.status >= 500) {
        services.logger.error({ err: error, requestId: req.requestId }, 'request failed');
      } else {
        services.logger.debug(
          { code: error.code, requestId: req.requestId, path: req.path },
          'request rejected',
        );
      }
      res.status(error.status).json({
        error: {
          code: error.code,
          message: error.expose ? error.message : 'Something went wrong. Please try again.',
          ...(error.fields ? { fields: error.fields } : {}),
          ...(error.issues ? { issues: error.issues } : {}),
          requestId: req.requestId,
        },
      });
      return;
    }

    // Zod errors that escaped an explicit validate() call.
    if (error && typeof error === 'object' && 'issues' in error) {
      const issues = (error as { issues: Array<{ path: unknown[]; message: string }> }).issues;
      res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Some of the values you entered are not valid.',
          issues: issues.map((issue) => ({
            path: issue.path.join('.'),
            message: issue.message,
          })),
          requestId: req.requestId,
        },
      });
      return;
    }

    if (error instanceof SyntaxError && 'body' in error) {
      res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Request body is not valid JSON.',
          requestId: req.requestId,
        },
      });
      return;
    }

    services.logger.error({ err: error, requestId: req.requestId }, 'unhandled error');
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Something went wrong. Please try again.',
        requestId: req.requestId,
      },
    });
  };
}