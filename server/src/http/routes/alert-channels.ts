import { Router } from 'express';
import { z } from 'zod';

import {
  alertRuleSchema,
  createAlertChannelSchema,
  testAlertChannelSchema,
  updateAlertChannelSchema,
} from '@sitesentinel/shared';
import type { AlertEventType } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

const deliveryQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  status: z.enum(['queued', 'sent', 'failed', 'suppressed', 'skipped']).optional(),
  monitorId: idParamSchema.optional(),
});

export function alertChannelRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  /* ---------------------------------------------------------------------- */
  /* Channels                                                                */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/',
    asyncHandler(async (req, res) => {
      const verification = await services.emailAdapter.verifyConfiguration();
      res.json({
        channels: await services.alerts.listChannels(req.organization!.id),
        rules: await services.alerts.listRules(req.organization!.id),
        stats: await services.alerts.stats(req.organization!.id),
        email: {
          provider: services.emailAdapter.name,
          deliversMessages: services.emailAdapter.deliversMessages,
          setupHint: services.emailAdapter.setupHint,
          detail: verification.detail,
        },
        note:
          'A delivery marked "sent" means the provider accepted the alert. Email delivery is never claimed: SMTP returns no delivery receipt.',
      });
    }),
  );

  router.post(
    '/',
    requirePermission('alert.manage'),
    validate({ body: createAlertChannelSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as {
        channelType: 'email' | 'webhook';
        name: string;
        enabled: boolean;
        recipients: string[];
        webhookUrl?: string | null;
      };
      const result = await services.alerts.createChannel({
        organizationId: req.organization!.id,
        actorUserId: req.principal!.user.id,
        channel: {
          channelType: body.channelType,
          name: body.name,
          enabled: body.enabled,
          recipients: body.recipients,
          webhookUrl: body.webhookUrl ?? null,
        },
      });
      res.status(201).json({
        channel: result.summary,
        // Shown once. It is stored encrypted and is never returned again.
        webhookSecret: result.secret,
      });
    }),
  );

  router.patch(
    '/:channelId',
    requirePermission('alert.manage'),
    validate({ params: withOrganization({ channelId: idParamSchema }), body: updateAlertChannelSchema }),
    asyncHandler(async (req, res) => {
      const result = await services.alerts.updateChannel({
        organizationId: req.organization!.id,
        channelId: req.params.channelId as string,
        actorUserId: req.principal!.user.id,
        patch: req.body as Record<string, never>,
      });
      res.json({ channel: result.summary, webhookSecret: result.secret });
    }),
  );

  router.delete(
    '/:channelId',
    requirePermission('alert.manage'),
    validate({ params: withOrganization({ channelId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      await services.alerts.deleteChannel(
        req.organization!.id,
        req.params.channelId as string,
        req.principal!.user.id,
      );
      res.status(204).end();
    }),
  );

  router.post(
    '/:channelId/test',
    requirePermission('alert.manage'),
    validate({ params: withOrganization({ channelId: idParamSchema }), body: testAlertChannelSchema }),
    asyncHandler(async (req, res) => {
      const result = await services.alerts.test(
        req.organization!.id,
        req.params.channelId as string,
        { userId: req.principal!.user.id, name: req.principal!.user.displayName ?? req.principal!.user.email },
      );
      res.json(result);
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Rules                                                                   */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/rules/list',
    asyncHandler(async (req, res) => {
      res.json({ rules: await services.alerts.listRules(req.organization!.id) });
    }),
  );

  router.post(
    '/rules',
    requirePermission('alert.manage'),
    validate({ body: alertRuleSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as {
        monitorId: string | null;
        eventType: AlertEventType;
        channelId: string;
        enabled: boolean;
        repeatMinutes: number | null;
        quietHours: { start: string; end: string; timezone: string } | null;
      };
      const rule = await services.alerts.createRule({
        organizationId: req.organization!.id,
        actorUserId: req.principal!.user.id,
        rule: body,
      });
      res.status(201).json({ rule });
    }),
  );

  router.patch(
    '/rules/:ruleId',
    requirePermission('alert.manage'),
    validate({
      params: withOrganization({ ruleId: idParamSchema }),
      body: z.object({
        enabled: z.boolean().optional(),
        repeatMinutes: z.number().int().min(1).max(10_080).nullable().optional(),
        quietHours: z
          .object({
            start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
            end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
            timezone: z.string().trim().min(1).max(64),
          })
          .nullable()
          .optional(),
      }),
    }),
    asyncHandler(async (req, res) => {
      const rule = await services.alerts.updateRule({
        organizationId: req.organization!.id,
        ruleId: req.params.ruleId as string,
        actorUserId: req.principal!.user.id,
        patch: req.body as Record<string, never>,
      });
      res.json({ rule });
    }),
  );

  router.delete(
    '/rules/:ruleId',
    requirePermission('alert.manage'),
    validate({ params: withOrganization({ ruleId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      await services.alerts.deleteRule(
        req.organization!.id,
        req.params.ruleId as string,
        req.principal!.user.id,
      );
      res.status(204).end();
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Delivery history and outbox                                             */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/deliveries',
    validate({ query: deliveryQuery }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as {
        page: number;
        pageSize: number;
        status?: 'queued' | 'sent' | 'failed' | 'suppressed' | 'skipped';
        monitorId?: string;
      };
      res.json(await services.alerts.listDeliveries(req.organization!.id, query));
    }),
  );

  router.get(
    '/outbox',
    asyncHandler(async (req, res) => {
      res.json({
        messages: await services.email.outbox(req.organization!.id, 50),
        counts: await services.email.stats(req.organization!.id),
        note:
          'A message marked "sent" means the email provider accepted it for delivery. SMTP does not report delivery, so SiteSentinel never claims an alert reached an inbox.',
      });
    }),
  );

  return router;
}