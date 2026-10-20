import { Router } from 'express';
import { z } from 'zod';

import {
  changeMemberRoleSchema,
  createInvitationSchema,
  transferOwnershipSchema,
  updateMonitoringSettingsSchema,
  updateOrganizationSchema,
} from '@sitesentinel/shared';

import type { Role } from '@sitesentinel/shared';

import type { Services } from '../../container.js';
import { asyncHandler, requirePermission } from '../middleware.js';
import { validate } from '../validate.js';
import { idParamSchema, withOrganization } from './params.js';

const deleteBody = z.object({ confirmation: z.string().trim().min(1) });

export function organizationRouter(services: Services): Router {
  const router = Router({ mergeParams: true });

  router.get(
    '/',
    asyncHandler(async (req, res) => {
      const [organization, settings, defaults, probe] = await Promise.all([
        services.organizations.get(req.organization!.id),
        services.organizations.getSettings(req.organization!.id),
        services.organizations.defaults(req.organization!.id),
        services.probes.health(),
      ]);
      res.json({
        organization,
        role: req.organizationRole,
        permissions: req.permissions,
        settings,
        defaults,
        probe: {
          detail: probe.detail,
          maxRedirects: services.probes.maxRedirects,
          maxResponseBytes: services.probes.maxResponseBytes,
          allowedHttpPorts: [...services.probes.allowedHttpPorts],
          allowedTcpPorts: [...services.probes.allowedTcpPorts],
          domainExpiryAvailable: false,
        },
        email: {
          provider: services.emailAdapter.name,
          deliversMessages: services.emailAdapter.deliversMessages,
          setupHint: services.emailAdapter.setupHint,
        },
      });
    }),
  );

  router.patch(
    '/',
    requirePermission('settings.manage'),
    validate({ body: updateOrganizationSchema }),
    asyncHandler(async (req, res) => {
      res.json({
        organization: await services.organizations.update(
          req.organization!.id,
          req.principal!.user.id,
          req.body as Record<string, never>,
        ),
      });
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Monitoring settings                                                     */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/settings/monitoring',
    asyncHandler(async (req, res) => {
      res.json({
        settings: await services.organizations.getSettings(req.organization!.id),
        defaults: await services.organizations.defaults(req.organization!.id),
        timezone: req.organization!.timezone,
      });
    }),
  );

  router.patch(
    '/settings/monitoring',
    requirePermission('settings.manage'),
    validate({ body: updateMonitoringSettingsSchema }),
    asyncHandler(async (req, res) => {
      const settings = await services.organizations.updateSettings(
        req.organization!.id,
        req.principal!.user.id,
        req.body as Record<string, never>,
      );
      res.json({ settings });
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Members and invitations                                                */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/members',
    asyncHandler(async (req, res) => {
      res.json({
        members: await services.organizations.listMembers(req.organization!.id),
        myRole: req.organizationRole,
      });
    }),
  );

  router.post(
    '/members/invitations',
    requirePermission('member.manage'),
    validate({ body: createInvitationSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as { email: string; role: Role };
      const invitation = await services.organizations.invite({
        organizationId: req.organization!.id,
        email: body.email,
        role: body.role,
        invitedBy: req.principal!.user.id,
        actorRole: req.organizationRole!,
      });

      const acceptUrl = `${services.config.appUrl}/accept-invitation?token=${invitation.token}`;
      res.status(201).json({
        invitation: {
          id: invitation.invitationId,
          expiresAt: invitation.expiresAt.toISOString(),
          acceptUrl,
          // The link is shown once here. It is never emailed automatically,
          // because no email provider is guaranteed to be configured.
          emailed: false,
        },
      });
    }),
  );

  router.get(
    '/members/invitations',
    requirePermission('member.manage'),
    asyncHandler(async (req, res) => {
      res.json({ invitations: await services.organizations.listInvitations(req.organization!.id) });
    }),
  );

  router.delete(
    '/members/invitations/:invitationId',
    requirePermission('member.manage'),
    validate({ params: withOrganization({ invitationId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      await services.organizations.revokeInvitation(
        req.organization!.id,
        req.params.invitationId as string,
        req.principal!.user.id,
      );
      res.status(204).end();
    }),
  );

  router.patch(
    '/members/:memberId',
    requirePermission('member.manage'),
    validate({
      params: withOrganization({ memberId: idParamSchema }),
      body: changeMemberRoleSchema,
    }),
    asyncHandler(async (req, res) => {
      const member = await services.organizations.changeMemberRole({
        organizationId: req.organization!.id,
        membershipId: req.params.memberId as string,
        actorUserId: req.principal!.user.id,
        actorRole: req.organizationRole!,
        role: (req.body as { role: Role }).role,
      });
      res.json({ member });
    }),
  );

  router.delete(
    '/members/:memberId',
    requirePermission('member.manage'),
    validate({ params: withOrganization({ memberId: idParamSchema }) }),
    asyncHandler(async (req, res) => {
      await services.organizations.removeMember({
        organizationId: req.organization!.id,
        membershipId: req.params.memberId as string,
        actorUserId: req.principal!.user.id,
        actorRole: req.organizationRole!,
      });
      res.status(204).end();
    }),
  );

  router.post(
    '/transfer-ownership',
    requirePermission('ownership.transfer'),
    validate({ body: transferOwnershipSchema }),
    asyncHandler(async (req, res) => {
      const body = req.body as { membershipId: string; confirmation: string };
      const member = await services.organizations.transferOwnership({
        organizationId: req.organization!.id,
        membershipId: body.membershipId,
        actorUserId: req.principal!.user.id,
        confirmation: body.confirmation,
      });
      res.json({ member });
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Organization deletion                                                   */
  /* ---------------------------------------------------------------------- */

  router.post(
    '/delete',
    requirePermission('organization.delete'),
    validate({ body: deleteBody }),
    asyncHandler(async (req, res) => {
      await services.organizations.softDelete(
        req.organization!.id,
        req.principal!.user.id,
        (req.body as { confirmation: string }).confirmation,
      );
      res.status(204).end();
    }),
  );

  /* ---------------------------------------------------------------------- */
  /* Audit log                                                               */
  /* ---------------------------------------------------------------------- */

  router.get(
    '/audit',
    requirePermission('audit.view'),
    validate({
      query: z.object({
        page: z.coerce.number().int().min(1).default(1),
        pageSize: z.coerce.number().int().min(1).max(100).default(25),
        entityType: z.string().trim().max(50).optional(),
        entityId: z.string().trim().max(80).optional(),
        action: z.string().trim().max(80).optional(),
      }),
    }),
    asyncHandler(async (req, res) => {
      const query = req.query as unknown as {
        page: number;
        pageSize: number;
        entityType?: string;
        entityId?: string;
        action?: string;
      };
      res.json(await services.audit.list(req.organization!.id, query));
    }),
  );

  return router;
}