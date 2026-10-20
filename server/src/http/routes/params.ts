/**
 * Route-level Zod schemas for path parameters.
 *
 * `organizationId` is declared here because the organization-scoped router is
 * mounted with `mergeParams: true`: without that flag `req.params.organizationId`
 * is `undefined` and every tenant-scoped route would fail validation.
 */

import { z } from 'zod';

export const idParamSchema = z.string().uuid();
export const organizationParamSchema = z.object({ organizationId: idParamSchema });

export function withOrganization(params: z.ZodRawShape) {
  return z.object({ organizationId: idParamSchema, ...params });
}