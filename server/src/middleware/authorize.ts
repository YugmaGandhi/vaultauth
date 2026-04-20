import { FastifyRequest, FastifyReply } from 'fastify';
import { sendError, sendForbidden } from '../utils/response';
import { mfaService } from '../services/mfa.service';
import { createLogger } from '../utils/logger';

const log = createLogger('AuthorizeMiddleware');

// Returns a middleware function that checks for a specific permission
// Usage: { preHandler: [authenticate, authorize('read:users')] }
export function authorize(requiredPermission: string) {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user) {
      return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
    }

    if (!user.permissions.includes(requiredPermission)) {
      log.warn(
        {
          userId: user.id,
          required: requiredPermission,
          has: user.permissions,
        },
        'Permission denied'
      );
      return sendForbidden(
        reply,
        'FORBIDDEN',
        'You do not have permission to perform this action'
      );
    }
  };
}

// ── Org-scoped middleware ────────────────────────────────

// Asserts the user has an active org context
// Use this on endpoints that require an org but don't need a specific permission
export function requireOrg() {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user) {
      return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
    }

    if (!user.orgId) {
      return sendError(
        reply,
        400,
        'NO_ACTIVE_ORG',
        'No active organization. Call POST /auth/set-active-org first.'
      );
    }
  };
}

// Validates that URL :orgId matches the user's active org
// Super-admins bypass this check — they can manage any org
// Must come after authenticate + requireOrg in the preHandler chain
export function resolveOrgFromParam() {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;
    const { orgId } = request.params as { orgId?: string };

    if (!user || !orgId) return;

    // Super-admins can operate on any org
    if (user.roles.includes('super-admin')) return;

    if (user.orgId !== orgId) {
      log.warn(
        { userId: user.id, activeOrg: user.orgId, requestedOrg: orgId },
        'Org mismatch — user tried to access a different org'
      );
      return sendForbidden(
        reply,
        'FORBIDDEN',
        'You do not have access to this organization'
      );
    }
  };
}

// Checks org-level permissions (from orgPermissions in the JWT)
// Usage: { preHandler: [authenticate, requireOrg(), resolveOrgFromParam(), authorizeOrg('write:members')] }
export function authorizeOrg(requiredPermission: string) {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user) {
      return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
    }

    if (!user.orgPermissions.includes(requiredPermission)) {
      log.warn(
        {
          userId: user.id,
          orgId: user.orgId,
          required: requiredPermission,
          has: user.orgPermissions,
        },
        'Org permission denied'
      );
      return sendForbidden(
        reply,
        'FORBIDDEN',
        'You do not have permission to perform this action in this organization'
      );
    }
  };
}

// Checks the user's built-in org membership role (owner/admin/member)
// Usage: { preHandler: [authenticate, requireOrg(), resolveOrgFromParam(), authorizeOrgRole('owner', 'admin')] }
export function authorizeOrgRole(...allowedRoles: string[]) {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user) {
      return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
    }

    if (!user.orgRole || !allowedRoles.includes(user.orgRole)) {
      log.warn(
        {
          userId: user.id,
          orgId: user.orgId,
          required: allowedRoles,
          has: user.orgRole,
        },
        'Org role denied'
      );
      return sendForbidden(
        reply,
        'FORBIDDEN',
        'You do not have the required role in this organization'
      );
    }
  };
}

// Blocks org-scoped requests when the org enforces MFA but the user has not enrolled.
// Must come after authenticate + requireOrg() in the preHandler chain so req.user
// and req.user.orgId are guaranteed to be set.
// Super-admins bypass this check — they always satisfy any org policy.
export function requireMfaIfEnforced() {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user || !user.orgId) return; // Guard — prior middleware ensures these exist

    // Super-admins can always access org endpoints regardless of MFA policy
    if (user.roles.includes('super-admin')) return;

    const satisfies = await mfaService.userSatisfiesOrgMfaPolicy(
      user.id,
      user.orgId
    );

    if (!satisfies) {
      log.warn(
        { userId: user.id, orgId: user.orgId },
        'Org MFA policy not satisfied — blocking request'
      );
      return sendForbidden(
        reply,
        'MFA_REQUIRED',
        'This organization requires MFA. Please enroll at POST /auth/mfa/setup.'
      );
    }
  };
}

// Checks if user has ANY of the required permissions
export function authorizeAny(...requiredPermissions: string[]) {
  return async (
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    const user = request.user;

    if (!user) {
      return sendForbidden(reply, 'FORBIDDEN', 'Authentication required');
    }

    const hasAny = requiredPermissions.some((p) =>
      user.permissions.includes(p)
    );

    if (!hasAny) {
      log.warn(
        {
          userId: user.id,
          required: requiredPermissions,
          has: user.permissions,
        },
        'Permission denied'
      );
      return sendForbidden(
        reply,
        'FORBIDDEN',
        'You do not have permission to perform this action'
      );
    }
  };
}
