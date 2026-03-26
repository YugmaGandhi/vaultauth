import { FastifyRequest, FastifyReply } from 'fastify';
import { sendForbidden } from '../utils/response';
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
