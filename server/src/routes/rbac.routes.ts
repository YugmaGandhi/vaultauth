import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate } from '../middleware/authenticate';
import { authorize } from '../middleware/authorize';
import {
  sendSuccess,
  sendError,
  sendValidationError,
  sendNotFound,
} from '../utils/response';
import { rbacService } from '../services/rbac.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';

const log = createLogger('RBACRoutes');

export function rbacRoutes(
  app: FastifyInstance,
  _options: unknown,
  done: () => void
) {
  // ── GET /roles ────────────────────────────────────────
  app.get(
    '/roles',
    { preHandler: [authenticate, authorize('read:roles')] },
    async (_request, reply) => {
      const allRoles = await rbacService.getAllRoles();
      return sendSuccess(reply, { roles: allRoles });
    }
  );

  // ── GET /users/:userId/roles ──────────────────────────
  app.get(
    '/users/:userId/roles',
    { preHandler: [authenticate, authorize('read:roles')] },
    async (request, reply) => {
      const { userId } = request.params as { userId: string };
      const result = await rbacService.getUserRolesAndPermissions(userId);
      return sendSuccess(reply, { userId, ...result });
    }
  );

  // ── POST /users/:userId/roles ─────────────────────────
  app.post(
    '/users/:userId/roles',
    { preHandler: [authenticate, authorize('write:roles')] },
    async (request, reply) => {
      const { userId } = request.params as { userId: string };

      const parsed = z
        .object({
          roleId: z.string().uuid('Invalid role ID'),
        })
        .safeParse(request.body);

      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      try {
        await rbacService.assignRoleToUser(
          userId,
          parsed.data.roleId,
          request.user!.id
        );
        return sendSuccess(reply, { message: 'Role assigned successfully' });
      } catch (err) {
        if (err instanceof Error) {
          if (err.message === 'USER_NOT_FOUND') {
            return sendNotFound(reply, 'USER_NOT_FOUND', 'User not found');
          }
          if (err.message === 'ROLE_NOT_FOUND') {
            return sendNotFound(reply, 'ROLE_NOT_FOUND', 'Role not found');
          }
        }
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error({ err }, 'Failed to assign role');
        throw err;
      }
    }
  );

  // ── DELETE /users/:userId/roles/:roleId ───────────────
  app.delete(
    '/users/:userId/roles/:roleId',
    { preHandler: [authenticate, authorize('write:roles')] },
    async (request, reply) => {
      const { userId, roleId } = request.params as {
        userId: string;
        roleId: string;
      };

      await rbacService.removeRoleFromUser(userId, roleId);
      return sendSuccess(reply, { message: 'Role removed successfully' });
    }
  );

  done();
}
