import { FastifyInstance, FastifyPluginCallback } from 'fastify';
import { z } from 'zod';
import { sessionService } from '../services/session.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import { sendError, sendSuccess } from '../utils/response';
import { authenticate } from '../middleware/authenticate';

const log = createLogger('SessionRoutes');

const sessionRoutes: FastifyPluginCallback = (
  app: FastifyInstance,
  _options,
  done
) => {
  // ── GET /auth/sessions — list active sessions ──────────
  app.get(
    '/sessions',
    { preHandler: [authenticate] },
    async (request, reply) => {
      try {
        const sessions = await sessionService.listSessions(request.user!.id);
        return sendSuccess(reply, { sessions });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error listing sessions'
        );
        throw err;
      }
    }
  );

  // ── DELETE /auth/sessions/:id — revoke a specific session
  app.delete(
    '/sessions/:id',
    { preHandler: [authenticate] },
    async (request, reply) => {
      const parsed = z
        .object({ id: z.string().uuid('Invalid session ID') })
        .safeParse(request.params);

      if (!parsed.success) {
        return sendError(reply, 400, 'VALIDATION_ERROR', 'Invalid session ID');
      }

      try {
        await sessionService.revokeSession({
          sessionId: parsed.data.id,
          userId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, { message: 'Session revoked successfully' });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error revoking session'
        );
        throw err;
      }
    }
  );

  // ── DELETE /auth/sessions — revoke all sessions ────────
  app.delete(
    '/sessions',
    { preHandler: [authenticate] },
    async (request, reply) => {
      try {
        await sessionService.revokeAllSessions({
          userId: request.user!.id,
          ipAddress: request.ip,
        });
        return sendSuccess(reply, {
          message: 'All sessions revoked successfully',
        });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        log.error(
          { err, reqId: request.id },
          'Unexpected error revoking all sessions'
        );
        throw err;
      }
    }
  );

  done();
};

export { sessionRoutes };
