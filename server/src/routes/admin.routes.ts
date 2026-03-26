import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authenticate } from '../middleware/authenticate';
import { authorize } from '../middleware/authorize';
import { sendSuccess, sendValidationError } from '../utils/response';
import { auditRepository } from '../repositories/audit.repository';

export function adminRoutes(
  app: FastifyInstance,
  _options: unknown,
  done: () => void
) {
  // ── GET /admin/audit-logs ─────────────────────────────
  app.get(
    '/audit-logs',
    { preHandler: [authenticate, authorize('read:audit-logs')] },
    async (request, reply) => {
      const parsed = z
        .object({
          page: z.coerce.number().default(1),
          limit: z.coerce.number().max(100).default(20),
          userId: z.string().uuid().optional(),
        })
        .safeParse(request.query);

      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((i) => ({
            field: i.path.join('.'),
            message: i.message,
          }))
        );
      }

      const logs = await auditRepository.findAll(parsed.data);
      return sendSuccess(reply, {
        logs,
        meta: { page: parsed.data.page, limit: parsed.data.limit },
      });
    }
  );

  done();
}
