import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authService } from '../services/auth.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import { sendCreated, sendError, sendValidationError } from '../utils/response';

const log = createLogger('AuthRoutes');

// Zod schema for register request body
const registerSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .toLowerCase()
    .trim(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters'),
});

export function authRoutes(app: FastifyInstance) {
  // ── POST /auth/register ─────────────────────────────────
  app.post('/auth/register', async (request, reply) => {
    // Step 1 — Validate request body
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    // Step 2 — Call service
    try {
      const result = await authService.register({
        email: parsed.data.email,
        password: parsed.data.password,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendCreated(reply, result);
    } catch (err) {
      // Handle known application errors
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }

      // Unknown error — let global error handler deal with it
      log.error({ err, reqId: request.id }, 'Unexpected error in register');
      throw err;
    }
  });
}
