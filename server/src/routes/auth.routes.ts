import { FastifyInstance, FastifyPluginCallback } from 'fastify';
import { z } from 'zod';
import { authService } from '../services/auth.service';
import { isAppError } from '../utils/errors';
import { createLogger } from '../utils/logger';
import {
  sendCreated,
  sendError,
  sendSuccess,
  sendValidationError,
} from '../utils/response';
import { authenticate } from '../middleware/authenticate';

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

const loginSchema = z.object({
  email: z.string().email('Invalid email format').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'),
});

const authRoutes: FastifyPluginCallback = (
  app: FastifyInstance,
  _options,
  done
) => {
  // ── POST /auth/register ─────────────────────────────────
  app.post('/register', async (request, reply) => {
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

  // ── POST /login ─────────────────────────────────────────
  app.post('/login', async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const result = await authService.login({
        email: parsed.data.email,
        password: parsed.data.password,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, result);
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      log.error({ err, reqId: request.id }, 'Unexpected error in login');
      throw err;
    }
  });

  // ── POST /logout ─────────────────────────────────────────
  app.post(
    '/logout',
    { preHandler: [authenticate] },
    async (request, reply) => {
      const parsed = z
        .object({
          refreshToken: z.string().min(1, 'Refresh token is required'),
        })
        .safeParse(request.body);

      if (!parsed.success) {
        return sendValidationError(
          reply,
          parsed.error.issues.map((issue) => ({
            field: issue.path.join('.'),
            message: issue.message,
          }))
        );
      }

      try {
        await authService.logout({
          refreshToken: parsed.data.refreshToken,
          userId: request.user!.id,
          ipAddress: request.ip,
        });

        return sendSuccess(reply, { message: 'Logged out successfully' });
      } catch (err) {
        if (isAppError(err)) {
          return sendError(reply, err.statusCode, err.code, err.message);
        }
        throw err;
      }
    }
  );

  // ── POST /refresh ─────────────────────────────────────────
  app.post('/refresh', async (request, reply) => {
    const parsed = z
      .object({
        refreshToken: z.string().min(1, 'Refresh token is required'),
      })
      .safeParse(request.body);

    if (!parsed.success) {
      return sendValidationError(
        reply,
        parsed.error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }))
      );
    }

    try {
      const result = await authService.refreshTokens({
        refreshToken: parsed.data.refreshToken,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
      });

      return sendSuccess(reply, result);
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      throw err;
    }
  });

  // ── GET /me ───────────────────────────────────────────────
  app.get('/me', { preHandler: [authenticate] }, async (request, reply) => {
    try {
      const user = await authService.getMe(request.user!.id);
      return sendSuccess(reply, { user });
    } catch (err) {
      if (isAppError(err)) {
        return sendError(reply, err.statusCode, err.code, err.message);
      }
      throw err;
    }
  });

  // Tell Fastify this plugin has finished registering
  done();
};

export { authRoutes };
