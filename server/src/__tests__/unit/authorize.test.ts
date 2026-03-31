import { FastifyRequest, FastifyReply } from 'fastify';
import { authorize, authorizeAny } from '../../middleware/authorize';

// ── Mock logger ──────────────────────────────────────────
jest.mock('../../utils/logger', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// ── Test helpers ─────────────────────────────────────────
function mockRequest(user?: {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
}): FastifyRequest {
  return { user } as unknown as FastifyRequest;
}

function mockReply() {
  const state = { statusCode: 0 };
  const reply = {
    get statusCode() {
      return state.statusCode;
    },
    status(code: number) {
      state.statusCode = code;
      return reply;
    },
    send() {
      return reply;
    },
  } as unknown as FastifyReply & { statusCode: number };
  return reply;
}

describe('authorize()', () => {
  it('should allow request when user has the required permission', async () => {
    const middleware = authorize('read:roles');
    const request = mockRequest({
      id: 'user-1',
      email: 'admin@example.com',
      roles: ['admin'],
      permissions: ['read:roles', 'write:roles'],
    });
    const reply = mockReply();

    const result = await middleware(request, reply);

    // Should return undefined (no response sent — request continues)
    expect(result).toBeUndefined();
  });

  it('should reject when user lacks the required permission', async () => {
    const middleware = authorize('write:roles');
    const request = mockRequest({
      id: 'user-1',
      email: 'user@example.com',
      roles: ['user'],
      permissions: ['read:profile'],
    });
    const reply = mockReply();

    await middleware(request, reply);

    expect(reply.statusCode).toBe(403);
  });

  it('should reject when user is not attached to request', async () => {
    const middleware = authorize('read:roles');
    const request = mockRequest(undefined);
    const reply = mockReply();

    await middleware(request, reply);

    expect(reply.statusCode).toBe(403);
  });
});

describe('authorizeAny()', () => {
  it('should allow when user has at least one of the required permissions', async () => {
    const middleware = authorizeAny('write:roles', 'read:roles');
    const request = mockRequest({
      id: 'user-1',
      email: 'mod@example.com',
      roles: ['moderator'],
      permissions: ['read:roles'],
    });
    const reply = mockReply();

    const result = await middleware(request, reply);

    expect(result).toBeUndefined();
  });

  it('should reject when user has none of the required permissions', async () => {
    const middleware = authorizeAny('write:roles', 'write:users');
    const request = mockRequest({
      id: 'user-1',
      email: 'user@example.com',
      roles: ['user'],
      permissions: ['read:profile'],
    });
    const reply = mockReply();

    await middleware(request, reply);

    expect(reply.statusCode).toBe(403);
  });

  it('should reject when user is not attached to request', async () => {
    const middleware = authorizeAny('read:roles');
    const request = mockRequest(undefined);
    const reply = mockReply();

    await middleware(request, reply);

    expect(reply.statusCode).toBe(403);
  });
});
