import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('Session Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
    );
    await seedSystemData();
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Helpers ────────────────────────────────────────────
  async function registerAndLogin(email: string, password: string) {
    await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password },
    });
    // Bypass email verification for tests
    await db
      .update(users)
      .set({ isVerified: true })
      .where(eq(users.email, email));

    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
    return loginRes.json<{
      data: { accessToken: string; refreshToken: string };
    }>().data;
  }

  // ── GET /auth/sessions ─────────────────────────────────
  describe('GET /auth/sessions', () => {
    it('should return active sessions for the authenticated user', async () => {
      const { accessToken } = await registerAndLogin(
        'sessions@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'GET',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { sessions: unknown[] } }>();
      expect(body.data.sessions).toHaveLength(1);
      expect(body.data.sessions[0]).toMatchObject({
        id: expect.any(String),
        createdAt: expect.any(String),
        expiresAt: expect.any(String),
      });
      // tokenHash must never appear in the response
      expect(JSON.stringify(body)).not.toContain('tokenHash');
    });

    it('should return 401 without auth token', async () => {
      const res = await app.inject({ method: 'GET', url: '/auth/sessions' });
      expect(res.statusCode).toBe(401);
    });

    it('should return multiple sessions when logged in from multiple devices', async () => {
      const email = 'multi@example.com';
      const password = 'password123';

      const { accessToken } = await registerAndLogin(email, password);

      // Second login = second session
      await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { sessions: unknown[] } }>();
      expect(body.data.sessions).toHaveLength(2);
    });
  });

  // ── DELETE /auth/sessions/:id ──────────────────────────
  describe('DELETE /auth/sessions/:id', () => {
    it('should revoke a specific session', async () => {
      const { accessToken } = await registerAndLogin(
        'revoke@example.com',
        'password123'
      );

      // Get the session id
      const listRes = await app.inject({
        method: 'GET',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const { sessions } = listRes.json<{
        data: { sessions: { id: string }[] };
      }>().data;
      const sessionId = sessions[0].id;

      // Revoke it
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/auth/sessions/${sessionId}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(revokeRes.statusCode).toBe(200);

      // Session should no longer appear in the list
      const afterRes = await app.inject({
        method: 'GET',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      const afterSessions = afterRes.json<{
        data: { sessions: unknown[] };
      }>().data.sessions;
      expect(afterSessions).toHaveLength(0);
    });

    it('should return 404 when revoking a session that does not belong to the user', async () => {
      const { accessToken } = await registerAndLogin(
        'user1@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/sessions/00000000-0000-0000-0000-000000000000',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('should return 400 for a non-UUID session id', async () => {
      const { accessToken } = await registerAndLogin(
        'bad-id@example.com',
        'password123'
      );

      const res = await app.inject({
        method: 'DELETE',
        url: '/auth/sessions/not-a-uuid',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // ── DELETE /auth/sessions ──────────────────────────────
  describe('DELETE /auth/sessions', () => {
    it('should revoke all sessions for the user', async () => {
      const email = 'revokeall@example.com';
      const password = 'password123';
      const { accessToken } = await registerAndLogin(email, password);

      // Create a second session
      await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password },
      });

      // Revoke all
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(revokeRes.statusCode).toBe(200);

      // No active sessions remain
      const listRes = await app.inject({
        method: 'GET',
        url: '/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      // Access token is still valid (it's a JWT, short-lived), but sessions are gone
      expect(listRes.statusCode).toBe(200);
      expect(
        listRes.json<{ data: { sessions: unknown[] } }>().data.sessions
      ).toHaveLength(0);
    });

    it('should return 401 without auth token', async () => {
      const res = await app.inject({ method: 'DELETE', url: '/auth/sessions' });
      expect(res.statusCode).toBe(401);
    });
  });
});
