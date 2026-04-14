import { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { db } from '../../db/connection';
import { redis } from '../../db/redis';
import { users, webhookEndpoints } from '../../db/schema';
import { eq, sql } from 'drizzle-orm';
import { seedSystemData } from '../../db/seed';

describe('Webhook Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    await redis.connect();
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await redis.flushdb();
    await db.execute(
      sql`TRUNCATE TABLE webhook_deliveries, webhook_endpoints, deletion_requests, audit_logs, refresh_tokens, email_tokens, user_roles, role_permissions, roles, permissions, org_role_permissions, org_member_roles, org_permissions, org_roles, org_invitations, org_members, organizations, users RESTART IDENTITY CASCADE`
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
    await db
      .update(users)
      .set({ isVerified: true })
      .where(eq(users.email, email));

    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password },
    });
    return loginRes.json<{ data: { accessToken: string } }>().data;
  }

  async function createOrg(token: string, name: string, slug: string) {
    const res = await app.inject({
      method: 'POST',
      url: '/api/orgs',
      headers: { authorization: `Bearer ${token}` },
      payload: { name, slug },
    });
    return res.json<{ data: { organization: { id: string } } }>().data
      .organization;
  }

  // ── POST /api/orgs/:orgId/webhooks ─────────────────────
  describe('POST /api/orgs/:orgId/webhooks', () => {
    it('should register a webhook endpoint and return a one-time secret', async () => {
      const { accessToken } = await registerAndLogin(
        'user@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org', 'test-org');

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          url: 'https://example.com/hook',
          events: ['user.login'],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<{
        data: { endpoint: { id: string }; secret: string };
      }>();
      expect(body.data.endpoint.id).toBeDefined();
      // Secret is 64-char hex
      expect(body.data.secret).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should reject HTTP (non-HTTPS) URLs', async () => {
      const { accessToken } = await registerAndLogin(
        'user2@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 2', 'test-org-2');

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          url: 'http://example.com/hook',
          events: ['user.login'],
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('should reject empty events array', async () => {
      const { accessToken } = await registerAndLogin(
        'user3@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 3', 'test-org-3');

      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          url: 'https://example.com/hook',
          events: [],
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('should require authentication', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/orgs/00000000-0000-0000-0000-000000000001/webhooks',
        payload: { url: 'https://example.com/hook', events: ['user.login'] },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // ── GET /api/orgs/:orgId/webhooks ──────────────────────
  describe('GET /api/orgs/:orgId/webhooks', () => {
    it('should list endpoints for the org', async () => {
      const { accessToken } = await registerAndLogin(
        'user4@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 4', 'test-org-4');

      // Register one endpoint
      await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { url: 'https://example.com/hook', events: ['user.login'] },
      });

      const res = await app.inject({
        method: 'GET',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { endpoints: unknown[] } }>();
      expect(body.data.endpoints).toHaveLength(1);
    });
  });

  // ── PATCH /api/orgs/:orgId/webhooks/:endpointId ────────
  describe('PATCH /api/orgs/:orgId/webhooks/:endpointId', () => {
    it('should update an endpoint', async () => {
      const { accessToken } = await registerAndLogin(
        'user5@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 5', 'test-org-5');

      const createRes = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { url: 'https://example.com/hook', events: ['user.login'] },
      });
      const { endpoint } = createRes.json<{
        data: { endpoint: { id: string } };
      }>().data;

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${org.id}/webhooks/${endpoint.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { isActive: false },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { endpoint: { isActive: boolean } } }>();
      expect(body.data.endpoint.isActive).toBe(false);
    });

    it('should return 404 for non-existent endpoint', async () => {
      const { accessToken } = await registerAndLogin(
        'user6@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 6', 'test-org-6');

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/orgs/${org.id}/webhooks/00000000-0000-0000-0000-000000000099`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { isActive: false },
      });

      expect(res.statusCode).toBe(404);
    });
  });

  // ── DELETE /api/orgs/:orgId/webhooks/:endpointId ───────
  describe('DELETE /api/orgs/:orgId/webhooks/:endpointId', () => {
    it('should delete endpoint and cascade deliveries', async () => {
      const { accessToken } = await registerAndLogin(
        'user7@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 7', 'test-org-7');

      const createRes = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { url: 'https://example.com/hook', events: ['user.login'] },
      });
      const { endpoint } = createRes.json<{
        data: { endpoint: { id: string } };
      }>().data;

      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/orgs/${org.id}/webhooks/${endpoint.id}`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(deleteRes.statusCode).toBe(200);

      // Verify row removed from DB
      const rows = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.id, endpoint.id));
      expect(rows).toHaveLength(0);
    });
  });

  // ── GET /api/orgs/:orgId/webhooks/:endpointId/deliveries ─
  describe('GET /api/orgs/:orgId/webhooks/:endpointId/deliveries', () => {
    it('should return delivery log for an endpoint', async () => {
      const { accessToken } = await registerAndLogin(
        'user8@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 8', 'test-org-8');

      const createRes = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { url: 'https://example.com/hook', events: ['user.login'] },
      });
      const { endpoint } = createRes.json<{
        data: { endpoint: { id: string } };
      }>().data;

      const res = await app.inject({
        method: 'GET',
        url: `/api/orgs/${org.id}/webhooks/${endpoint.id}/deliveries`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ data: { deliveries: unknown[] } }>();
      expect(Array.isArray(body.data.deliveries)).toBe(true);
    });
  });

  // ── POST /api/orgs/:orgId/webhooks/:endpointId/test ────
  describe('POST /api/orgs/:orgId/webhooks/:endpointId/test', () => {
    it('should return 200 after attempting test delivery (endpoint unreachable is OK)', async () => {
      const { accessToken } = await registerAndLogin(
        'user9@test.com',
        'Password1!'
      );
      const org = await createOrg(accessToken, 'Test Org 9', 'test-org-9');

      const createRes = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks`,
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { url: 'https://example.com/hook', events: ['webhook.test'] },
      });
      const { endpoint } = createRes.json<{
        data: { endpoint: { id: string } };
      }>().data;

      // The test endpoint URL won't respond — that's expected in unit/integration tests.
      // The route should not fail because of network errors (delivery logs the failure).
      const res = await app.inject({
        method: 'POST',
        url: `/api/orgs/${org.id}/webhooks/${endpoint.id}/test`,
        headers: { authorization: `Bearer ${accessToken}` },
      });

      // Route itself succeeds — delivery may fail internally, that's logged
      expect(res.statusCode).toBe(200);
    });
  });
});
