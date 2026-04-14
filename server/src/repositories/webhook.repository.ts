import { and, asc, desc, eq, lte } from 'drizzle-orm';
import { db } from '../db/connection';
import { webhookEndpoints, webhookDeliveries } from '../db/schema';
import { WebhookDelivery, WebhookEndpoint } from '../utils/types';

export class WebhookRepository {
  // ── Endpoints ─────────────────────────────────────────

  async createEndpoint(params: {
    orgId: string;
    url: string;
    events: string[];
    secretHash: string;
  }): Promise<WebhookEndpoint> {
    const [endpoint] = await db
      .insert(webhookEndpoints)
      .values(params)
      .returning();

    return endpoint;
  }

  // Returns all endpoints for an org — used by fanout to build the target list.
  // Only active endpoints receive deliveries.
  async findByOrg(orgId: string): Promise<WebhookEndpoint[]> {
    return db
      .select()
      .from(webhookEndpoints)
      .where(
        and(
          eq(webhookEndpoints.orgId, orgId),
          eq(webhookEndpoints.isActive, true)
        )
      );
  }

  async findById(id: string): Promise<WebhookEndpoint | null> {
    const [endpoint] = await db
      .select()
      .from(webhookEndpoints)
      .where(eq(webhookEndpoints.id, id));

    return endpoint ?? null;
  }

  async updateEndpoint(
    id: string,
    updates: Partial<Pick<WebhookEndpoint, 'url' | 'events' | 'isActive'>>
  ): Promise<WebhookEndpoint | null> {
    const [updated] = await db
      .update(webhookEndpoints)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(webhookEndpoints.id, id))
      .returning();

    return updated ?? null;
  }

  async deleteEndpoint(id: string): Promise<void> {
    await db.delete(webhookEndpoints).where(eq(webhookEndpoints.id, id));
  }

  // ── Deliveries ────────────────────────────────────────

  // nextRetryAt = now() so the delivery job picks it up on the very next poll.
  async createDelivery(params: {
    webhookEndpointId: string;
    eventType: string;
    payload: Record<string, unknown>;
  }): Promise<WebhookDelivery> {
    const [delivery] = await db
      .insert(webhookDeliveries)
      .values({ ...params, nextRetryAt: new Date() })
      .returning();

    return delivery;
  }

  // Polling query for the retry job — all pending deliveries whose nextRetryAt
  // has passed. Ordered by nextRetryAt asc so the oldest-due delivery runs
  // first (FIFO under contention). Limits to 100 per run to cap memory and
  // execution time.
  async findDueDeliveries(): Promise<WebhookDelivery[]> {
    return db
      .select()
      .from(webhookDeliveries)
      .where(
        and(
          eq(webhookDeliveries.status, 'pending'),
          lte(webhookDeliveries.nextRetryAt, new Date())
        )
      )
      .orderBy(asc(webhookDeliveries.nextRetryAt))
      .limit(100);
  }

  async updateDelivery(
    id: string,
    updates: Partial<
      Pick<
        WebhookDelivery,
        'status' | 'attempts' | 'lastAttemptAt' | 'nextRetryAt' | 'responseCode'
      >
    >
  ): Promise<void> {
    await db
      .update(webhookDeliveries)
      .set(updates)
      .where(eq(webhookDeliveries.id, id));
  }

  async findDeliveryById(id: string): Promise<WebhookDelivery | null> {
    const [delivery] = await db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, id));

    return delivery ?? null;
  }

  async findDeliveriesByEndpoint(
    endpointId: string
  ): Promise<WebhookDelivery[]> {
    return db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.webhookEndpointId, endpointId))
      .orderBy(desc(webhookDeliveries.createdAt))
      .limit(50);
  }
}

export const webhookRepository = new WebhookRepository();
