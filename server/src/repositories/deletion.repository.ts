import { and, eq, lte } from 'drizzle-orm';
import { db } from '../db/connection';
import { deletionRequests } from '../db/schema';
import { DeletionRequest } from '../utils/types';

const GRACE_PERIOD_DAYS = 30;

export class DeletionRepository {
  // ── Create ────────────────────────────────────────────
  async create(userId: string): Promise<DeletionRequest> {
    const scheduledPurgeAt = new Date();
    scheduledPurgeAt.setDate(scheduledPurgeAt.getDate() + GRACE_PERIOD_DAYS);

    const [request] = await db
      .insert(deletionRequests)
      .values({ userId, scheduledPurgeAt })
      .returning();

    return request;
  }

  // ── Find pending by user ──────────────────────────────
  async findPendingByUserId(userId: string): Promise<DeletionRequest | null> {
    const [request] = await db
      .select()
      .from(deletionRequests)
      .where(
        and(
          eq(deletionRequests.userId, userId),
          eq(deletionRequests.status, 'pending')
        )
      );

    return request ?? null;
  }

  // ── Cancel ────────────────────────────────────────────
  async cancel(id: string): Promise<void> {
    await db
      .update(deletionRequests)
      .set({ status: 'cancelled', cancelledAt: new Date() })
      .where(eq(deletionRequests.id, id));
  }

  // ── Find due (for purge job) ──────────────────────────
  // Returns all pending requests where grace period has expired
  async findDue(): Promise<DeletionRequest[]> {
    return db
      .select()
      .from(deletionRequests)
      .where(
        and(
          eq(deletionRequests.status, 'pending'),
          lte(deletionRequests.scheduledPurgeAt, new Date())
        )
      );
  }

  // ── Mark completed ────────────────────────────────────
  async markCompleted(id: string): Promise<void> {
    await db
      .update(deletionRequests)
      .set({ status: 'completed' })
      .where(eq(deletionRequests.id, id));
  }
}

export const deletionRepository = new DeletionRepository();
