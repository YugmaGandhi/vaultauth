import { eq, and, isNull, gt, desc } from 'drizzle-orm';
import { db } from '../db/connection';
import { refreshTokens } from '../db/schema';
import { createLogger } from '../utils/logger';

const log = createLogger('TokenRepository');

type CreateRefreshTokenParams = {
  userId: string;
  tokenHash: string;
  deviceInfo?: string;
  ipAddress?: string;
  expiresAt: Date;
};

export class TokenRepository {
  // ── Create ────────────────────────────────────────────
  async create(params: CreateRefreshTokenParams) {
    log.debug({ userId: params.userId }, 'Creating refresh token');

    const [token] = await db
      .insert(refreshTokens)
      .values({
        userId: params.userId,
        tokenHash: params.tokenHash,
        deviceInfo: params.deviceInfo,
        ipAddress: params.ipAddress,
        expiresAt: params.expiresAt,
      })
      .returning();

    return token;
  }

  // ── Find by Hash ──────────────────────────────────────
  async findByHash(tokenHash: string) {
    log.debug('Finding refresh token by hash');

    const [token] = await db
      .select()
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.tokenHash, tokenHash),
          isNull(refreshTokens.revokedAt)
        )
      );

    return token ?? null;
  }

  // ── Find Active Sessions for User ─────────────────────
  // Returns all non-revoked, non-expired tokens for a user
  // Excludes tokenHash — never expose the raw hash to API consumers
  async findActiveSessions(userId: string) {
    log.debug({ userId }, 'Finding active sessions');

    return db
      .select({
        id: refreshTokens.id,
        deviceInfo: refreshTokens.deviceInfo,
        ipAddress: refreshTokens.ipAddress,
        createdAt: refreshTokens.createdAt,
        expiresAt: refreshTokens.expiresAt,
      })
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt),
          gt(refreshTokens.expiresAt, new Date())
        )
      )
      .orderBy(desc(refreshTokens.createdAt));
  }

  // ── Find Active Session by ID (with ownership check) ──
  // Returns null if session doesn't exist, is expired, revoked,
  // or belongs to a different user
  async findActiveById(
    id: string,
    userId: string
  ): Promise<{ id: string } | null> {
    log.debug({ id, userId }, 'Finding active session by id');

    const [token] = await db
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.id, id),
          eq(refreshTokens.userId, userId),
          isNull(refreshTokens.revokedAt),
          gt(refreshTokens.expiresAt, new Date())
        )
      );

    return token ?? null;
  }

  // ── Revoke One ────────────────────────────────────────
  async revoke(id: string): Promise<void> {
    log.debug({ tokenId: id }, 'Revoking refresh token');

    await db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(eq(refreshTokens.id, id));
  }

  // ── Revoke All for User ───────────────────────────────
  // Called when password changes or stolen token detected
  async revokeAllForUser(userId: string): Promise<void> {
    log.warn({ userId }, 'Revoking all refresh tokens for user');

    await db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(
        and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt))
      );
  }
}

export const tokenRepository = new TokenRepository();
