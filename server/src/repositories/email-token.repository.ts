import { eq, and, isNull } from 'drizzle-orm';
import crypto from 'crypto';
import { db } from '../db/connection';
import { emailTokens } from '../db/schema';
import { createLogger } from '../utils/logger';

const log = createLogger('EmailTokenRepository');

type EmailTokenType = 'email_verification' | 'password_reset';

export class EmailTokenRepository {
  // ── Generate and store token ───────────────────────────
  async create(
    userId: string,
    type: EmailTokenType,
    expiryHours: number
  ): Promise<string> {
    // Generate raw token — this is what gets sent in the email
    const rawToken = crypto.randomBytes(32).toString('hex');

    // Store SHA-256 hash — same pattern as refresh tokens
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + expiryHours);

    // Invalidate any existing unused tokens of this type for user
    await db
      .update(emailTokens)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(emailTokens.userId, userId),
          eq(emailTokens.type, type),
          isNull(emailTokens.usedAt)
        )
      );

    await db.insert(emailTokens).values({
      userId,
      tokenHash,
      type,
      expiresAt,
    });

    log.debug({ userId, type }, 'Email token created');

    // Return raw token — only time it exists in plain text
    return rawToken;
  }

  // ── Find valid token ───────────────────────────────────
  async findValid(rawToken: string, type: EmailTokenType) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(rawToken)
      .digest('hex');

    const [token] = await db
      .select()
      .from(emailTokens)
      .where(
        and(
          eq(emailTokens.tokenHash, tokenHash),
          eq(emailTokens.type, type),
          isNull(emailTokens.usedAt)
        )
      );

    if (!token) return null;

    // Check expiry
    if (token.expiresAt < new Date()) {
      log.debug({ type }, 'Email token expired');
      return null;
    }

    return token;
  }

  // ── Mark token as used ─────────────────────────────────
  async markUsed(id: string): Promise<void> {
    await db
      .update(emailTokens)
      .set({ usedAt: new Date() })
      .where(eq(emailTokens.id, id));
  }
}

export const emailTokenRepository = new EmailTokenRepository();
