import { tokenRepository } from '../repositories/token.repository';
import { auditRepository } from '../repositories/audit.repository';
import { NotFoundError } from '../utils/errors';
import { createLogger } from '../utils/logger';

const log = createLogger('SessionService');

type RevokeSessionParams = {
  sessionId: string;
  userId: string;
  ipAddress?: string;
};

type RevokeAllSessionsParams = {
  userId: string;
  ipAddress?: string;
};

export class SessionService {
  // ── List active sessions ──────────────────────────────
  async listSessions(userId: string) {
    log.debug({ userId }, 'Listing active sessions');
    return tokenRepository.findActiveSessions(userId);
  }

  // ── Revoke a specific session ─────────────────────────
  async revokeSession({ sessionId, userId, ipAddress }: RevokeSessionParams) {
    log.debug({ sessionId, userId }, 'Revoking session');

    const session = await tokenRepository.findActiveById(sessionId, userId);
    if (!session) {
      throw new NotFoundError('SESSION_NOT_FOUND', 'Session not found');
    }

    await tokenRepository.revoke(sessionId);

    void auditRepository.create({
      userId,
      eventType: 'session_revoked',
      ipAddress,
      metadata: { sessionId },
    });
  }

  // ── Revoke all sessions (sign out everywhere) ─────────
  async revokeAllSessions({ userId, ipAddress }: RevokeAllSessionsParams) {
    log.debug({ userId }, 'Revoking all sessions');

    await tokenRepository.revokeAllForUser(userId);

    void auditRepository.create({
      userId,
      eventType: 'all_sessions_revoked',
      ipAddress,
    });
  }
}

export const sessionService = new SessionService();
