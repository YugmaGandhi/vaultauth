import { SessionService } from '../../services/session.service';
import { tokenRepository } from '../../repositories/token.repository';
import { auditRepository } from '../../repositories/audit.repository';
import { NotFoundError } from '../../utils/errors';

jest.mock('../../repositories/token.repository');
jest.mock('../../repositories/audit.repository');

const mockTokenRepo = tokenRepository as jest.Mocked<typeof tokenRepository>;
const mockAuditRepo = auditRepository as jest.Mocked<typeof auditRepository>;

const userId = '550e8400-e29b-41d4-a716-446655440000';
const sessionId = '660e8400-e29b-41d4-a716-446655440001';

const mockSession = {
  id: sessionId,
  deviceInfo: 'Mozilla/5.0',
  ipAddress: '127.0.0.1',
  createdAt: new Date('2026-04-01T00:00:00Z'),
  expiresAt: new Date('2026-05-01T00:00:00Z'),
};

describe('SessionService', () => {
  let service: SessionService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new SessionService();
    mockAuditRepo.create.mockResolvedValue(undefined);
  });

  // ── listSessions ───────────────────────────────────────
  describe('listSessions()', () => {
    it('should return active sessions for the user', async () => {
      mockTokenRepo.findActiveSessions.mockResolvedValue([mockSession]);

      const result = await service.listSessions(userId);

      expect(mockTokenRepo.findActiveSessions).toHaveBeenCalledWith(userId);
      expect(result).toEqual([mockSession]);
    });

    it('should return empty array when no active sessions', async () => {
      mockTokenRepo.findActiveSessions.mockResolvedValue([]);

      const result = await service.listSessions(userId);

      expect(result).toEqual([]);
    });
  });

  // ── revokeSession ──────────────────────────────────────
  describe('revokeSession()', () => {
    it('should revoke a session that belongs to the user', async () => {
      mockTokenRepo.findActiveById.mockResolvedValue({ id: sessionId });
      mockTokenRepo.revoke.mockResolvedValue(undefined);

      await service.revokeSession({
        sessionId,
        userId,
        ipAddress: '127.0.0.1',
      });

      expect(mockTokenRepo.findActiveById).toHaveBeenCalledWith(
        sessionId,
        userId
      );
      expect(mockTokenRepo.revoke).toHaveBeenCalledWith(sessionId);
    });

    it('should throw NotFoundError if session does not belong to user', async () => {
      mockTokenRepo.findActiveById.mockResolvedValue(null);

      await expect(
        service.revokeSession({ sessionId, userId })
      ).rejects.toThrow(NotFoundError);

      expect(mockTokenRepo.revoke).not.toHaveBeenCalled();
    });

    it('should throw NotFoundError with correct code if session is already revoked', async () => {
      mockTokenRepo.findActiveById.mockResolvedValue(null);

      await expect(
        service.revokeSession({ sessionId, userId })
      ).rejects.toThrow('Session not found');
    });
  });

  // ── revokeAllSessions ──────────────────────────────────
  describe('revokeAllSessions()', () => {
    it('should revoke all sessions for the user', async () => {
      mockTokenRepo.revokeAllForUser.mockResolvedValue(undefined);

      await service.revokeAllSessions({ userId, ipAddress: '127.0.0.1' });

      expect(mockTokenRepo.revokeAllForUser).toHaveBeenCalledWith(userId);
    });
  });
});
