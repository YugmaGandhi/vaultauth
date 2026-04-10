import { auditRepository } from '../repositories/audit.repository';
import { deletionRepository } from '../repositories/deletion.repository';
import { userRepository } from '../repositories/user.repository';
import { ConflictError, ForbiddenError, NotFoundError } from '../utils/errors';
import { createLogger } from '../utils/logger';

const log = createLogger('DeletionService');

export class DeletionService {
  // ── Request self-service deletion ─────────────────────
  // Schedules the account for permanent deletion in 30 days.
  // User can cancel within the grace period.
  async requestDeletion(params: {
    userId: string;
    ipAddress?: string;
  }): Promise<{ scheduledPurgeAt: Date }> {
    const { userId, ipAddress } = params;

    const existing = await deletionRepository.findPendingByUserId(userId);
    if (existing) {
      throw new ConflictError(
        'DELETION_ALREADY_REQUESTED',
        'A deletion request is already pending for this account'
      );
    }

    const request = await deletionRepository.create(userId);

    await auditRepository.create({
      userId,
      eventType: 'account_deletion_requested',
      ipAddress,
      metadata: { scheduledPurgeAt: request.scheduledPurgeAt.toISOString() },
    });

    log.info({ userId }, 'Account deletion requested');

    return { scheduledPurgeAt: request.scheduledPurgeAt };
  }

  // ── Cancel pending deletion request ───────────────────
  async cancelDeletion(params: {
    userId: string;
    ipAddress?: string;
  }): Promise<void> {
    const { userId, ipAddress } = params;

    const request = await deletionRepository.findPendingByUserId(userId);
    if (!request) {
      throw new NotFoundError(
        'DELETION_REQUEST_NOT_FOUND',
        'No pending deletion request found for this account'
      );
    }

    await deletionRepository.cancel(request.id);

    await auditRepository.create({
      userId,
      eventType: 'account_deletion_cancelled',
      ipAddress,
      metadata: {},
    });

    log.info({ userId }, 'Account deletion cancelled');
  }

  // ── Admin force-delete (immediate, no grace period) ───
  async forceDelete(params: {
    userId: string;
    adminId: string;
    ipAddress?: string;
  }): Promise<void> {
    const { userId, adminId, ipAddress } = params;

    if (userId === adminId) {
      throw new ForbiddenError(
        'CANNOT_DELETE_SELF',
        'Admins cannot delete their own account through this endpoint'
      );
    }

    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('USER_NOT_FOUND', 'User not found');
    }

    // Audit log before deletion — user FK will become null after delete
    await auditRepository.create({
      userId: adminId,
      eventType: 'account_deleted',
      ipAddress,
      metadata: { targetUserId: userId, email: user.email, forced: true },
    });

    await userRepository.deleteUser(userId);

    log.warn({ userId, adminId }, 'User force-deleted by admin');
  }

  // ── Purge expired deletion requests (called by job) ───
  // Returns number of accounts successfully purged.
  async purgeExpired(): Promise<number> {
    const due = await deletionRepository.findDue();

    let purged = 0;
    for (const request of due) {
      if (!request.userId) continue;

      try {
        const user = await userRepository.findById(request.userId);

        // Audit log before deletion
        await auditRepository.create({
          userId: request.userId,
          eventType: 'account_deleted',
          metadata: {
            email: user?.email ?? null,
            forced: false,
            deletionRequestId: request.id,
          },
        });

        // Delete user first — if this fails, request stays pending and
        // the next purge run will retry. Marking completed first would
        // permanently skip a failed deletion.
        await userRepository.deleteUser(request.userId);

        // Mark completed after successful deletion — userId FK becomes
        // null on the record (set null) once the user row is gone
        await deletionRepository.markCompleted(request.id);

        purged++;
        log.info({ userId: request.userId }, 'User account purged');
      } catch (err) {
        log.error(
          { err, requestId: request.id, userId: request.userId },
          'Failed to purge user — skipping'
        );
      }
    }

    return purged;
  }
}

export const deletionService = new DeletionService();
