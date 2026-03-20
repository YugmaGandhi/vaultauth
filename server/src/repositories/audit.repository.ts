import { db } from '../db/connection';
import { auditLogs, auditEventTypeEnum } from '../db/schema';
import { createLogger } from '../utils/logger';

const log = createLogger('AuditRepository');

type AuditEventType = (typeof auditEventTypeEnum.enumValues)[number];

type CreateAuditLogParams = {
  userId?: string;
  eventType: AuditEventType;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
};

export class AuditRepository {
  async create(params: CreateAuditLogParams): Promise<void> {
    log.debug({ eventType: params.eventType }, 'Writing audit log');

    try {
      await db.insert(auditLogs).values({
        userId: params.userId,
        eventType: params.eventType,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
        metadata: params.metadata ?? {},
      });
    } catch (err) {
      // Audit log failure should never break the main flow
      // Log the error but don't throw
      log.error({ err }, 'Failed to write audit log');
    }
  }
}

export const auditRepository = new AuditRepository();
