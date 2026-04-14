import { WebhookService } from '../../services/webhook.service';
import { webhookRepository } from '../../repositories/webhook.repository';
import { orgRepository } from '../../repositories/org.repository';
import {
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from '../../utils/errors';
import type { WebhookDelivery, WebhookEndpoint } from '../../utils/types';

jest.mock('../../repositories/webhook.repository');
jest.mock('../../repositories/org.repository');
// AES-256-GCM requires the env key — mock env so it stays stable in tests
jest.mock('../../config/env', () => ({
  env: {
    WEBHOOK_SECRET_KEY:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    LOG_LEVEL: 'error',
    NODE_ENV: 'test',
  },
}));

const mockRepo = webhookRepository as jest.Mocked<typeof webhookRepository>;
const mockOrgRepo = orgRepository as jest.Mocked<typeof orgRepository>;

const orgId = '00000000-0000-0000-0000-000000000001';
const actorUserId = '00000000-0000-0000-0000-000000000002';
const endpointId = '00000000-0000-0000-0000-000000000010';
const deliveryId = '00000000-0000-0000-0000-000000000020';

const mockEndpoint: WebhookEndpoint = {
  id: endpointId,
  orgId,
  url: 'https://example.com/webhook',
  events: ['user.login', 'org.member.joined'],
  secretHash: 'iv:tag:ciphertext', // placeholder — not decrypted in most tests
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockDelivery: WebhookDelivery = {
  id: deliveryId,
  webhookEndpointId: endpointId,
  eventType: 'user.login',
  payload: { userId: 'u1' },
  status: 'pending',
  attempts: 0,
  nextRetryAt: new Date(),
  lastAttemptAt: null,
  responseCode: null,
  createdAt: new Date(),
};

const adminMembership = { id: 'mem-1', role: 'admin' };
const memberMembership = { id: 'mem-1', role: 'member' };

describe('WebhookService', () => {
  let service: WebhookService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new WebhookService();
  });

  // ── registerEndpoint ──────────────────────────────────────
  describe('registerEndpoint()', () => {
    it('should create an endpoint and return a one-time secret (no secretHash in response)', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.createEndpoint.mockResolvedValue(mockEndpoint);

      const result = await service.registerEndpoint({
        actorUserId,
        orgId,
        url: 'https://example.com/webhook',
        events: ['user.login'],
      });

      expect(mockRepo.createEndpoint).toHaveBeenCalledWith(
        expect.objectContaining({ orgId, url: 'https://example.com/webhook' })
      );
      // Secret is a 64-char hex string (32 bytes)
      expect(result.secret).toMatch(/^[0-9a-f]{64}$/);
      // secretHash must NOT appear in the returned endpoint
      expect(result.endpoint).not.toHaveProperty('secretHash');
    });

    it('should throw ForbiddenError if actor is not an org admin/owner', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(memberMembership);

      await expect(
        service.registerEndpoint({
          actorUserId,
          orgId,
          url: 'https://example.com/webhook',
          events: ['user.login'],
        })
      ).rejects.toThrow(ForbiddenError);
      expect(mockRepo.createEndpoint).not.toHaveBeenCalled();
    });

    it('should throw ForbiddenError if actor is not a member of the org', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(null);

      await expect(
        service.registerEndpoint({
          actorUserId,
          orgId,
          url: 'https://example.com/webhook',
          events: ['user.login'],
        })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should reject non-HTTPS URLs', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);

      await expect(
        service.registerEndpoint({
          actorUserId,
          orgId,
          url: 'http://example.com/webhook',
          events: ['user.login'],
        })
      ).rejects.toThrow(ValidationError);
      expect(mockRepo.createEndpoint).not.toHaveBeenCalled();
    });

    it('should reject empty events array', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);

      await expect(
        service.registerEndpoint({
          actorUserId,
          orgId,
          url: 'https://example.com/webhook',
          events: [],
        })
      ).rejects.toThrow(ValidationError);
    });
  });

  // ── updateEndpoint ────────────────────────────────────────
  describe('updateEndpoint()', () => {
    it('should throw NotFoundError if endpoint does not exist', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.findById.mockResolvedValue(null);

      await expect(
        service.updateEndpoint({
          actorUserId,
          endpointId,
          orgId,
          updates: { isActive: false },
        })
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw ForbiddenError if endpoint belongs to another org', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.findById.mockResolvedValue({
        ...mockEndpoint,
        orgId: '00000000-0000-0000-0000-000000000099',
      });

      await expect(
        service.updateEndpoint({
          actorUserId,
          endpointId,
          orgId,
          updates: { isActive: false },
        })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should update endpoint and return safe record (no secretHash)', async () => {
      const updated = { ...mockEndpoint, isActive: false };
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.findById.mockResolvedValue(mockEndpoint);
      mockRepo.updateEndpoint.mockResolvedValue(updated);

      const result = await service.updateEndpoint({
        actorUserId,
        endpointId,
        orgId,
        updates: { isActive: false },
      });

      expect(mockRepo.updateEndpoint).toHaveBeenCalledWith(
        endpointId,
        expect.objectContaining({ isActive: false })
      );
      expect(result.isActive).toBe(false);
      expect(result).not.toHaveProperty('secretHash');
    });
  });

  // ── deleteEndpoint ────────────────────────────────────────
  describe('deleteEndpoint()', () => {
    it('should delete the endpoint', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.findById.mockResolvedValue(mockEndpoint);
      mockRepo.deleteEndpoint.mockResolvedValue(undefined);

      await service.deleteEndpoint({ actorUserId, endpointId, orgId });

      expect(mockRepo.deleteEndpoint).toHaveBeenCalledWith(endpointId);
    });

    it('should throw NotFoundError if not found', async () => {
      mockOrgRepo.findMembership.mockResolvedValue(adminMembership);
      mockRepo.findById.mockResolvedValue(null);

      await expect(
        service.deleteEndpoint({ actorUserId, endpointId, orgId })
      ).rejects.toThrow(NotFoundError);
    });
  });

  // ── fanout ────────────────────────────────────────────────
  describe('fanout()', () => {
    it('should create a delivery for each subscribed active endpoint', async () => {
      mockRepo.findByOrg.mockResolvedValue([mockEndpoint]);
      mockRepo.createDelivery.mockResolvedValue(mockDelivery);

      await service.fanout({
        eventType: 'user.login',
        orgId,
        payload: { userId: 'u1' },
      });

      expect(mockRepo.createDelivery).toHaveBeenCalledTimes(1);
      expect(mockRepo.createDelivery).toHaveBeenCalledWith(
        expect.objectContaining({
          webhookEndpointId: endpointId,
          eventType: 'user.login',
        })
      );
    });

    it('should not create deliveries for unsubscribed event types', async () => {
      mockRepo.findByOrg.mockResolvedValue([
        { ...mockEndpoint, events: ['org.member.joined'] },
      ]);

      await service.fanout({
        eventType: 'user.login',
        orgId,
        payload: { userId: 'u1' },
      });

      expect(mockRepo.createDelivery).not.toHaveBeenCalled();
    });

    it('should do nothing if no active endpoints exist', async () => {
      mockRepo.findByOrg.mockResolvedValue([]);

      await service.fanout({ eventType: 'user.login', orgId, payload: {} });

      expect(mockRepo.createDelivery).not.toHaveBeenCalled();
    });
  });

  // ── retryFailed ───────────────────────────────────────────
  describe('retryFailed()', () => {
    it('should return 0 when no due deliveries', async () => {
      mockRepo.findDueDeliveries.mockResolvedValue([]);

      const count = await service.retryFailed();

      expect(count).toBe(0);
    });

    it('should call deliver for each due delivery and return count', async () => {
      mockRepo.findDueDeliveries.mockResolvedValue([mockDelivery]);
      mockRepo.findDeliveryById.mockResolvedValue(mockDelivery);
      mockRepo.findById.mockResolvedValue(null); // endpoint gone → marks failed
      mockRepo.updateDelivery.mockResolvedValue(undefined);

      const count = await service.retryFailed();

      expect(count).toBe(1);
    });

    it('should continue processing if one delivery throws', async () => {
      const d2: WebhookDelivery = { ...mockDelivery, id: 'delivery-2' };
      mockRepo.findDueDeliveries.mockResolvedValue([mockDelivery, d2]);

      mockRepo.findDeliveryById
        .mockRejectedValueOnce(new Error('DB error'))
        .mockResolvedValueOnce(d2);
      mockRepo.findById.mockResolvedValue(null);
      mockRepo.updateDelivery.mockResolvedValue(undefined);

      const count = await service.retryFailed();

      expect(count).toBe(1);
    });
  });
});
