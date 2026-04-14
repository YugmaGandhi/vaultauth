import { startWebhookDeliveryJob } from '../../jobs/webhook-delivery.job';
import { webhookService } from '../../services/webhook.service';

jest.mock('../../services/webhook.service', () => ({
  webhookService: { retryFailed: jest.fn() },
}));

const mockRetryFailed = webhookService.retryFailed as jest.Mock;

describe('startWebhookDeliveryJob()', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should return an interval handle', () => {
    const handle = startWebhookDeliveryJob();
    expect(handle).toBeDefined();
    clearInterval(handle);
  });

  it('should call retryFailed after 30 seconds', async () => {
    mockRetryFailed.mockResolvedValue(0);

    const handle = startWebhookDeliveryJob();

    jest.advanceTimersByTime(30_000);
    await Promise.resolve();

    expect(mockRetryFailed).toHaveBeenCalledTimes(1);

    clearInterval(handle);
  });

  it('should not throw if retryFailed rejects', async () => {
    mockRetryFailed.mockRejectedValue(new Error('network error'));

    const handle = startWebhookDeliveryJob();

    jest.advanceTimersByTime(30_000);
    await Promise.resolve();

    // Job must swallow the error — no unhandled rejection
    expect(mockRetryFailed).toHaveBeenCalled();

    clearInterval(handle);
  });
});
