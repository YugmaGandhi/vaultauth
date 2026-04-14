import { webhookService } from '../services/webhook.service';
import { createLogger } from '../utils/logger';

const log = createLogger('WebhookDeliveryJob');

const POLL_INTERVAL_MS = 30_000; // 30 seconds — keeps first retry (5s delay) responsive

export function startWebhookDeliveryJob(): NodeJS.Timeout {
  const handle = setInterval(() => {
    void (async () => {
      try {
        const processed = await webhookService.retryFailed();
        if (processed > 0) {
          log.info({ processed }, 'Webhook delivery job completed');
        }
      } catch (err) {
        log.error({ err }, 'Webhook delivery job failed');
      }
    })();
  }, POLL_INTERVAL_MS);

  return handle;
}
