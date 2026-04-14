import { deletionService } from '../services/deletion.service';
import { createLogger } from '../utils/logger';

const log = createLogger('DeletionPurgeJob');
const INTERVAL_MS = 60 * 60 * 1000; // 1 hour

export function startDeletionPurgeJob(): NodeJS.Timeout {
  log.info('Deletion purge job started');

  const handle = setInterval(() => {
    void (async () => {
      log.debug('Running deletion purge check');
      try {
        const purged = await deletionService.purgeExpired();
        if (purged > 0) {
          log.info({ purged }, 'Deletion purge completed');
        }
      } catch (err) {
        log.error({ err }, 'Deletion purge job failed');
      }
    })();
  }, INTERVAL_MS);

  return handle;
}
