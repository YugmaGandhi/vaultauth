import argon2 from 'argon2';
import { createLogger } from '../utils/logger';

const log = createLogger('PasswordService');

// These parameters follow OWASP recommendations for Argon2id
// Do NOT lower these values — they exist for security reasons
const ARGON2_OPTIONS = {
  type: argon2.argon2id, // Argon2id variant — best of both worlds
  // id = resistant to both side-channel and GPU attacks
  memoryCost: 65536, // 64MB — makes GPU cracking expensive
  timeCost: 3, // 3 iterations — balance of speed vs security
  parallelism: 4, // 4 threads — matches typical server CPU
};

export class PasswordService {
  // ── Hash ────────────────────────────────────────────────
  // Takes a plain text password, returns a hash string
  // The hash contains the salt — no need to store separately
  async hash(password: string): Promise<string> {
    log.debug('Hashing password');

    try {
      return await argon2.hash(password, ARGON2_OPTIONS);
    } catch (err) {
      log.error({ err }, 'Failed to hash password');
      throw new Error('Password hashing failed');
    }
  }

  // ── Verify ──────────────────────────────────────────────
  // Compares a plain text password against a stored hash
  // Returns true if they match, false otherwise
  // NEVER throws on mismatch — only throws on system error
  async verify(password: string, hash: string): Promise<boolean> {
    log.debug('Verifying password');

    // Validate hash format before calling argon2
    // Valid Argon2id hashes always start with $argon2id$
    if (!hash.startsWith('$argon2')) {
      log.debug('Invalid hash format — not an Argon2 hash');
      return false;
    }

    try {
      return await argon2.verify(hash, password);
    } catch (err) {
      log.error({ err }, 'Failed to verify password');
      // Return false instead of throwing — caller handles auth logic
      return false;
    }
  }

  // ── Needs Rehash ────────────────────────────────────────
  // Returns true if the hash was created with old/weaker parameters
  // Lets you silently upgrade hashes on next login
  // Useful when you increase security parameters in the future
  needsRehash(hash: string): boolean {
    return argon2.needsRehash(hash, ARGON2_OPTIONS);
  }
}

export const passwordService = new PasswordService();
