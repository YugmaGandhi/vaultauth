import { PasswordService } from '../../services/password.service';

// Create a fresh instance for each test
// Don't use the singleton — tests should be isolated
const passwordService = new PasswordService();

describe('PasswordService', () => {
  describe('hash()', () => {
    it('should return a hash string', async () => {
      const hash = await passwordService.hash('mypassword123');

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should return an Argon2id hash', async () => {
      const hash = await passwordService.hash('mypassword123');

      // Argon2id hashes always start with this prefix
      expect(hash).toMatch(/^\$argon2id\$/);
    });

    it('should produce different hashes for the same password', async () => {
      // Each hash call generates a new random salt
      // So the same password always produces a different hash
      const hash1 = await passwordService.hash('mypassword123');
      const hash2 = await passwordService.hash('mypassword123');

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different passwords', async () => {
      const hash1 = await passwordService.hash('password1');
      const hash2 = await passwordService.hash('password2');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verify()', () => {
    it('should return true for correct password', async () => {
      const password = 'mypassword123';
      const hash = await passwordService.hash(password);
      const result = await passwordService.verify(password, hash);

      expect(result).toBe(true);
    });

    it('should return false for wrong password', async () => {
      const hash = await passwordService.hash('correctpassword');
      const result = await passwordService.verify('wrongpassword', hash);

      expect(result).toBe(false);
    });

    it('should return false for empty hash string', async () => {
      const result = await passwordService.verify('password', '');
      expect(result).toBe(false);
    });

    it('should return false for invalid hash string', async () => {
      // Passing a non-Argon2 string should return false, not throw
      const result = await passwordService.verify(
        'password',
        'not-a-valid-hash'
      );

      expect(result).toBe(false);
    });

    it('should correctly verify after multiple hash calls', async () => {
      // Verifies that salt is correctly embedded in the hash
      const password = 'testpassword';
      const hash = await passwordService.hash(password);

      // Verify multiple times — should always be consistent
      expect(await passwordService.verify(password, hash)).toBe(true);
      expect(await passwordService.verify(password, hash)).toBe(true);
      expect(await passwordService.verify('wrong', hash)).toBe(false);
    });
  });

  describe('needsRehash()', () => {
    it('should return false for hash created with current parameters', async () => {
      const hash = await passwordService.hash('mypassword123');
      const result = passwordService.needsRehash(hash);

      expect(result).toBe(false);
    });
  });
});
