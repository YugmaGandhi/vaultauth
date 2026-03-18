import { ZodIssue } from 'zod';
import { envSchema } from '../../config/env';

describe('Environment Configuration', () => {
  it('should load valid environment variables successfully', () => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
      REDIS_URL: 'redis://localhost:6380',
      NODE_ENV: 'test',
    });

    expect(result.success).toBe(true);
  });

  it('should fail when DATABASE_URL is missing', () => {
    const result = envSchema.safeParse({
      REDIS_URL: 'redis://localhost:6380',
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map(
        (issue: ZodIssue) => issue.path[0]
      );
      expect(fields).toContain('DATABASE_URL');
    }
  });

  it('should fail when REDIS_URL is missing', () => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      const fields = result.error.issues.map(
        (issue: ZodIssue) => issue.path[0]
      );
      expect(fields).toContain('REDIS_URL');
    }
  });

  it('should use default PORT of 3000 when not set', () => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
      REDIS_URL: 'redis://localhost:6380',
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.PORT).toBe(3000);
    }
  });

  it('should reject invalid NODE_ENV values', () => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
      REDIS_URL: 'redis://localhost:6380',
      NODE_ENV: 'staging',
    });

    expect(result.success).toBe(false);
  });

  it('should coerce PORT from string to number', () => {
    const result = envSchema.safeParse({
      DATABASE_URL: 'postgresql://user:pass@localhost:5433/test',
      REDIS_URL: 'redis://localhost:6380',
      PORT: '4000', // string — should be coerced to number
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.PORT).toBe(4000);
      expect(typeof result.data.PORT).toBe('number');
    }
  });
});
