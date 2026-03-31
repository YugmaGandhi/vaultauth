// ── Mock logger ──────────────────────────────────────────
jest.mock('../../utils/logger', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

// ── Mock env ─────────────────────────────────────────────
jest.mock('../../config/env', () => ({
  env: {
    OAUTH_CALLBACK_BASE_URL: 'http://localhost:3000',
  },
}));

// ── Mock oauth-providers ─────────────────────────────────
const mockGoogleProvider = {
  name: 'google',
  authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  profileUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
  scopes: ['email', 'profile'],
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  getProfile: (data: Record<string, unknown>) => ({
    id: String(data.id),
    email: String(data.email),
  }),
};

jest.mock('../../config/oauth-providers', () => ({
  getOAuthProvider: jest.fn((name: string) => {
    if (name === 'google') return mockGoogleProvider;
    return null;
  }),
}));

// ── Mock global fetch ────────────────────────────────────
const mockFetch = jest.fn();
global.fetch = mockFetch;

import { OAuthService } from '../../services/oauth.service';

const oauthService = new OAuthService();

beforeEach(() => {
  jest.clearAllMocks();
});

describe('OAuthService', () => {
  // ── buildAuthUrl() ──────────────────────────────────────
  describe('buildAuthUrl()', () => {
    it('should build a valid Google auth URL', () => {
      const url = oauthService.buildAuthUrl('google', 'test-state-123');

      expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('state=test-state-123');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=email+profile');
      expect(url).toContain(
        'redirect_uri=' +
          encodeURIComponent('http://localhost:3000/auth/oauth/google/callback')
      );
    });

    it('should throw for unconfigured provider', () => {
      expect(() => oauthService.buildAuthUrl('discord', 'state')).toThrow(
        "OAuth provider 'discord' is not configured"
      );
    });
  });

  // ── exchangeCode() ──────────────────────────────────────
  describe('exchangeCode()', () => {
    it('should exchange code for access token', async () => {
      mockFetch.mockResolvedValue({
        json: () =>
          Promise.resolve({
            access_token: 'google-access-token-123',
            token_type: 'Bearer',
          }),
      });

      const token = await oauthService.exchangeCode('google', 'auth-code-xyz');

      expect(token).toBe('google-access-token-123');
      expect(mockFetch).toHaveBeenCalledWith(
        'https://oauth2.googleapis.com/token',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        })
      );
    });

    it('should throw when token exchange fails', async () => {
      mockFetch.mockResolvedValue({
        json: () =>
          Promise.resolve({
            error: 'invalid_grant',
          }),
      });

      await expect(
        oauthService.exchangeCode('google', 'bad-code')
      ).rejects.toThrow('OAuth token exchange failed: invalid_grant');
    });

    it('should throw when access_token is missing', async () => {
      mockFetch.mockResolvedValue({
        json: () =>
          Promise.resolve({
            token_type: 'Bearer',
          }),
      });

      await expect(oauthService.exchangeCode('google', 'code')).rejects.toThrow(
        'OAuth token exchange failed'
      );
    });

    it('should throw for unconfigured provider', async () => {
      await expect(
        oauthService.exchangeCode('discord', 'code')
      ).rejects.toThrow("OAuth provider 'discord' is not configured");
    });
  });

  // ── fetchProfile() ──────────────────────────────────────
  describe('fetchProfile()', () => {
    it('should fetch and normalize user profile', async () => {
      mockFetch.mockResolvedValue({
        json: () =>
          Promise.resolve({
            id: '12345',
            email: 'user@gmail.com',
            name: 'Test User',
          }),
      });

      const profile = await oauthService.fetchProfile('google', 'access-token');

      expect(profile).toEqual({
        id: '12345',
        email: 'user@gmail.com',
      });
      expect(mockFetch).toHaveBeenCalledWith(
        'https://www.googleapis.com/oauth2/v2/userinfo',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer access-token',
          }),
        })
      );
    });

    it('should throw when email is missing from profile', async () => {
      // Override getProfile to return empty email
      const originalGetProfile = mockGoogleProvider.getProfile;
      mockGoogleProvider.getProfile = () => ({ id: '12345', email: '' });

      mockFetch.mockResolvedValue({
        json: () => Promise.resolve({ id: '12345' }),
      });

      await expect(
        oauthService.fetchProfile('google', 'token')
      ).rejects.toThrow('Could not retrieve email from OAuth provider');

      mockGoogleProvider.getProfile = originalGetProfile;
    });

    it('should throw for unconfigured provider', async () => {
      await expect(
        oauthService.fetchProfile('discord', 'token')
      ).rejects.toThrow("OAuth provider 'discord' is not configured");
    });
  });

  // ── generateState() ─────────────────────────────────────
  describe('generateState()', () => {
    it('should return a hex string', () => {
      const state = oauthService.generateState();

      expect(typeof state).toBe('string');
      expect(state).toMatch(/^[a-f0-9]{32}$/);
    });

    it('should generate unique states', () => {
      const state1 = oauthService.generateState();
      const state2 = oauthService.generateState();

      expect(state1).not.toBe(state2);
    });
  });
});
