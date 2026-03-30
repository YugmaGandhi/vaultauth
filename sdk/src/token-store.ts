import { TokenPair } from './types'

// In-memory token storage
export class TokenStore {
  private accessToken: string | null = null
  private refreshToken: string | null = null
  private expiresAt: number | null = null

  set(tokens: TokenPair): void {
    this.accessToken = tokens.accessToken
    this.refreshToken = tokens.refreshToken
    // Calculate absolute expiry time from relative expiresIn
    this.expiresAt = Date.now() + tokens.expiresIn * 1000
  }

  getAccessToken(): string | null {
    return this.accessToken
  }

  getRefreshToken(): string | null {
    return this.refreshToken
  }

  // Returns true if access token exists and is not expired
  // Checks 30 seconds before actual expiry to avoid edge cases
  isAccessTokenValid(): boolean {
    if (!this.accessToken || !this.expiresAt) return false
    return Date.now() < this.expiresAt - 30 * 1000
  }

  isAuthenticated(): boolean {
    return this.refreshToken !== null
  }

  clear(): void {
    this.accessToken = null
    this.refreshToken = null
    this.expiresAt = null
  }
}