# @vaultauth/js

Official JavaScript/TypeScript SDK for [VaultAuth](https://github.com/YugmaGandhi/vaultauth).

## Installation
```bash
npm install @vaultauth/js
```

## Quick Start
```typescript
import { VaultAuthClient } from '@vaultauth/js'

const client = new VaultAuthClient({
  baseUrl: 'https://your-vaultauth-instance.com'
})

// Register
await client.register('user@example.com', 'password123')

// Login
const { user } = await client.login('user@example.com', 'password123')
console.log(user.email, user.roles)

// Make authenticated requests — token handled automatically
const me = await client.getMe()

// Token refresh happens automatically when expired

// Logout
await client.logout()
```

## OAuth
```typescript
// Redirect user to OAuth provider
window.location.href = client.getOAuthUrl('google')

// After redirect back — extract tokens from URL
const params = new URLSearchParams(window.location.search)
client.handleOAuthCallback(
  params.get('accessToken')!,
  params.get('refreshToken')!
)
```

## Error Handling
```typescript
import { VaultAuthClient, VaultAuthError } from '@vaultauth/js'

try {
  await client.login('user@example.com', 'wrongpassword')
} catch (err) {
  if (err instanceof VaultAuthError) {
    console.log(err.code)    // 'INVALID_CREDENTIALS'
    console.log(err.message) // 'Invalid email or password'
    console.log(err.statusCode) // 401

    // Convenience checks
    if (err.isTokenExpired) { ... }
    if (err.isRateLimited) { ... }
    if (err.isValidationError) {
      err.details?.forEach(d => console.log(d.field, d.message))
    }
  }
}
```

## Configuration
```typescript
const client = new VaultAuthClient({
  baseUrl: 'https://your-vaultauth-instance.com',
  timeout: 10000,        // Request timeout in ms (default: 10000)
  fetchImpl: customFetch // Custom fetch implementation (optional)
})
```