# Changelog

All notable changes to Griffon are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.4.0] — 2026-04-21

### Added

**API Key Management**

- `POST /api/api-keys` — create a named API key with explicit permissions; returns plaintext key once, never stored
- `GET /api/api-keys` — list all active (non-revoked) keys for the authenticated user; `keyHash` never included in any response
- `GET /api/api-keys/:id` — get single key metadata with ownership enforcement
- `DELETE /api/api-keys/:id` — revoke a key; accepts optional `totpCode` in body for MFA-enrolled users
- `GET /api/admin/users/:id/api-keys` — admin: list any user's API keys without ownership check
- `DELETE /api/admin/users/:id/api-keys/:keyId` — admin: revoke any user's key without ownership check or MFA gate
- API key authentication in `authenticate` middleware — `Bearer grf_live_*` tokens are detected, SHA-256 hashed, looked up, and validated; `lastUsedAt` updated in background (fire-and-forget)
- New env var: `MAX_API_KEYS_PER_USER` (default: `10`) — limits active keys per user
- Bruno collection: 4 new request files (`api-key-create`, `api-key-list`, `api-key-get`, `api-key-revoke`) + 2 admin files

**Security**

- API keys stored as SHA-256 hash only — plaintext is never persisted
- `grf_live_` prefix enables identification in logs and secret scanners
- MFA gate: key creation and revocation require a valid TOTP code when MFA is enrolled
- Key permissions are frozen at creation — authenticating with a key never grants more than the specified scope
- Disabled user blocklist check applies to API key auth path (same as JWT path)

---

## [0.3.0] — 2026-04-17

### Added

**TOTP-based Multi-Factor Authentication**

- `POST /auth/mfa/setup` — generates TOTP secret, returns `otpauthUri`, base64 QR code image (`qrCodeDataUrl`), and 8 recovery codes
- `POST /auth/mfa/verify-setup` — confirms enrollment with first TOTP code; activates MFA on the account
- `POST /auth/mfa/verify` — completes two-step login; accepts TOTP code or recovery code, returns full token pair
- `GET /auth/mfa/status` — returns enrollment state and remaining recovery code count
- `DELETE /auth/mfa` — disables MFA (requires valid TOTP code)
- `POST /auth/mfa/recovery-codes` — regenerates all 8 recovery codes (requires valid TOTP code)
- `GET /api/orgs/:orgId/mfa-policy` — org owners and admins can read the MFA enforcement policy
- `PUT /api/orgs/:orgId/mfa-policy` — org owners can enable/disable MFA enforcement for all members
- `DELETE /api/admin/users/:id/mfa` — admins can force-disable MFA for a user (support recovery flow)
- `requireMfaIfEnforced()` middleware — blocks org-scoped endpoints for members without MFA when enforcement is on; super-admins bypass
- `POST /auth/login` now returns `{ mfaRequired: true, mfaToken }` when MFA is enrolled instead of tokens
- OAuth login (`oauthLogin`) also gates on MFA — same two-step flow applies

**Security**

- TOTP secrets encrypted at rest with AES-256-GCM (`MFA_ENCRYPTION_KEY`)
- MFA challenge token stored in Redis as SHA-256 hash, consumed atomically via `GETDEL` (prevents single-use race condition)
- Recovery codes: 80-bit entropy, SHA-256 hashed, normalized before hashing (dash-insensitive matching)
- `env.ts` now rejects `MFA_ENCRYPTION_KEY === WEBHOOK_SECRET_KEY` in production

**Other**

- `mfa_recovery_codes.user_id` index added — avoids full table scans on recovery code lookup
- Bruno collection: 9 new request files covering all MFA and org policy endpoints
- `login.bru` updated to auto-save `mfaToken` and clear stale tokens on MFA challenge
- `qrcode` package added for server-side QR code generation

### Changed

- `POST /auth/login` response shape — added `mfaRequired` field (always present, `false` for non-MFA logins)

---

## [0.2.0] — 2025

### Added

- Webhook events — HTTPS callbacks with HMAC-SHA256 signing and exponential backoff retry
- Admin user management API — create, update, disable, enable, force-delete users
- Account deletion — GDPR-compliant self-service with 30-day grace period
- Prometheus metrics endpoint (`/metrics`)
- JavaScript SDK (`@griffon/js`)

---

## [0.1.0] — 2025

### Added

- Email + password registration and login with Argon2id hashing
- OAuth2 — Google, GitHub, Microsoft
- JWT with RS256 signing and refresh token rotation
- RBAC — roles and permissions embedded in tokens
- Multi-organization support with org-scoped roles
- Session management — list and revoke sessions
- Email verification and password reset flows
- Redis-backed rate limiting and brute force protection
- Audit logging
