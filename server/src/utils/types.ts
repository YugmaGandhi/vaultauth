import { InferSelectModel, InferInsertModel } from 'drizzle-orm';
import {
  users,
  refreshTokens,
  roles,
  permissions,
  organizations,
  orgMembers,
  orgInvitations,
  orgRoles,
  orgPermissions,
  deletionRequests,
  webhookEndpoints,
  webhookDeliveries,
  mfaSettings,
  mfaRecoveryCodes,
  orgMfaPolicies,
  apiKeys,
} from '../db/schema';

// Infer types directly from Drizzle schema
// These stay in sync automatically when schema changes
export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
export type RefreshToken = InferSelectModel<typeof refreshTokens>;
export type Role = InferSelectModel<typeof roles>;
export type Permission = InferSelectModel<typeof permissions>;
export type Organization = InferSelectModel<typeof organizations>;
export type NewOrganization = InferInsertModel<typeof organizations>;
export type OrgMember = InferSelectModel<typeof orgMembers>;
export type OrgInvitation = InferSelectModel<typeof orgInvitations>;
export type OrgRole = InferSelectModel<typeof orgRoles>;
export type OrgPermission = InferSelectModel<typeof orgPermissions>;
export type DeletionRequest = InferSelectModel<typeof deletionRequests>;
export type WebhookEndpoint = InferSelectModel<typeof webhookEndpoints>;
export type WebhookDelivery = InferSelectModel<typeof webhookDeliveries>;
// MFA
export type MfaSetting = InferSelectModel<typeof mfaSettings>;
export type MfaRecoveryCode = InferSelectModel<typeof mfaRecoveryCodes>;
export type OrgMfaPolicy = InferSelectModel<typeof orgMfaPolicies>;
// API Keys
export type ApiKey = InferSelectModel<typeof apiKeys>;

// Safe shape for API responses — secretHash must never be sent to clients,
// same rule as passwordHash on User.
// events cast to string[] here because Drizzle types jsonb as unknown.
export type SafeWebhookEndpoint = Omit<
  WebhookEndpoint,
  'secretHash' | 'events'
> & {
  events: string[];
};

export function toSafeWebhookEndpoint(
  endpoint: WebhookEndpoint
): SafeWebhookEndpoint {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { secretHash, events, ...rest } = endpoint;
  return { ...rest, events: (events as string[]) ?? [] };
}

// API key shape safe to return in API responses.
// keyHash is SHA-256 of the full key — must never leave the server.
// permissions cast to string[] because Drizzle types jsonb as unknown.
export type SafeApiKey = Omit<ApiKey, 'keyHash' | 'permissions'> & {
  permissions: string[];
};

export function toSafeApiKey(key: ApiKey): SafeApiKey {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { keyHash, permissions, ...rest } = key;
  return { ...rest, permissions: (permissions as string[]) ?? [] };
}

// MFA setting shape safe to return in API responses.
// encryptedSecret is AES-256-GCM ciphertext — must never leave the server.
// Clients only need to know if MFA is enabled and when it was activated.
export type SafeMfaSetting = Omit<MfaSetting, 'encryptedSecret'>;

export function toSafeMfaSetting(setting: MfaSetting): SafeMfaSetting {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { encryptedSecret, ...safe } = setting;
  return safe;
}

// User shape safe to return in API responses
// Never includes passwordHash
export type SafeUser = Omit<User, 'passwordHash'>;

// What gets embedded in JWT payload
// Platform claims (roles, permissions) and org claims are separate
export type TokenUser = {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
  orgId: string | null;
  orgRole: string | null;
  orgPermissions: string[];
};

// ── Utility Functions ────────────────────────────────────
// Single source of truth for stripping sensitive fields
// Use this everywhere instead of duplicating the destructure
export function toSafeUser(user: User): SafeUser {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}
