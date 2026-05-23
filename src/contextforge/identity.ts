import { createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { ContextForgeIdentity } from '../context/request-context';
import { MCPError, ErrorCode } from '../types';

export interface IdentityVerificationOptions {
  claimsSecret?: string;
  contextForgeJwtSecret?: string;
  requireSignature?: boolean;
  requireIdentity?: boolean;
}

interface ContextForgeJwtClaims {
  sub?: unknown;
  username?: unknown;
  email?: unknown;
  groups?: unknown;
  teams?: unknown;
  roles?: unknown;
  exp?: unknown;
  nbf?: unknown;
  user?: {
    email?: unknown;
    full_name?: unknown;
    is_admin?: unknown;
    auth_provider?: unknown;
  };
}

interface ContextForgeMetaUser {
  id?: unknown;
  email?: unknown;
  full_name?: unknown;
  fullName?: unknown;
  groups?: unknown;
  teams?: unknown;
  roles?: unknown;
  is_admin?: unknown;
  isAdmin?: unknown;
  auth_method?: unknown;
  authMethod?: unknown;
}

function firstHeader(headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>, name: string): string | undefined {
  const direct = headers[name] ?? headers[name.toLowerCase()];
  const value = Array.isArray(direct) ? direct[0] : direct;
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

function splitCsv(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function parseBoolean(value: string | undefined): boolean {
  return value?.toLowerCase() === 'true';
}

function base64UrlDecode(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

function parseJwtPart(value: string): unknown {
  try {
    return JSON.parse(base64UrlDecode(value).toString('utf8')) as unknown;
  } catch {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token is malformed');
  }
}

function signIdentityPayload(identity: Pick<ContextForgeIdentity, 'id' | 'email'>, secret: string): string {
  const payload = `${identity.id}:${identity.email ?? ''}`;
  return createHmac('sha256', secret).update(payload).digest('hex');
}

function safeCompareHex(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');

  if (leftBuffer.length === 0 || leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function safeCompareBuffer(left: Buffer, right: Buffer): boolean {
  if (left.length === 0 || left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}

function splitJwt(token: string): [string, string, string] {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token is malformed');
  }
  return parts as [string, string, string];
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function stringArrayClaim(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    .map((item) => item.trim());
}

function booleanClaim(value: unknown): boolean {
  return value === true;
}

function verifyJwtSignature(headerPart: string, payloadPart: string, signaturePart: string, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest();
  let actual: Buffer;
  try {
    actual = base64UrlDecode(signaturePart);
  } catch {
    return false;
  }
  return safeCompareBuffer(actual, expected);
}

function assertJwtTimeClaims(claims: ContextForgeJwtClaims, nowSeconds = Math.floor(Date.now() / 1000)): void {
  if (typeof claims.exp === 'number' && claims.exp < nowSeconds) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token is expired');
  }
  if (typeof claims.nbf === 'number' && claims.nbf > nowSeconds) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token is not yet valid');
  }
}

function identityFromContextForgeJwt(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  jwtSecret: string | undefined,
): ContextForgeIdentity | undefined {
  const authorization = firstHeader(headers, 'authorization');
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1];
  if (!token) {
    return undefined;
  }

  if (!jwtSecret) {
    throw new MCPError(ErrorCode.AUTH_REQUIRED, 'ContextForge bearer token cannot be verified');
  }

  const [headerPart, payloadPart, signaturePart] = splitJwt(token);
  const header = parseJwtPart(headerPart);
  if (typeof header !== 'object' || header === null || (header as { alg?: unknown }).alg !== 'HS256') {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token uses an unsupported algorithm');
  }

  if (!verifyJwtSignature(headerPart, payloadPart, signaturePart, jwtSecret)) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token signature is invalid');
  }

  const parsedClaims = parseJwtPart(payloadPart);
  if (typeof parsedClaims !== 'object' || parsedClaims === null) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token claims are malformed');
  }

  const claims = parsedClaims as ContextForgeJwtClaims;
  assertJwtTimeClaims(claims);

  const id = stringClaim(claims.sub) ?? stringClaim(claims.username) ?? stringClaim(claims.user?.email) ?? stringClaim(claims.email);
  if (!id) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge bearer token does not contain a user id');
  }

  const email = stringClaim(claims.user?.email) ?? stringClaim(claims.email) ?? (id.includes('@') ? id : undefined);
  const identity: ContextForgeIdentity = {
    id,
    groups: stringArrayClaim(claims.groups),
    teams: stringArrayClaim(claims.teams),
    roles: stringArrayClaim(claims.roles),
    isAdmin: claims.user?.is_admin === true,
    authMethod: 'contextforge-jwt',
  };

  if (email) {
    identity.email = email;
  }

  const fullName = stringClaim(claims.user?.full_name);
  if (fullName) {
    identity.fullName = fullName;
  }

  return identity;
}

export function verifyContextForgeSignature(
  identity: Pick<ContextForgeIdentity, 'id' | 'email'>,
  signature: string | undefined,
  claimsSecret: string | undefined,
): boolean {
  if (!signature || !claimsSecret) {
    return false;
  }

  const expected = signIdentityPayload(identity, claimsSecret);
  return safeCompareHex(signature, expected);
}

export function extractContextForgeIdentity(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  options: IdentityVerificationOptions = {},
): ContextForgeIdentity | undefined {
  const id = firstHeader(headers, 'x-forwarded-user-id');
  const email = firstHeader(headers, 'x-forwarded-user-email');

  if (!id) {
    const jwtIdentity = identityFromContextForgeJwt(headers, options.contextForgeJwtSecret);
    if (jwtIdentity) {
      return jwtIdentity;
    }

    if (options.requireIdentity) {
      throw new MCPError(ErrorCode.AUTH_REQUIRED, 'ContextForge identity header or bearer token is required');
    }
    return undefined;
  }

  const identity: ContextForgeIdentity = {
    id,
    groups: splitCsv(firstHeader(headers, 'x-forwarded-user-groups')),
    teams: splitCsv(firstHeader(headers, 'x-forwarded-user-teams')),
    roles: splitCsv(firstHeader(headers, 'x-forwarded-user-roles')),
    isAdmin: parseBoolean(firstHeader(headers, 'x-forwarded-user-admin')),
  };

  if (email) {
    identity.email = email;
  }

  const fullName = firstHeader(headers, 'x-forwarded-user-full-name');
  if (fullName) {
    identity.fullName = fullName;
  }

  const authMethod = firstHeader(headers, 'x-forwarded-user-auth-method');
  if (authMethod) {
    identity.authMethod = authMethod;
  }

  if (options.requireSignature) {
    const signature = firstHeader(headers, 'x-forwarded-user-claims-signature');
    if (!verifyContextForgeSignature(identity, signature, options.claimsSecret)) {
      throw new MCPError(ErrorCode.AUTH_REQUIRED, 'ContextForge identity signature is missing or invalid');
    }
  }

  return identity;
}

export function extractContextForgeIdentityFromMeta(meta: unknown): ContextForgeIdentity | undefined {
  if (typeof meta !== 'object' || meta === null) {
    return undefined;
  }

  const user = (meta as { user?: unknown }).user;
  if (typeof user !== 'object' || user === null) {
    return undefined;
  }

  const metaUser = user as ContextForgeMetaUser;
  const id = stringClaim(metaUser.id) ?? stringClaim(metaUser.email);
  if (!id) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge _meta.user does not contain a user id');
  }

  const identity: ContextForgeIdentity = {
    id,
    groups: stringArrayClaim(metaUser.groups),
    teams: stringArrayClaim(metaUser.teams),
    roles: stringArrayClaim(metaUser.roles),
    isAdmin: booleanClaim(metaUser.is_admin) || booleanClaim(metaUser.isAdmin),
    authMethod: stringClaim(metaUser.auth_method) ?? stringClaim(metaUser.authMethod) ?? 'contextforge-meta',
  };

  const email = stringClaim(metaUser.email) ?? (id.includes('@') ? id : undefined);
  if (email) {
    identity.email = email;
  }

  const fullName = stringClaim(metaUser.full_name) ?? stringClaim(metaUser.fullName);
  if (fullName) {
    identity.fullName = fullName;
  }

  return identity;
}
