import { createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { ContextForgeIdentity } from '../context/request-context';
import { MCPError, ErrorCode } from '../types';

export interface IdentityVerificationOptions {
  claimsSecret?: string;
  requireSignature?: boolean;
  requireIdentity?: boolean;
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
    if (options.requireIdentity) {
      throw new MCPError(ErrorCode.AUTH_REQUIRED, 'ContextForge identity header is required');
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
