import { createHmac } from 'node:crypto';
import { extractContextForgeIdentity, verifyContextForgeSignature } from '../../src/contextforge/identity';

function signature(userId: string, email: string, secret: string): string {
  return createHmac('sha256', secret).update(`${userId}:${email}`).digest('hex');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function contextForgeJwt(claims: Record<string, unknown>, secret: string): string {
  const header = base64UrlJson({ alg: 'HS256', typ: 'JWT' });
  const payload = base64UrlJson(claims);
  const jwtSignature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${jwtSignature}`;
}

describe('ContextForge identity verification', () => {
  it('extracts signed identity headers', () => {
    const secret = 'contextforge-claims-secret';
    const headers = {
      'x-forwarded-user-id': 'alice@happyvertical.com',
      'x-forwarded-user-email': 'alice@happyvertical.com',
      'x-forwarded-user-groups': 'platform,contextforge',
      'x-forwarded-user-admin': 'true',
      'x-forwarded-user-claims-signature': signature('alice@happyvertical.com', 'alice@happyvertical.com', secret),
    };

    const identity = extractContextForgeIdentity(headers, {
      claimsSecret: secret,
      requireIdentity: true,
      requireSignature: true,
    });

    expect(identity).toEqual({
      id: 'alice@happyvertical.com',
      email: 'alice@happyvertical.com',
      groups: ['platform', 'contextforge'],
      teams: [],
      roles: [],
      isAdmin: true,
    });
  });

  it('rejects invalid signatures', () => {
    expect(() => extractContextForgeIdentity({
      'x-forwarded-user-id': 'alice@happyvertical.com',
      'x-forwarded-user-email': 'alice@happyvertical.com',
      'x-forwarded-user-claims-signature': '00',
    }, {
      claimsSecret: 'contextforge-claims-secret',
      requireIdentity: true,
      requireSignature: true,
    })).toThrow('signature is missing or invalid');
  });

  it('uses ContextForge user-id/email payload semantics', () => {
    const secret = 'contextforge-claims-secret';
    const valid = signature('bob@happyvertical.com', '', secret);

    expect(verifyContextForgeSignature({ id: 'bob@happyvertical.com' }, valid, secret)).toBe(true);
    expect(verifyContextForgeSignature({ id: 'bob@happyvertical.com', email: 'bob@happyvertical.com' }, valid, secret)).toBe(false);
  });

  it('extracts identity from a verified ContextForge bearer JWT when forwarded headers are absent', () => {
    const secret = 'contextforge-jwt-secret';
    const token = contextForgeJwt({
      iss: 'mcpgateway',
      aud: 'mcpgateway-api',
      sub: 'cricket@happyvertical.com',
      username: 'cricket@happyvertical.com',
      user: {
        email: 'cricket@happyvertical.com',
        full_name: 'Cricket',
        is_admin: false,
      },
      teams: ['team-a'],
    }, secret);

    const identity = extractContextForgeIdentity({
      authorization: `Bearer ${token}`,
    }, {
      contextForgeJwtSecret: secret,
      requireIdentity: true,
      requireSignature: true,
    });

    expect(identity).toEqual({
      id: 'cricket@happyvertical.com',
      email: 'cricket@happyvertical.com',
      fullName: 'Cricket',
      groups: [],
      teams: ['team-a'],
      roles: [],
      isAdmin: false,
      authMethod: 'contextforge-jwt',
    });
  });

  it('rejects a ContextForge bearer JWT with an invalid signature', () => {
    const token = contextForgeJwt({
      sub: 'cricket@happyvertical.com',
      user: { email: 'cricket@happyvertical.com' },
    }, 'actual-secret');

    expect(() => extractContextForgeIdentity({
      authorization: `Bearer ${token}`,
    }, {
      contextForgeJwtSecret: 'wrong-secret',
      requireIdentity: true,
      requireSignature: true,
    })).toThrow('bearer token signature is invalid');
  });
});
