import { createHmac } from 'node:crypto';
import { extractContextForgeIdentity, verifyContextForgeSignature } from '../../src/contextforge/identity';

function signature(userId: string, email: string, secret: string): string {
  return createHmac('sha256', secret).update(`${userId}:${email}`).digest('hex');
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
});
