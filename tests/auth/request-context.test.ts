import { AuthManager } from '../../src/auth/AuthManager';
import { runWithRequestContext } from '../../src/context/request-context';

describe('request-scoped auth context', () => {
  it('uses the linked user token inside ContextForge requests', async () => {
    const authManager = new AuthManager();
    authManager.connect('https://tasks.example.com/api/v1', 'tk_global');

    const session = await runWithRequestContext({
      authSession: {
        apiUrl: 'https://tasks.example.com/api/v1',
        apiToken: 'tk_alice',
        authType: 'api-token',
        userId: 'alice@happyvertical.com',
      },
    }, async () => authManager.getSession());

    expect(session.apiToken).toBe('tk_alice');
    expect(session.userId).toBe('alice@happyvertical.com');
  });

  it('does not fall back to global auth when a ContextForge request has no linked token', () => {
    const authManager = new AuthManager();
    authManager.connect('https://tasks.example.com/api/v1', 'tk_global');

    expect(() => runWithRequestContext({}, () => authManager.getSession())).toThrow(
      'No Vikunja token is linked',
    );
  });
});
