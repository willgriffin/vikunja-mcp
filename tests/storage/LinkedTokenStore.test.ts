import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LinkedTokenStore } from '../../src/storage/LinkedTokenStore';

describe('LinkedTokenStore', () => {
  let dir: string;
  let dbPath: string;
  let store: LinkedTokenStore;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vikunja-mcp-token-store-'));
    dbPath = join(dir, 'tokens.sqlite');
    store = new LinkedTokenStore(dbPath, 'a-long-enough-test-encryption-secret');
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('stores linked tokens encrypted at rest', () => {
    store.upsert({
      userId: 'alice@happyvertical.com',
      email: 'alice@happyvertical.com',
      apiUrl: 'https://tasks.example.com/api/v1',
      apiToken: 'tk_secret_token',
      authType: 'api-token',
      vikunjaUserId: '42',
      vikunjaUsername: 'alice',
    });

    const session = store.getSession('alice@happyvertical.com');
    expect(session).toEqual({
      apiUrl: 'https://tasks.example.com/api/v1',
      apiToken: 'tk_secret_token',
      authType: 'api-token',
      userId: 'alice@happyvertical.com',
    });

    const sqliteBytes = readFileSync(dbPath);
    expect(sqliteBytes.includes(Buffer.from('tk_secret_token'))).toBe(false);
  });

  it('isolates linked tokens by ContextForge user id', () => {
    store.upsert({
      userId: 'alice@happyvertical.com',
      apiUrl: 'https://tasks.example.com/api/v1',
      apiToken: 'tk_alice',
      authType: 'api-token',
    });
    store.upsert({
      userId: 'bob@happyvertical.com',
      apiUrl: 'https://tasks.example.com/api/v1',
      apiToken: 'tk_bob',
      authType: 'api-token',
    });

    expect(store.getSession('alice@happyvertical.com')?.apiToken).toBe('tk_alice');
    expect(store.getSession('bob@happyvertical.com')?.apiToken).toBe('tk_bob');
  });
});
