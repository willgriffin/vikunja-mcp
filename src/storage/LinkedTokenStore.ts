import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { AuthManager } from '../auth/AuthManager';
import type { AuthSession } from '../types';

export interface LinkedTokenRecord {
  userId: string;
  email?: string;
  apiUrl: string;
  apiToken: string;
  authType: 'api-token' | 'jwt';
  vikunjaUserId?: string;
  vikunjaUsername?: string;
  updatedAt: string;
}

export interface LinkedTokenStatus {
  linked: boolean;
  apiUrl?: string;
  authType?: 'api-token' | 'jwt';
  vikunjaUserId?: string;
  vikunjaUsername?: string;
  updatedAt?: string;
}

interface StoredTokenRow {
  user_id: string;
  email: string | null;
  api_url: string;
  encrypted_token: string;
  iv: string;
  tag: string;
  auth_type: 'api-token' | 'jwt';
  vikunja_user_id: string | null;
  vikunja_username: string | null;
  updated_at: string;
}

export class LinkedTokenStore {
  private readonly db: Database.Database;
  private readonly encryptionKey: Buffer;

  constructor(databasePath: string, encryptionSecret: string) {
    if (!encryptionSecret || encryptionSecret.length < 16) {
      throw new Error('TOKEN_ENCRYPTION_KEY must be set to a non-empty secret of at least 16 characters');
    }

    this.db = new Database(databasePath);
    this.encryptionKey = createHash('sha256').update(encryptionSecret).digest();
    this.initialize();
  }

  close(): void {
    this.db.close();
  }

  getSession(userId: string): AuthSession | undefined {
    const record = this.get(userId);
    if (!record) {
      return undefined;
    }

    const session: AuthSession = {
      apiUrl: record.apiUrl,
      apiToken: record.apiToken,
      authType: record.authType,
      userId,
    };
    return session;
  }

  get(userId: string): LinkedTokenRecord | undefined {
    const row = this.db
      .prepare('SELECT * FROM linked_tokens WHERE user_id = ?')
      .get(userId) as StoredTokenRow | undefined;

    if (!row) {
      return undefined;
    }

    const token = this.decrypt(row.encrypted_token, row.iv, row.tag);
    const record: LinkedTokenRecord = {
      userId: row.user_id,
      apiUrl: row.api_url,
      apiToken: token,
      authType: row.auth_type,
      updatedAt: row.updated_at,
    };

    if (row.email) {
      record.email = row.email;
    }
    if (row.vikunja_user_id) {
      record.vikunjaUserId = row.vikunja_user_id;
    }
    if (row.vikunja_username) {
      record.vikunjaUsername = row.vikunja_username;
    }

    return record;
  }

  getStatus(userId: string): LinkedTokenStatus {
    const row = this.db
      .prepare('SELECT user_id, api_url, auth_type, vikunja_user_id, vikunja_username, updated_at FROM linked_tokens WHERE user_id = ?')
      .get(userId) as Omit<StoredTokenRow, 'email' | 'encrypted_token' | 'iv' | 'tag'> | undefined;

    if (!row) {
      return { linked: false };
    }

    const status: LinkedTokenStatus = {
      linked: true,
      apiUrl: row.api_url,
      authType: row.auth_type,
      updatedAt: row.updated_at,
    };

    if (row.vikunja_user_id) {
      status.vikunjaUserId = row.vikunja_user_id;
    }
    if (row.vikunja_username) {
      status.vikunjaUsername = row.vikunja_username;
    }

    return status;
  }

  upsert(record: Omit<LinkedTokenRecord, 'updatedAt'>): LinkedTokenStatus {
    const encrypted = this.encrypt(record.apiToken);
    const updatedAt = new Date().toISOString();

    this.db
      .prepare(`
        INSERT INTO linked_tokens (
          user_id, email, api_url, encrypted_token, iv, tag, auth_type,
          vikunja_user_id, vikunja_username, created_at, updated_at
        )
        VALUES (@userId, @email, @apiUrl, @encryptedToken, @iv, @tag, @authType, @vikunjaUserId, @vikunjaUsername, @updatedAt, @updatedAt)
        ON CONFLICT(user_id) DO UPDATE SET
          email = excluded.email,
          api_url = excluded.api_url,
          encrypted_token = excluded.encrypted_token,
          iv = excluded.iv,
          tag = excluded.tag,
          auth_type = excluded.auth_type,
          vikunja_user_id = excluded.vikunja_user_id,
          vikunja_username = excluded.vikunja_username,
          updated_at = excluded.updated_at
      `)
      .run({
        userId: record.userId,
        email: record.email ?? null,
        apiUrl: record.apiUrl,
        encryptedToken: encrypted.encryptedToken,
        iv: encrypted.iv,
        tag: encrypted.tag,
        authType: record.authType,
        vikunjaUserId: record.vikunjaUserId ?? null,
        vikunjaUsername: record.vikunjaUsername ?? null,
        updatedAt,
      });

    return this.getStatus(record.userId);
  }

  delete(userId: string): boolean {
    const result = this.db.prepare('DELETE FROM linked_tokens WHERE user_id = ?').run(userId);
    return result.changes > 0;
  }

  private initialize(): void {
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS linked_tokens (
        user_id TEXT PRIMARY KEY,
        email TEXT,
        api_url TEXT NOT NULL,
        encrypted_token TEXT NOT NULL,
        iv TEXT NOT NULL,
        tag TEXT NOT NULL,
        auth_type TEXT NOT NULL,
        vikunja_user_id TEXT,
        vikunja_username TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
  }

  private encrypt(token: string): { encryptedToken: string; iv: string; tag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      encryptedToken: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  private decrypt(encryptedToken: string, iv: string, tag: string): string {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      Buffer.from(iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(tag, 'base64'));

    return Buffer.concat([
      decipher.update(Buffer.from(encryptedToken, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  }
}

export async function validateVikunjaToken(apiUrl: string, token: string): Promise<{
  authType: 'api-token' | 'jwt';
  userId?: string;
  username?: string;
}> {
  const normalizedApiUrl = apiUrl.replace(/\/+$/, '');
  const response = await fetch(`${normalizedApiUrl}/user`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Vikunja token validation failed with HTTP ${response.status}`);
  }

  const user = (await response.json().catch(() => ({}))) as {
    id?: number | string;
    username?: string;
    name?: string;
  };

  const result: {
    authType: 'api-token' | 'jwt';
    userId?: string;
    username?: string;
  } = {
    authType: AuthManager.detectAuthType(token),
  };

  if (user.id !== undefined) {
    result.userId = String(user.id);
  }
  const username = user.username ?? user.name;
  if (username !== undefined) {
    result.username = username;
  }

  return result;
}
