import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { AuthManager } from '../../src/auth/AuthManager';
import type { LinkedTokenStore } from '../../src/storage/LinkedTokenStore';
import { startHttpServer, type HttpRuntimeOptions } from '../../src/http/server';
import type { VikunjaUpdateHub } from '../../src/updates/VikunjaUpdateHub';

interface TestResponse {
  statusCode: number;
  body: string;
}

function request(server: Server, method: string, path: string, body = '', headers: Record<string, string> = {}): Promise<TestResponse> {
  const address = server.address() as AddressInfo;
  const requestHeaders = { ...headers };
  if (body.length > 0) {
    requestHeaders['content-length'] = Buffer.byteLength(body).toString();
  }

  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port: address.port,
      path,
      method,
      headers: requestHeaders,
    }, (res) => {
      let responseBody = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode ?? 0, body: responseBody });
      });
    });

    req.on('error', reject);
    if (body.length > 0) {
      req.write(body);
    }
    req.end();
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function createOptions(overrides: Partial<HttpRuntimeOptions> = {}): HttpRuntimeOptions {
  return {
    port: 0,
    host: '127.0.0.1',
    authManager: {} as AuthManager,
    tokenStore: {
      getSession: jest.fn(),
    } as unknown as LinkedTokenStore,
    updateHub: {
      broadcastWebhook: jest.fn().mockResolvedValue(1),
      unsubscribe: jest.fn(),
    } as unknown as VikunjaUpdateHub,
    requireIdentity: false,
    requireIdentitySignature: false,
    ...overrides,
  };
}

describe('HTTP MCP server hardening', () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) {
      await closeServer(server);
      server = undefined;
    }
  });

  it('returns a JSON-RPC parse error for invalid JSON MCP requests', async () => {
    server = await startHttpServer(createOptions());

    const response = await request(server, 'POST', '/mcp', '{invalid-json', {
      'content-type': 'application/json',
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body)).toMatchObject({
      jsonrpc: '2.0',
      error: {
        code: -32700,
        message: 'Parse error',
      },
      id: null,
    });
  });

  it('rejects oversized request bodies before reading them fully', async () => {
    server = await startHttpServer(createOptions({ maxBodyBytes: 4 }));

    const response = await request(server, 'POST', '/mcp', '{"too":"large"}', {
      'content-type': 'application/json',
    });

    expect(response.statusCode).toBe(413);
    expect(JSON.parse(response.body).error.message).toContain('Request body exceeds maximum size');
  });

  it('does not expose the webhook endpoint without a configured secret', async () => {
    const updateHub = {
      broadcastWebhook: jest.fn(),
      unsubscribe: jest.fn(),
    } as unknown as VikunjaUpdateHub;
    server = await startHttpServer(createOptions({ updateHub }));

    const response = await request(server, 'POST', '/webhooks/vikunja', '{}');

    expect(response.statusCode).toBe(404);
    expect(updateHub.broadcastWebhook).not.toHaveBeenCalled();
  });

  it('accepts signed webhook requests when a secret is configured', async () => {
    const secret = 'vikunja-webhook-secret';
    const body = JSON.stringify({ event_name: 'task.updated' });
    const signature = createHmac('sha256', secret).update(body).digest('hex');
    const updateHub = {
      broadcastWebhook: jest.fn().mockResolvedValue(1),
      unsubscribe: jest.fn(),
    } as unknown as VikunjaUpdateHub;
    server = await startHttpServer(createOptions({ updateHub, webhookSecret: secret }));

    const response = await request(server, 'POST', '/webhooks/vikunja', body, {
      'x-vikunja-signature': signature,
    });

    expect(response.statusCode).toBe(202);
    expect(JSON.parse(response.body)).toEqual({ accepted: true, delivered: 1 });
    expect(updateHub.broadcastWebhook).toHaveBeenCalledWith(JSON.parse(body));
  });
});
