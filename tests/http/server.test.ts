import { createHmac } from 'node:crypto';
import { request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { AuthManager } from '../../src/auth/AuthManager';
import type { LinkedTokenStore } from '../../src/storage/LinkedTokenStore';
import { startHttpServer, type HttpRuntimeOptions } from '../../src/http/server';
import type { VikunjaUpdateHub } from '../../src/updates/VikunjaUpdateHub';

interface TestResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
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
        resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: responseBody });
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

function parseMcpBody(body: string): unknown {
  const dataLine = body.split('\n').find((line) => line.startsWith('data: '));
  return JSON.parse(dataLine ? dataLine.slice('data: '.length) : body);
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function contextForgeJwt(userId: string, secret: string): string {
  const header = base64UrlJson({ alg: 'HS256', typ: 'JWT' });
  const payload = base64UrlJson({
    iss: 'mcpgateway',
    aud: 'mcpgateway-api',
    sub: userId,
    username: userId,
    user: {
      email: userId,
      full_name: 'ContextForge User',
      is_admin: false,
    },
  });
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function createOptions(overrides: Partial<HttpRuntimeOptions> = {}): HttpRuntimeOptions {
  return {
    port: 0,
    host: '127.0.0.1',
    authManager: {} as AuthManager,
    tokenStore: {
      getSession: jest.fn(),
      getStatus: jest.fn().mockReturnValue({ linked: false }),
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

  it('allows anonymous MCP discovery when ContextForge identity is required', async () => {
    server = await startHttpServer(createOptions({
      requireIdentity: true,
      requireIdentitySignature: true,
      identityClaimsSecret: 'identity-secret',
    }));

    const initializeResponse = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'contextforge-probe', version: '0.0.0' },
        },
      }),
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
      },
    );
    const sessionId = initializeResponse.headers['mcp-session-id'];

    expect(initializeResponse.statusCode).toBe(200);
    expect(typeof sessionId).toBe('string');

    const toolsResponse = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      }),
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-session-id': String(sessionId),
      },
    );

    expect(toolsResponse.statusCode).toBe(200);
    expect(parseMcpBody(toolsResponse.body)).toMatchObject({
      jsonrpc: '2.0',
      id: 2,
    });
  });

  it('still requires ContextForge identity for tool calls after anonymous discovery', async () => {
    server = await startHttpServer(createOptions({
      requireIdentity: true,
      requireIdentitySignature: true,
      identityClaimsSecret: 'identity-secret',
    }));

    const initializeResponse = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'contextforge-probe', version: '0.0.0' },
        },
      }),
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
      },
    );

    const response = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'vikunja_auth_status',
          arguments: {},
        },
      }),
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-session-id': String(initializeResponse.headers['mcp-session-id']),
      },
    );

    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.body).error.message).toBe('ContextForge identity header or bearer token is required');
  });

  it('accepts a verified ContextForge bearer JWT for user-scoped tool calls', async () => {
    const tokenStore = {
      getSession: jest.fn(),
      getStatus: jest.fn().mockReturnValue({ linked: false }),
    } as unknown as LinkedTokenStore;
    server = await startHttpServer(createOptions({
      tokenStore,
      requireIdentity: true,
      requireIdentitySignature: true,
      contextForgeJwtSecret: 'contextforge-jwt-secret',
    }));

    const initializeResponse = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'contextforge-probe', version: '0.0.0' },
        },
      }),
      {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
      },
    );

    const response = await request(
      server,
      'POST',
      '/mcp',
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'vikunja_auth_status',
          arguments: {},
        },
      }),
      {
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${contextForgeJwt('cricket@happyvertical.com', 'contextforge-jwt-secret')}`,
        'content-type': 'application/json',
        'mcp-session-id': String(initializeResponse.headers['mcp-session-id']),
      },
    );

    expect(response.statusCode).toBe(200);
    expect((tokenStore.getStatus as jest.Mock)).toHaveBeenCalledWith('cricket@happyvertical.com');
    expect(JSON.stringify(parseMcpBody(response.body))).toContain('No Vikunja token is linked');
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
