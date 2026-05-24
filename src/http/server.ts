import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { AuthManager } from '../auth/AuthManager';
import type { VikunjaClientFactory } from '../client/VikunjaClientFactory';
import { runWithRequestContext, type ContextForgeIdentity } from '../context/request-context';
import { extractContextForgeIdentity, extractContextForgeIdentityFromMeta } from '../contextforge/identity';
import type { LinkedTokenStore } from '../storage/LinkedTokenStore';
import { registerTools } from '../tools';
import { registerContextForgeTools } from '../tools/contextforge';
import type { VikunjaUpdateHub } from '../updates/VikunjaUpdateHub';
import { verifyVikunjaWebhookSignature } from '../updates/webhook-signature';
import { MCPError, ErrorCode } from '../types';
import { logger } from '../utils/logger';

export interface HttpRuntimeOptions {
  port: number;
  host: string;
  authManager: AuthManager;
  clientFactory?: VikunjaClientFactory;
  tokenStore: LinkedTokenStore;
  updateHub: VikunjaUpdateHub;
  identityClaimsSecret?: string;
  contextForgeJwtSecret?: string;
  requireIdentity: boolean;
  requireIdentitySignature: boolean;
  webhookSecret?: string;
  maxBodyBytes?: number;
}

interface SessionTransport {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  allowsAnonymousDiscovery: boolean;
  identity?: ContextForgeIdentity | undefined;
}

interface SseSessionTransport {
  transport: SSEServerTransport;
  server: McpServer;
  identity?: ContextForgeIdentity | undefined;
}

function createMcpServer(
  authManager: AuthManager,
  clientFactory: VikunjaClientFactory | undefined,
  tokenStore: LinkedTokenStore,
  updateHub: VikunjaUpdateHub,
): McpServer {
  const server = new McpServer({
    name: 'vikunja-mcp',
    version: '0.3.0',
  }, {
    capabilities: {
      logging: {},
    },
  });

  registerTools(server, authManager, clientFactory);
  registerContextForgeTools(server, tokenStore, updateHub);
  return server;
}

function getHeader(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function isInitializeMessage(body: unknown): boolean {
  if (Array.isArray(body)) {
    return body.some(isInitializeRequest);
  }
  return isInitializeRequest(body);
}

const IDENTITY_OPTIONAL_METHODS = new Set([
  'initialize',
  'notifications/initialized',
  'tools/list',
  'resources/list',
  'resources/templates/list',
  'prompts/list',
]);

function isJsonRpcObject(value: unknown): value is { method?: unknown } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isIdentityOptionalMessage(body: unknown): boolean {
  const messages = Array.isArray(body) ? body : [body];
  return messages.length > 0 && messages.every((message) => {
    if (!isJsonRpcObject(message) || typeof message.method !== 'string') {
      return false;
    }
    return IDENTITY_OPTIONAL_METHODS.has(message.method);
  });
}

function getJsonRpcMeta(message: unknown): unknown {
  if (!isJsonRpcObject(message)) {
    return undefined;
  }
  const params = (message as { params?: unknown }).params;
  if (typeof params !== 'object' || params === null) {
    return undefined;
  }
  return (params as { _meta?: unknown })._meta;
}

function identityFromJsonRpcMeta(body: unknown): ContextForgeIdentity | undefined {
  const messages = Array.isArray(body) ? body : [body];
  let identity: ContextForgeIdentity | undefined;

  for (const message of messages) {
    const messageIdentity = extractContextForgeIdentityFromMeta(getJsonRpcMeta(message));
    if (!messageIdentity) {
      continue;
    }

    if (identity && identity.id !== messageIdentity.id) {
      throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge _meta.user cannot change within one MCP request');
    }
    identity = messageIdentity;
  }

  return identity;
}

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

async function readRawBody(req: IncomingMessage, maxBodyBytes: number): Promise<string> {
  const contentLength = Number(req.headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) {
    throw new MCPError(
      ErrorCode.REQUEST_TOO_LARGE,
      `Request body exceeds maximum size of ${maxBodyBytes} bytes`,
    );
  }

  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of req as AsyncIterable<Buffer | string>) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
    totalBytes += buffer.length;
    if (totalBytes > maxBodyBytes) {
      throw new MCPError(
        ErrorCode.REQUEST_TOO_LARGE,
        `Request body exceeds maximum size of ${maxBodyBytes} bytes`,
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function writeJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  if (res.headersSent) {
    return;
  }

  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
  });
  res.end(JSON.stringify(payload));
}

function writeText(res: ServerResponse, statusCode: number, payload: string): void {
  if (res.headersSent) {
    return;
  }

  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
  });
  res.end(payload);
}

function jsonRpcError(message: string, code = -32603): unknown {
  return {
    jsonrpc: '2.0',
    error: {
      code,
      message,
    },
    id: null,
  };
}

function statusForError(error: unknown): number {
  if (error instanceof MCPError) {
    if (error.code === ErrorCode.REQUEST_TOO_LARGE) {
      return 413;
    }
    if (error.code === ErrorCode.AUTH_REQUIRED || error.code === ErrorCode.AUTH_FAILED) {
      return 401;
    }
    if (error.code === ErrorCode.PERMISSION_DENIED) {
      return 403;
    }
    if (error.code === ErrorCode.VALIDATION_ERROR) {
      return 400;
    }
  }

  return 500;
}

function createIdentityOptions(
  options: HttpRuntimeOptions,
  requestAllowsMissingIdentity: boolean,
  sessionIdentity: ContextForgeIdentity | undefined,
  metaIdentity: ContextForgeIdentity | undefined,
): {
  claimsSecret?: string;
  contextForgeJwtSecret?: string;
  requireIdentity: boolean;
  requireSignature: boolean;
} {
  const identityOptions: {
    claimsSecret?: string;
    contextForgeJwtSecret?: string;
    requireIdentity: boolean;
    requireSignature: boolean;
  } = {
    requireIdentity: options.requireIdentity
      && !requestAllowsMissingIdentity
      && sessionIdentity === undefined
      && metaIdentity === undefined,
    requireSignature: options.requireIdentitySignature,
  };
  if (options.identityClaimsSecret !== undefined) {
    identityOptions.claimsSecret = options.identityClaimsSecret;
  }
  if (options.contextForgeJwtSecret !== undefined) {
    identityOptions.contextForgeJwtSecret = options.contextForgeJwtSecret;
  }
  return identityOptions;
}

function resolveIdentityForRequest(
  req: IncomingMessage,
  identityOptions: ReturnType<typeof createIdentityOptions>,
  sessionIdentity: ContextForgeIdentity | undefined,
  metaIdentity: ContextForgeIdentity | undefined,
): ContextForgeIdentity | undefined {
  let identity = extractContextForgeIdentity(req.headers, identityOptions) ?? metaIdentity;
  if (identity !== undefined && sessionIdentity !== undefined && sessionIdentity.id !== identity.id) {
    throw new MCPError(ErrorCode.AUTH_FAILED, 'ContextForge identity cannot change within an MCP session');
  }
  if (identity === undefined && sessionIdentity !== undefined) {
    identity = sessionIdentity;
  }
  return identity;
}

function createRequestContext(
  identity: ContextForgeIdentity | undefined,
  tokenStore: LinkedTokenStore,
): {
  identity?: ContextForgeIdentity;
  authSession?: NonNullable<ReturnType<LinkedTokenStore['getSession']>>;
} {
  const authSession = identity ? tokenStore.getSession(identity.id) : undefined;
  const requestContext: {
    identity?: ContextForgeIdentity;
    authSession?: NonNullable<typeof authSession>;
  } = {};
  if (identity !== undefined) {
    requestContext.identity = identity;
  }
  if (authSession !== undefined) {
    requestContext.authSession = authSession;
  }
  return requestContext;
}

export async function startHttpServer(options: HttpRuntimeOptions): Promise<Server> {
  const transports = new Map<string, SessionTransport>();
  const sseTransports = new Map<string, SseSessionTransport>();
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  const handleRequest = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

    if (url.pathname === '/healthz') {
      writeJson(res, 200, { ok: true });
      return;
    }

    if (url.pathname === '/webhooks/vikunja') {
      if (req.method !== 'POST') {
        writeText(res, 405, 'method not allowed');
        return;
      }

      if (!options.webhookSecret) {
        writeText(res, 404, 'not found');
        return;
      }

      const rawBody = await readRawBody(req, maxBodyBytes);
      if (!verifyVikunjaWebhookSignature(rawBody, req.headers['x-vikunja-signature'], options.webhookSecret)) {
        writeText(res, 401, 'invalid signature');
        return;
      }

      try {
        const payload = JSON.parse(rawBody) as unknown;
        const delivered = await options.updateHub.broadcastWebhook(payload);
        writeJson(res, 202, { accepted: true, delivered });
      } catch (error) {
        logger.warn('Failed to process Vikunja webhook', { error });
        writeText(res, 400, 'invalid webhook payload');
      }
      return;
    }

    if (url.pathname === '/sse') {
      if (req.method !== 'GET') {
        writeText(res, 405, 'method not allowed');
        return;
      }

      const identityOptions = createIdentityOptions(options, true, undefined, undefined);
      const identity = resolveIdentityForRequest(req, identityOptions, undefined, undefined);
      const server = createMcpServer(
        options.authManager,
        options.clientFactory,
        options.tokenStore,
        options.updateHub,
      );
      const transport = new SSEServerTransport('/message', res);
      sseTransports.set(transport.sessionId, { transport, server, identity });
      transport.onclose = (): void => {
        options.updateHub.unsubscribe(transport.sessionId);
        sseTransports.delete(transport.sessionId);
      };
      await runWithRequestContext(createRequestContext(identity, options.tokenStore), async () => {
        await server.connect(transport);
      });
      return;
    }

    if (url.pathname === '/message') {
      if (req.method !== 'POST') {
        writeText(res, 405, 'method not allowed');
        return;
      }

      const sessionId = url.searchParams.get('sessionId') ?? undefined;
      if (!sessionId) {
        writeJson(res, 400, jsonRpcError('Missing SSE session id', -32000));
        return;
      }

      const sessionTransport = sseTransports.get(sessionId);
      if (!sessionTransport) {
        writeJson(res, 404, jsonRpcError('Invalid SSE session id', -32001));
        return;
      }

      const rawBody = await readRawBody(req, maxBodyBytes);
      let body: unknown;
      if (rawBody.length > 0) {
        try {
          body = JSON.parse(rawBody) as unknown;
        } catch {
          writeJson(res, 400, jsonRpcError('Parse error', -32700));
          return;
        }
      }

      const requestAllowsMissingIdentity = isIdentityOptionalMessage(body);
      const metaIdentity = identityFromJsonRpcMeta(body);
      const identityOptions = createIdentityOptions(
        options,
        requestAllowsMissingIdentity,
        sessionTransport.identity,
        metaIdentity,
      );
      const identity = resolveIdentityForRequest(req, identityOptions, sessionTransport.identity, metaIdentity);
      if (identity !== undefined) {
        sessionTransport.identity = identity;
      }

      await runWithRequestContext(createRequestContext(identity, options.tokenStore), async () => {
        await sessionTransport.transport.handlePostMessage(req, res, body);
      });
      return;
    }

    if (url.pathname !== '/mcp') {
      writeText(res, 404, 'not found');
      return;
    }

    try {
      const sessionId = getHeader(req, 'mcp-session-id');
      let body: unknown;
      let requestAllowsMissingIdentity = false;
      const existingSessionTransport = sessionId ? transports.get(sessionId) : undefined;

      if (req.method === 'POST') {
        const rawBody = await readRawBody(req, maxBodyBytes);
        if (rawBody.length > 0) {
          try {
            body = JSON.parse(rawBody) as unknown;
          } catch {
            writeJson(res, 400, jsonRpcError('Parse error', -32700));
            return;
          }
        }
        requestAllowsMissingIdentity = isIdentityOptionalMessage(body);
      } else if ((req.method === 'GET' || req.method === 'DELETE') && sessionId) {
        requestAllowsMissingIdentity = transports.get(sessionId)?.allowsAnonymousDiscovery === true;
      }

      const metaIdentity = identityFromJsonRpcMeta(body);
      const identityOptions = createIdentityOptions(
        options,
        requestAllowsMissingIdentity,
        existingSessionTransport?.identity,
        metaIdentity,
      );
      const identity = resolveIdentityForRequest(req, identityOptions, existingSessionTransport?.identity, metaIdentity);
      if (identity !== undefined && existingSessionTransport !== undefined) {
        existingSessionTransport.identity = identity;
      }
      const requestContext = createRequestContext(identity, options.tokenStore);

      await runWithRequestContext(requestContext, async () => {
        if (req.method === 'POST') {
          let sessionTransport: SessionTransport | undefined;
          if (sessionId) {
            sessionTransport = transports.get(sessionId);
            if (!sessionTransport) {
              writeJson(res, 404, jsonRpcError('Invalid MCP session id', -32001));
              return;
            }
          } else if (isInitializeMessage(body)) {
            const server = createMcpServer(
              options.authManager,
              options.clientFactory,
              options.tokenStore,
              options.updateHub,
            );
            const allowsAnonymousDiscovery = identity === undefined;
            const transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: (): string => randomUUID(),
              onsessioninitialized: (newSessionId: string): void => {
                transports.set(newSessionId, {
                  transport,
                  server,
                  allowsAnonymousDiscovery,
                  identity,
                });
              },
              onsessionclosed: (closedSessionId: string): void => {
                options.updateHub.unsubscribe(closedSessionId);
                transports.delete(closedSessionId);
              },
            });
            transport.onclose = (): void => {
              if (transport.sessionId) {
                options.updateHub.unsubscribe(transport.sessionId);
                transports.delete(transport.sessionId);
              }
            };
            await server.connect(transport);
            sessionTransport = { transport, server, allowsAnonymousDiscovery };
          } else {
            writeJson(res, 400, jsonRpcError('Missing MCP session id for non-initialize request', -32000));
            return;
          }

          await sessionTransport.transport.handleRequest(req, res, body);
          return;
        }

        if (req.method === 'GET' || req.method === 'DELETE') {
          if (!sessionId) {
            writeJson(res, 400, jsonRpcError('Missing MCP session id', -32000));
            return;
          }
          const sessionTransport = transports.get(sessionId);
          if (!sessionTransport) {
            writeJson(res, 404, jsonRpcError('Invalid MCP session id', -32001));
            return;
          }

          await sessionTransport.transport.handleRequest(req, res);
          return;
        }

        writeJson(res, 405, jsonRpcError('Method not allowed', -32000));
      });
    } catch (error) {
      logger.warn('HTTP MCP request failed', { error });
      writeJson(
        res,
        statusForError(error),
        jsonRpcError(error instanceof Error ? error.message : 'Internal server error'),
      );
    }
  };

  const httpServer = createServer((req, res) => {
    handleRequest(req, res).catch((error: unknown) => {
      logger.warn('Unhandled HTTP MCP request failure', { error });
      if (!res.headersSent) {
        writeJson(
          res,
          statusForError(error),
          jsonRpcError(error instanceof Error ? error.message : 'Internal server error'),
        );
        return;
      }
      res.destroy(error instanceof Error ? error : undefined);
    });
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(options.port, options.host, () => {
      httpServer.off('error', reject);
      resolve();
    });
  });

  logger.info(`Vikunja MCP HTTP server listening on ${options.host}:${options.port}`);
  return httpServer;
}
