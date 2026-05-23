#!/usr/bin/env node

/**
 * Vikunja MCP Server
 * Main entry point for the Model Context Protocol server
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import dotenv from 'dotenv';

import { AuthManager } from './auth/AuthManager';
import { registerTools } from './tools';
import { logger } from './utils/logger';
import { createSecureConnectionMessage, createSecureLogConfig } from './utils/security';
import { createVikunjaClientFactory, setGlobalClientFactory, type VikunjaClientFactory } from './client';
import { LinkedTokenStore } from './storage/LinkedTokenStore';
import { VikunjaUpdateHub } from './updates/VikunjaUpdateHub';
import { startHttpServer } from './http/server';

dotenv.config({ quiet: true });

const server = new McpServer({
  name: 'vikunja-mcp',
  version: '0.2.0',
});

const authManager = new AuthManager();

let clientFactory: VikunjaClientFactory | null = null;

async function initializeFactory(): Promise<void> {
  try {
    clientFactory = await createVikunjaClientFactory(authManager);
    if (clientFactory) {
      await setGlobalClientFactory(clientFactory);
    }
  } catch (error) {
    logger.warn('Failed to initialize client factory during startup:', error);
    // Factory will be initialized on first authentication
  }
}

// Initialize factory during module load for both production and test environments
// This ensures the factory is available for tests
export const factoryInitializationPromise = initializeFactory()
  .then(() => {
    try {
      if (clientFactory) {
        registerTools(server, authManager, clientFactory);
      } else {
        registerTools(server, authManager, undefined);
      }
    } catch (error) {
      logger.error('Failed to initialize:', error);
      // Fall back to legacy registration for backwards compatibility
      registerTools(server, authManager, undefined);
    }
  })
  .catch((error) => {
    logger.warn('Failed to initialize client factory during module load:', error);
    registerTools(server, authManager, undefined);
  });

if (process.env.VIKUNJA_URL && process.env.VIKUNJA_API_TOKEN) {
  const connectionMessage = createSecureConnectionMessage(
    process.env.VIKUNJA_URL, 
    process.env.VIKUNJA_API_TOKEN
  );
  logger.info(`Auto-authenticating: ${connectionMessage}`);
  authManager.connect(process.env.VIKUNJA_URL, process.env.VIKUNJA_API_TOKEN);
  const detectedAuthType = authManager.getAuthType();
  logger.info(`Using detected auth type: ${detectedAuthType}`);
}

function parsePositiveIntegerEnv(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === '') {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    logger.warn(`Invalid positive integer environment value "${value}", using ${fallback}`);
    return fallback;
  }

  return Math.floor(parsed);
}

async function main(): Promise<void> {
  await factoryInitializationPromise;

  const transportMode = process.env.MCP_TRANSPORT ?? process.env.MCP_MODE ?? 'stdio';
  if (transportMode === 'http' || transportMode === 'streamable-http') {
    const tokenStore = new LinkedTokenStore(
      process.env.TOKEN_STORE_PATH ?? '/data/vikunja-mcp.sqlite',
      process.env.TOKEN_ENCRYPTION_KEY ?? '',
    );
    const updateHubOptions: {
      pollingIntervalMs: number;
      webhookTargetUrl?: string;
      webhookSecret?: string;
    } = {
      pollingIntervalMs: parsePositiveIntegerEnv(process.env.VIKUNJA_POLL_INTERVAL_MS, 30000),
    };
    if (process.env.VIKUNJA_MCP_WEBHOOK_URL !== undefined) {
      updateHubOptions.webhookTargetUrl = process.env.VIKUNJA_MCP_WEBHOOK_URL;
    }
    if (process.env.VIKUNJA_WEBHOOK_SECRET !== undefined) {
      updateHubOptions.webhookSecret = process.env.VIKUNJA_WEBHOOK_SECRET;
    }
    const updateHub = new VikunjaUpdateHub(updateHubOptions);

    const httpOptions: {
      port: number;
      host: string;
      authManager: AuthManager;
      clientFactory?: VikunjaClientFactory;
      tokenStore: LinkedTokenStore;
      updateHub: VikunjaUpdateHub;
      identityClaimsSecret?: string;
      requireIdentity: boolean;
      requireIdentitySignature: boolean;
      webhookSecret?: string;
    } = {
      port: Number(process.env.PORT ?? process.env.MCP_HTTP_PORT ?? '3333'),
      host: process.env.HOST ?? '0.0.0.0',
      authManager,
      tokenStore,
      updateHub,
      requireIdentity: process.env.CONTEXTFORGE_IDENTITY_REQUIRED !== 'false',
      requireIdentitySignature: process.env.CONTEXTFORGE_IDENTITY_SIGNATURE_REQUIRED !== 'false',
    };
    if (clientFactory !== null) {
      httpOptions.clientFactory = clientFactory;
    }
    if (process.env.IDENTITY_CLAIMS_SECRET !== undefined) {
      httpOptions.identityClaimsSecret = process.env.IDENTITY_CLAIMS_SECRET;
    }
    if (process.env.VIKUNJA_WEBHOOK_SECRET !== undefined) {
      httpOptions.webhookSecret = process.env.VIKUNJA_WEBHOOK_SECRET;
    }

    await startHttpServer(httpOptions);
    return;
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('Vikunja MCP server started');
  
  const config = createSecureLogConfig({
    mode: process.env.MCP_MODE,
    debug: process.env.DEBUG,
    hasAuth: !!process.env.VIKUNJA_URL && !!process.env.VIKUNJA_API_TOKEN,
    url: process.env.VIKUNJA_URL,
    token: process.env.VIKUNJA_API_TOKEN,
  });
  
  logger.debug('Configuration loaded', config);
}

// Only start the server if not in test environment
if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
  main().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

// Essential exports only - eliminated 80+ lines of unnecessary barrel exports
// Use direct imports instead of centralized re-exports for better tree-shaking

// Core types that are commonly imported by external code
export { MCPError, ErrorCode } from './types/errors';
export type { TaskResponseData, FilterExpression, Task } from './types';
export type { ParseResult } from './types/filters';
export type { AorpBuilderConfig, AorpFactoryResult } from './types';

// Core utilities that are widely used across the codebase
export { logger } from './utils/logger';
export { isAuthenticationError } from './utils/auth-error-handler';
export { withRetry, RETRY_CONFIG } from './utils/retry';
export { transformApiError, handleFetchError, handleStatusCodeError } from './utils/error-handler';
export { parseFilterString } from './utils/filters';
export { validateTaskCountLimit } from './utils/memory';
export { createStandardResponse, createAorpErrorResponse as createErrorResponse } from './utils/response-factory';

// Additional exports for task modules
export type { SimpleResponse } from './utils/simple-response';

// Client utilities for external usage
export { getClientFromContext, clearGlobalClientFactory } from './client';
