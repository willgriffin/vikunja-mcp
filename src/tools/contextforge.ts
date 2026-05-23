import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { getRequestAuthSession, getRequestIdentity, type ContextForgeIdentity } from '../context/request-context';
import type { LinkedTokenStore } from '../storage/LinkedTokenStore';
import { validateVikunjaToken } from '../storage/LinkedTokenStore';
import type { VikunjaUpdateHub } from '../updates/VikunjaUpdateHub';
import { MCPError, ErrorCode } from '../types';
import { createStandardResponse } from '../utils/response-factory';
import { formatMcpResponse } from '../utils/simple-response';

function requireIdentity(): ContextForgeIdentity {
  const identity = getRequestIdentity();
  if (!identity) {
    throw new MCPError(ErrorCode.AUTH_REQUIRED, 'ContextForge identity is required');
  }
  return identity;
}

export function registerContextForgeTools(
  server: McpServer,
  tokenStore: LinkedTokenStore | undefined,
  updateHub: VikunjaUpdateHub | undefined,
): void {
  server.tool(
    'link_vikunja_token',
    'Link a Vikunja API token to the current ContextForge user',
    {
      token: z.string().min(1),
      apiUrl: z.string().url().optional(),
    },
    async (args) => {
      if (!tokenStore) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'Linked token storage is not configured');
      }

      const identity = requireIdentity();
      const apiUrl = (args.apiUrl ?? process.env.VIKUNJA_URL)?.replace(/\/+$/, '');
      if (!apiUrl) {
        throw new MCPError(ErrorCode.VALIDATION_ERROR, 'apiUrl or VIKUNJA_URL is required');
      }

      const validation = await validateVikunjaToken(apiUrl, args.token);
      const tokenRecord: {
        userId: string;
        email?: string;
        apiUrl: string;
        apiToken: string;
        authType: 'api-token' | 'jwt';
        vikunjaUserId?: string;
        vikunjaUsername?: string;
      } = {
        userId: identity.id,
        apiUrl,
        apiToken: args.token,
        authType: validation.authType,
      };
      if (identity.email !== undefined) {
        tokenRecord.email = identity.email;
      }
      if (validation.userId !== undefined) {
        tokenRecord.vikunjaUserId = validation.userId;
      }
      if (validation.username !== undefined) {
        tokenRecord.vikunjaUsername = validation.username;
      }

      const status = tokenStore.upsert(tokenRecord);

      const response = createStandardResponse(
        'link-vikunja-token',
        'Vikunja token linked for the current ContextForge user',
        { ...status } as Record<string, unknown>,
        { userId: identity.id },
      );
      return { content: formatMcpResponse(response) };
    },
  );

  server.tool(
    'vikunja_auth_status',
    'Return linked Vikunja authentication status for the current ContextForge user',
    {},
    () => {
      if (!tokenStore) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'Linked token storage is not configured');
      }

      const identity = requireIdentity();
      const status = tokenStore.getStatus(identity.id);
      const response = createStandardResponse(
        'vikunja-auth-status',
        status.linked ? 'Vikunja token is linked' : 'No Vikunja token is linked',
        { ...status } as Record<string, unknown>,
        { userId: identity.id },
      );
      return { content: formatMcpResponse(response) };
    },
  );

  server.tool(
    'unlink_vikunja_token',
    'Remove the linked Vikunja API token for the current ContextForge user',
    {},
    () => {
      if (!tokenStore) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'Linked token storage is not configured');
      }

      const identity = requireIdentity();
      const removed = tokenStore.delete(identity.id);
      const response = createStandardResponse(
        'unlink-vikunja-token',
        removed ? 'Linked Vikunja token removed' : 'No linked Vikunja token was present',
        { linked: false, removed },
        { userId: identity.id },
      );
      return { content: formatMcpResponse(response) };
    },
  );

  server.tool(
    'watch_project_updates',
    'Subscribe to Vikunja project task updates for the current ContextForge MCP session',
    {
      projectId: z.number().int().positive(),
      enableWebhook: z.boolean().optional(),
    },
    async (args, extra) => {
      if (!updateHub) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'Vikunja update hub is not configured');
      }

      const identity = requireIdentity();
      const authSession = getRequestAuthSession();
      if (!authSession) {
        throw new MCPError(
          ErrorCode.AUTH_REQUIRED,
          'No Vikunja token is linked for this ContextForge user. Use link_vikunja_token first.',
        );
      }
      if (!extra.sessionId) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'MCP session id is required for update subscriptions');
      }

      await updateHub.ensureProjectAccess(authSession, args.projectId);
      const webhookStatus = args.enableWebhook === false
        ? 'skipped'
        : await updateHub.ensureWebhook(authSession, args.projectId);

      updateHub.subscribe({
        sessionId: extra.sessionId,
        server,
        identity,
        authSession,
        projectId: args.projectId,
      });

      const response = createStandardResponse(
        'watch-project-updates',
        `Subscribed to Vikunja project ${args.projectId} updates`,
        {
          subscribed: true,
          projectId: args.projectId,
          webhook: webhookStatus,
          polling: true,
        },
        { userId: identity.id, sessionId: extra.sessionId },
      );
      return { content: formatMcpResponse(response) };
    },
  );

  server.tool(
    'unwatch_project_updates',
    'Unsubscribe the current ContextForge MCP session from Vikunja project updates',
    {
      projectId: z.number().int().positive().optional(),
    },
    (args, extra) => {
      if (!updateHub) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'Vikunja update hub is not configured');
      }
      if (!extra.sessionId) {
        throw new MCPError(ErrorCode.INTERNAL_ERROR, 'MCP session id is required for update subscriptions');
      }

      const removed = updateHub.unsubscribe(extra.sessionId, args.projectId);
      const response = createStandardResponse(
        'unwatch-project-updates',
        `Removed ${removed} Vikunja update subscription(s)`,
        { removed },
        { sessionId: extra.sessionId },
      );
      return { content: formatMcpResponse(response) };
    },
  );
}
