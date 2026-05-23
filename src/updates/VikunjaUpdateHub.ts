import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuthSession } from '../types';
import type { ContextForgeIdentity } from '../context/request-context';
import { logger } from '../utils/logger';

export interface VikunjaUpdateEvent {
  source: 'webhook' | 'poll';
  eventName: string;
  projectId: number;
  taskId?: number;
  timestamp: string;
  doer?: unknown;
  task?: unknown;
  project?: unknown;
  changedFields?: string[];
  raw?: unknown;
}

export interface UpdateSubscription {
  sessionId: string;
  server: McpServer;
  identity: ContextForgeIdentity;
  authSession: AuthSession;
  projectId: number;
  pollTimer?: NodeJS.Timeout;
  lastFingerprint?: string;
  lastAccessCheck?: number;
}

export interface VikunjaUpdateHubOptions {
  pollingIntervalMs: number;
  webhookTargetUrl?: string;
  webhookSecret?: string;
}

const WATCHED_EVENTS = [
  'task.created',
  'task.updated',
  'task.deleted',
  'task.assignee.created',
  'task.assignee.deleted',
  'task.comment.created',
  'task.comment.edited',
  'task.comment.deleted',
  'task.attachment.created',
  'task.attachment.deleted',
  'task.relation.created',
  'task.relation.deleted',
  'project.updated',
  'project.deleted',
  'project.shared.user',
  'project.shared.team',
];

export class VikunjaUpdateHub {
  private readonly subscriptions = new Map<string, UpdateSubscription>();

  constructor(private readonly options: VikunjaUpdateHubOptions) {}

  subscribe(subscription: Omit<UpdateSubscription, 'lastAccessCheck'>): void {
    const key = this.subscriptionKey(subscription.sessionId, subscription.projectId);
    const existing = this.subscriptions.get(key);
    if (existing?.pollTimer) {
      clearInterval(existing.pollTimer);
    }

    const stored: UpdateSubscription = {
      ...subscription,
      lastAccessCheck: 0,
    };
    this.subscriptions.set(key, stored);
    this.startPolling(stored);
  }

  unsubscribe(sessionId: string, projectId?: number): number {
    let removed = 0;
    for (const [key, subscription] of this.subscriptions.entries()) {
      if (subscription.sessionId !== sessionId) {
        continue;
      }
      if (projectId !== undefined && subscription.projectId !== projectId) {
        continue;
      }
      if (subscription.pollTimer) {
        clearInterval(subscription.pollTimer);
      }
      this.subscriptions.delete(key);
      removed += 1;
    }
    return removed;
  }

  async ensureProjectAccess(session: AuthSession, projectId: number): Promise<void> {
    const response = await fetch(`${session.apiUrl.replace(/\/+$/, '')}/projects/${projectId}`, {
      method: 'GET',
      headers: this.authHeaders(session),
    });

    if (!response.ok) {
      throw new Error(`Vikunja project ${projectId} is not accessible with the linked token`);
    }
  }

  async ensureWebhook(session: AuthSession, projectId: number): Promise<'created' | 'exists' | 'skipped'> {
    if (!this.options.webhookTargetUrl || !this.options.webhookSecret) {
      return 'skipped';
    }

    const baseUrl = session.apiUrl.replace(/\/+$/, '');
    const listResponse = await fetch(`${baseUrl}/projects/${projectId}/webhooks`, {
      method: 'GET',
      headers: this.authHeaders(session),
    });

    if (!listResponse.ok) {
      logger.warn('Unable to list Vikunja webhooks; polling remains active', {
        projectId,
        status: listResponse.status,
      });
      return 'skipped';
    }

    const existingWebhooks = (await listResponse.json().catch(() => [])) as Array<{
      target_url?: string;
      events?: string[];
    }>;

    const matching = existingWebhooks.find((webhook) => webhook.target_url === this.options.webhookTargetUrl);
    if (matching) {
      return 'exists';
    }

    const createResponse = await fetch(`${baseUrl}/projects/${projectId}/webhooks`, {
      method: 'PUT',
      headers: this.authHeaders(session),
      body: JSON.stringify({
        target_url: this.options.webhookTargetUrl,
        events: WATCHED_EVENTS,
        secret: this.options.webhookSecret,
      }),
    });

    if (!createResponse.ok) {
      logger.warn('Unable to create Vikunja webhook; polling remains active', {
        projectId,
        status: createResponse.status,
      });
      return 'skipped';
    }

    return 'created';
  }

  async broadcastWebhook(payload: unknown): Promise<number> {
    const update = this.webhookPayloadToUpdate(payload);
    if (!update) {
      logger.debug('Ignoring Vikunja webhook without project context', { payload });
      return 0;
    }

    return this.broadcast(update);
  }

  private async broadcast(update: VikunjaUpdateEvent): Promise<number> {
    let delivered = 0;
    const matchingSubscriptions = [...this.subscriptions.values()].filter(
      (subscription) => subscription.projectId === update.projectId,
    );

    for (const subscription of matchingSubscriptions) {
      const hasAccess = await this.subscriptionStillHasAccess(subscription);
      if (!hasAccess) {
        this.unsubscribe(subscription.sessionId, subscription.projectId);
        continue;
      }

      try {
        await subscription.server.sendLoggingMessage(
          {
            level: 'info',
            logger: 'vikunja.updates',
            data: update,
          },
          subscription.sessionId,
        );
        delivered += 1;
      } catch (error) {
        logger.warn('Failed to send Vikunja update notification', {
          projectId: update.projectId,
          sessionId: subscription.sessionId,
          error,
        });
      }
    }

    return delivered;
  }

  private startPolling(subscription: UpdateSubscription): void {
    const poll = async (): Promise<void> => {
      try {
        const tasks = await this.fetchProjectTasks(subscription.authSession, subscription.projectId);
        const fingerprint = this.fingerprintTasks(tasks);
        if (!subscription.lastFingerprint) {
          subscription.lastFingerprint = fingerprint;
          return;
        }

        if (subscription.lastFingerprint !== fingerprint) {
          subscription.lastFingerprint = fingerprint;
          await this.broadcast({
            source: 'poll',
            eventName: 'project.tasks.changed',
            projectId: subscription.projectId,
            timestamp: new Date().toISOString(),
            raw: { taskCount: Array.isArray(tasks) ? tasks.length : 0 },
          });
        }
      } catch (error) {
        logger.warn('Vikunja polling failed for subscription', {
          sessionId: subscription.sessionId,
          projectId: subscription.projectId,
          error,
        });
      }
    };

    void poll();
    subscription.pollTimer = setInterval((): void => {
      void poll();
    }, this.options.pollingIntervalMs);
  }

  private async fetchProjectTasks(session: AuthSession, projectId: number): Promise<unknown[]> {
    const response = await fetch(`${session.apiUrl.replace(/\/+$/, '')}/projects/${projectId}/tasks?per_page=250`, {
      method: 'GET',
      headers: this.authHeaders(session),
    });

    if (!response.ok) {
      throw new Error(`Failed to poll Vikunja project ${projectId}: HTTP ${response.status}`);
    }

    const body: unknown = await response.json();
    return Array.isArray(body) ? body as unknown[] : [];
  }

  private fingerprintTasks(tasks: unknown[]): string {
    const summary = tasks.map((task) => {
      const value = task as {
        id?: number;
        updated?: string;
        bucket_id?: number;
        done?: boolean;
        assignees?: unknown[];
      };
      return {
        id: value.id,
        updated: value.updated,
        bucket_id: value.bucket_id,
        done: value.done,
        assignees: value.assignees,
      };
    });

    return JSON.stringify(summary.sort((left, right) => Number(left.id ?? 0) - Number(right.id ?? 0)));
  }

  private webhookPayloadToUpdate(payload: unknown): VikunjaUpdateEvent | undefined {
    const body = payload as {
      event_name?: string;
      time?: string;
      data?: {
        task?: { id?: number; project_id?: number; bucket_id?: number; assignees?: unknown[] };
        project?: { id?: number };
        doer?: unknown;
      };
    };

    const projectId = body.data?.task?.project_id ?? body.data?.project?.id;
    if (typeof projectId !== 'number') {
      return undefined;
    }

    const update: VikunjaUpdateEvent = {
      source: 'webhook',
      eventName: body.event_name ?? 'vikunja.webhook',
      projectId,
      timestamp: body.time ?? new Date().toISOString(),
      raw: payload,
    };

    if (body.data?.task?.id !== undefined) {
      update.taskId = body.data.task.id;
    }
    if (body.data?.doer !== undefined) {
      update.doer = body.data.doer;
    }
    if (body.data?.task !== undefined) {
      update.task = body.data.task;
    }
    if (body.data?.project !== undefined) {
      update.project = body.data.project;
    }

    update.changedFields = this.changedFieldsFromEvent(update.eventName);
    return update;
  }

  private changedFieldsFromEvent(eventName: string): string[] {
    if (eventName.includes('assignee')) {
      return ['assignees'];
    }
    if (eventName.includes('comment')) {
      return ['comments'];
    }
    if (eventName.includes('attachment')) {
      return ['attachments'];
    }
    if (eventName.includes('relation')) {
      return ['relations'];
    }
    if (eventName === 'task.updated') {
      return ['task'];
    }
    return [];
  }

  private async subscriptionStillHasAccess(subscription: UpdateSubscription): Promise<boolean> {
    const now = Date.now();
    if (subscription.lastAccessCheck && now - subscription.lastAccessCheck < 60_000) {
      return true;
    }

    try {
      await this.ensureProjectAccess(subscription.authSession, subscription.projectId);
      subscription.lastAccessCheck = now;
      return true;
    } catch {
      return false;
    }
  }

  private authHeaders(session: AuthSession): Record<string, string> {
    return {
      Authorization: `Bearer ${session.apiToken}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    };
  }

  private subscriptionKey(sessionId: string, projectId: number): string {
    return `${sessionId}:${projectId}`;
  }
}
