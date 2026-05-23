import { AsyncLocalStorage } from 'node:async_hooks';
import type { AuthSession } from '../types';

export interface ContextForgeIdentity {
  id: string;
  email?: string;
  fullName?: string;
  groups: string[];
  teams: string[];
  roles: string[];
  isAdmin: boolean;
  authMethod?: string;
}

export interface RequestContext {
  identity?: ContextForgeIdentity;
  authSession?: AuthSession;
}

const requestContext = new AsyncLocalStorage<RequestContext>();

export function runWithRequestContext<T>(context: RequestContext, callback: () => T): T {
  return requestContext.run(context, callback);
}

export function getRequestContext(): RequestContext | undefined {
  return requestContext.getStore();
}

export function hasRequestContext(): boolean {
  return requestContext.getStore() !== undefined;
}

export function getRequestAuthSession(): AuthSession | undefined {
  return requestContext.getStore()?.authSession;
}

export function getRequestIdentity(): ContextForgeIdentity | undefined {
  return requestContext.getStore()?.identity;
}
