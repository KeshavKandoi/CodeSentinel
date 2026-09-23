import { expressAdapter } from './adapters/express.js';
import { fastifyAdapter } from './adapters/fastify.js';
import { nestjsAdapter } from './adapters/nestjs.js';
import { nextjsAdapter } from './adapters/nextjs.js';
import { fastapiAdapter } from './adapters/fastapi.js';
import { djangoAdapter } from './adapters/django.js';
import type { FrameworkAdapter, RouteFramework } from './types.js';

/**
 * Adding a framework = write an adapter and register it here. The discovery
 * engine (engine.ts) never needs to change.
 */
const registry = new Map<RouteFramework, FrameworkAdapter>();

export function registerAdapter(adapter: FrameworkAdapter): void {
  registry.set(adapter.id, adapter);
}

export function getAdapters(): FrameworkAdapter[] {
  return Array.from(registry.values());
}

registerAdapter(expressAdapter);
registerAdapter(fastifyAdapter);
registerAdapter(nestjsAdapter);
registerAdapter(nextjsAdapter);
registerAdapter(fastapiAdapter);
registerAdapter(djangoAdapter);
