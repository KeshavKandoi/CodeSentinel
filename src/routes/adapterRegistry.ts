import { expressAdapter } from './adapters/express.js';
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
