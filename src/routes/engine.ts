import type { AppConfig } from '../config.js';
import { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import { ok, type ToolOutcome } from '../types.js';
import { getAdapters } from './adapterRegistry.js';
import { createAdapterContext } from './sourceIndex.js';
import type { AttackSurfaceEntry, DiscoverRoutesResult, Exposure } from './types.js';

/**
 * Phase 4 entry point. Static only: never starts the app or sends requests.
 * Runs every adapter whose appliesTo() matches the Phase 2 ProjectProfile.
 */
export function discoverRoutes(config: AppConfig): ToolOutcome<DiscoverRoutesResult> {
  const warnings: string[] = [];
  const profile = runProjectDiscovery(config.projectRoot);
  warnings.push(...profile.warnings);

  const ctx = createAdapterContext(config, profile, warnings);
  const collected: AttackSurfaceEntry[] = [];
  const frameworks: DiscoverRoutesResult['frameworks'] = [];

  for (const adapter of getAdapters()) {
    let applicable = false;
    try {
      applicable = adapter.appliesTo(ctx);
    } catch (e) {
      warnings.push(`Adapter ${adapter.id} appliesTo() failed: ${(e as Error).message}`);
    }
    if (!applicable) {
      frameworks.push({ framework: adapter.id, applicable: false, routeCount: 0 });
      continue;
    }
    try {
      const found = adapter.discover(ctx);
      collected.push(...found);
      frameworks.push({ framework: adapter.id, applicable: true, routeCount: found.length });
    } catch (e) {
      warnings.push(`Adapter ${adapter.id} failed: ${(e as Error).message}`);
      frameworks.push({ framework: adapter.id, applicable: true, routeCount: 0 });
    }
  }

  // Exact duplicates (same id) are removed; different definitions of the same route are reported.
  const seenIds = new Set<string>();
  const entries: AttackSurfaceEntry[] = [];
  for (const entry of collected) {
    if (seenIds.has(entry.id)) continue;
    seenIds.add(entry.id);
    entries.push(entry);
  }
  entries.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.method.localeCompare(b.method) || a.path.localeCompare(b.path)
  );

  const byKey = new Map<string, string[]>();
  for (const entry of entries) {
    if (!entry.pathResolved || entry.method === 'unknown') continue;
    const key = `${entry.method} ${entry.path}`;
    const where = byKey.get(key) ?? [];
    where.push(`${entry.file}:${entry.line}`);
    byKey.set(key, where);
  }
  for (const [key, where] of byKey) {
    if (where.length > 1) warnings.push(`Duplicate route definition: ${key} is declared at ${where.join(', ')}.`);
  }

  if (!frameworks.some((f) => f.applicable)) {
    warnings.push('No supported web framework was detected, so no routes were discovered.');
  }

  const byMethod: Record<string, number> = {};
  const byFramework: Record<string, number> = {};
  const byExposure: Record<Exposure, number> = { public: 0, protected: 0, unknown: 0 };
  for (const entry of entries) {
    byMethod[entry.method] = (byMethod[entry.method] ?? 0) + 1;
    byFramework[entry.framework] = (byFramework[entry.framework] ?? 0) + 1;
    byExposure[entry.publicOrProtected] += 1;
  }

  return ok({
    project: { name: profile.projectName, ecosystem: profile.ecosystem },
    frameworks,
    summary: { total: entries.length, byMethod, byFramework, byExposure },
    entries,
    warnings: Array.from(new Set(warnings)),
  });
}
