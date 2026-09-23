import type { AppConfig } from '../config.js';
import type { Confidence, Ecosystem, Evidence, ProjectProfile } from '../discovery/types.js';

export type RouteFramework = 'express' | 'fastify' | 'nestjs' | 'nextjs' | 'fastapi' | 'django';
export type RouteLanguage = 'javascript' | 'typescript' | 'python';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'ALL' | 'unknown';
export type Exposure = 'public' | 'protected' | 'unknown';

export interface SourceRange {
  startLine: number;
  endLine: number;
}

export interface RouteParameter {
  name: string;
  type: string; // 'unknown' when it cannot be determined statically
  required: boolean | 'unknown';
}

/**
 * One externally reachable endpoint. Any value that cannot be determined
 * statically is the literal string 'unknown' (or an empty list) rather than
 * a guess. `evidence` explains exactly why the entry was discovered.
 */
export interface AttackSurfaceEntry {
  id: string;
  method: HttpMethod;
  path: string; // 'unknown' when not statically resolvable
  pathResolved: boolean; // false when a prefix or the path itself is unresolved
  framework: RouteFramework;
  language: RouteLanguage;
  file: string;
  line: number;
  sourceRange: SourceRange;
  handler: string;
  controller: string;
  router: string;
  middleware: string[];
  dependencies: string[];
  parameters: RouteParameter[]; // path parameters
  queryParameters: RouteParameter[];
  bodyParameters: RouteParameter[];
  authIndicators: string[];
  authorizationIndicators: string[];
  uploadIndicators: string[];
  responseIndicators: string[];
  publicOrProtected: Exposure;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface SourceFile {
  path: string;
  content: string;
}

export interface AdapterContext {
  config: AppConfig;
  profile: ProjectProfile;
  warnings: string[];
  /** Sandboxed, ignore-aware listing of source files with one of the extensions. */
  listSourceFiles(extensions: readonly string[]): string[];
  /** Sandboxed, cached, never-throwing read. Null when unreadable or truncated. */
  readSource(path: string): SourceFile | null;
}

export interface FrameworkAdapter {
  readonly id: RouteFramework;
  readonly ecosystems: readonly Ecosystem[];
  appliesTo(ctx: AdapterContext): boolean;
  discover(ctx: AdapterContext): AttackSurfaceEntry[];
}

export interface DiscoverRoutesResult {
  project: { name: string | null; ecosystem: Ecosystem };
  frameworks: Array<{ framework: RouteFramework; applicable: boolean; routeCount: number }>;
  summary: {
    total: number;
    byMethod: Record<string, number>;
    byFramework: Record<string, number>;
    byExposure: Record<Exposure, number>;
  };
  entries: AttackSurfaceEntry[];
  warnings: string[];
}
