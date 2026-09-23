import { createHash } from 'node:crypto';
import type { Confidence, Evidence } from '../discovery/types.js';
import { classifyGuards } from './authHeuristics.js';
import type {
  AttackSurfaceEntry,
  Exposure,
  HttpMethod,
  RouteFramework,
  RouteLanguage,
  RouteParameter,
} from './types.js';

export function unique<T>(items: readonly T[]): T[] {
  return Array.from(new Set(items));
}

export function languageForFile(file: string): RouteLanguage {
  if (file.endsWith('.py')) return 'python';
  return /\.(ts|tsx|mts|cts)$/.test(file) ? 'typescript' : 'javascript';
}

export function routeId(framework: RouteFramework, method: HttpMethod, routePath: string, file: string, line: number): string {
  const hash = createHash('sha256').update(`${framework}|${method}|${routePath}|${file}|${line}`).digest('hex').slice(0, 12);
  return `RT-${framework.toUpperCase()}-${hash}`;
}

export interface EntryInput {
  framework: RouteFramework;
  method: HttpMethod;
  path: string;
  pathResolved: boolean;
  file: string;
  line: number;
  endLine: number;
  handler: string;
  controller: string;
  router: string;
  middleware: string[];
  dependencies: string[];
  parameters: RouteParameter[];
  queryParameters: RouteParameter[];
  bodyParameters: RouteParameter[];
  extraAuth: string[];
  extraAuthz: string[];
  uploadIndicators: string[];
  responseIndicators: string[];
  confidence: Confidence;
  evidence: Evidence[];
}

/** Single place where guards are classified and public/protected is decided, so every adapter behaves the same. */
export function buildEntry(input: EntryInput): AttackSurfaceEntry {
  const guards = classifyGuards([...input.middleware, ...input.dependencies]);
  const authIndicators = unique([...guards.authentication, ...input.extraAuth]);
  const authorizationIndicators = unique([...guards.authorization, ...input.extraAuthz]);

  let exposure: Exposure;
  if (authIndicators.length > 0 || authorizationIndicators.length > 0) exposure = 'protected';
  else if (!input.pathResolved) exposure = 'unknown';
  else exposure = 'public';

  const evidence: Evidence[] = [...input.evidence];
  for (const a of authIndicators) {
    evidence.push({ source: 'heuristic:authentication', detail: `Authentication indicator "${a}" matched by name/pattern.` });
  }
  for (const a of authorizationIndicators) {
    evidence.push({ source: 'heuristic:authorization', detail: `Authorization indicator "${a}" matched by name/pattern.` });
  }
  if (exposure === 'public') {
    evidence.push({
      source: 'heuristic:exposure',
      detail:
        'No authentication or authorization indicator found in route middleware/dependencies, inherited middleware, or analyzable handler code. Absence of indicators does not prove the route is unauthenticated (auth may be enforced elsewhere).',
    });
  }

  return {
    id: routeId(input.framework, input.method, input.path, input.file, input.line),
    method: input.method,
    path: input.path,
    pathResolved: input.pathResolved,
    framework: input.framework,
    language: languageForFile(input.file),
    file: input.file,
    line: input.line,
    sourceRange: { startLine: input.line, endLine: Math.max(input.line, input.endLine) },
    handler: input.handler === '' ? 'unknown' : input.handler,
    controller: input.controller === '' ? 'unknown' : input.controller,
    router: input.router === '' ? 'unknown' : input.router,
    middleware: unique(input.middleware),
    dependencies: unique(input.dependencies),
    parameters: input.parameters,
    queryParameters: input.queryParameters,
    bodyParameters: input.bodyParameters,
    authIndicators,
    authorizationIndicators,
    uploadIndicators: unique(input.uploadIndicators),
    responseIndicators: unique(input.responseIndicators),
    publicOrProtected: exposure,
    confidence: input.confidence,
    evidence,
  };
}
