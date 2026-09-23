/**
 * Normalized, evidence-backed description of a project, produced by the
 * Phase 2 discovery module. Every detected technology carries the
 * confidence level and the concrete evidence that led to it, rather than
 * being asserted as a bare fact — callers (including an LLM consuming this
 * JSON) can see exactly why something was detected and how sure we are.
 */

export type Confidence = 'high' | 'medium' | 'low';

export interface Evidence {
  /** Where this evidence came from, e.g. "package.json dependencies", "file:next.config.js", "content-match". */
  source: string;
  /** Human-readable detail of what was found. */
  detail: string;
}

export interface DetectedItem {
  name: string;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface EntryPoint {
  path: string;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface DependencyInfo {
  name: string;
  version: string;
  dev: boolean;
}

export interface DockerInfo {
  hasDockerfile: boolean;
  hasCompose: boolean;
  files: string[];
  evidence: Evidence[];
}

/** The broad technology ecosystem the project belongs to. Node is fully
 * implemented in Phase 2; Python is recognized but deferred (see
 * projectDiscovery.ts) so it can be added later without restructuring. */
export type Ecosystem = 'node' | 'python' | 'unknown';

export interface ProjectProfile {
  projectName: string | null;
  ecosystem: Ecosystem;
  languages: DetectedItem[];
  packageManager: DetectedItem | null;
  frameworks: {
    frontend: DetectedItem[];
    backend: DetectedItem[];
  };
  database: DetectedItem[];
  orm: DetectedItem[];
  testFramework: DetectedItem[];
  entryPoints: EntryPoint[];
  scripts: Record<string, string>;
  dependencies: DependencyInfo[];
  docker: DockerInfo;
  configFiles: string[];
  envFiles: string[];
  /** Authentication-related dependencies detected (e.g. jsonwebtoken,
   * passport, next-auth). Presence only — no vulnerability analysis. */
  authIndicators: DetectedItem[];
  /** Non-fatal issues encountered during discovery (e.g. malformed
   * package.json). Discovery never throws; problems surface here instead. */
  warnings: string[];
}

export function emptyProjectProfile(): ProjectProfile {
  return {
    projectName: null,
    ecosystem: 'unknown',
    languages: [],
    packageManager: null,
    frameworks: { frontend: [], backend: [] },
    database: [],
    orm: [],
    testFramework: [],
    entryPoints: [],
    scripts: {},
    dependencies: [],
    docker: { hasDockerfile: false, hasCompose: false, files: [], evidence: [] },
    configFiles: [],
    envFiles: [],
    authIndicators: [],
    warnings: [],
  };
}
