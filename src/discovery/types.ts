
export type Confidence = 'high' | 'medium' | 'low';

export interface Evidence {
  source: string;
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

export type Ecosystem = 'node' | 'python' | 'go' | 'rust' | 'unknown';

export interface ProjectProfile {
  projectName: string | null;
  ecosystem: Ecosystem;
  nestedProjects: string[];
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
  authIndicators: DetectedItem[];
  warnings: string[];
}

export function emptyProjectProfile(): ProjectProfile {
  return {
    projectName: null,
    ecosystem: 'unknown',
    nestedProjects: [],
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
