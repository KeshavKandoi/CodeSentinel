export const SECURITY_DOMAINS = [
  'authentication', 'authorization', 'idor_bola', 'injection', 'command_execution',
  'path_traversal', 'ssrf', 'xss', 'csrf', 'file_upload', 'deserialization',
  'prototype_pollution', 'insecure_redirects', 'cors', 'security_headers',
  'session_cookies', 'jwt', 'cryptography', 'secrets', 'environment_configuration',
  'dependency_supply_chain', 'npm_scripts', 'docker', 'ci_cd', 'infrastructure',
  'database', 'api_security', 'websocket', 'graphql', 'ai_mcp',
] as const;
export type SecurityDomain = (typeof SECURITY_DOMAINS)[number];
export type DomainStatus = 'passed' | 'findings' | 'not_applicable' | 'unsupported' | 'skipped' | 'blocked' | 'inconclusive';

export interface RepositoryIndexFile {
  path: string;
  sizeBytes: number;
  contentHash: string;
  language: string;
  analyzed: boolean;
}

export interface RepositoryIndex {
  files: RepositoryIndexFile[];
  symbols: number;
  imports: number;
  exports: number;
  routes: number;
  middleware: number;
  databaseOperations: number;
  externalCalls: number;
  commandSinks: number;
  filesystemSinks: number;
  authenticationGuards: number;
  authorizationChecks: number;
  secretSignals: number;
  packageDependencies: number;
  ciWorkflows: number;
  dockerFiles: number;
  filesSkipped: number;
  coverageLimitations: string[];
}

export interface IntelligenceEvidence {
  id: string;
  domain: SecurityDomain;
  kind: 'source' | 'route' | 'access_control' | 'static_scan' | 'index' | 'baseline';
  sourceRef: string;
  file: string;
  line: number | null;
  detail: string;
  contentHash: string;
}

export interface IntelligenceFinding {
  id: string;
  title: string;
  domain: SecurityDomain;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  status: 'static_candidate' | 'runtime_verified' | 'not_reproduced' | 'inconclusive' | 'blocked';
  description: string;
  evidenceIds: string[];
  sourceRefs: string[];
  signals: string[];
  convergence: number;
  remediation: string;
}

export interface DomainCoverage {
  domain: SecurityDomain;
  status: DomainStatus;
  findings: number;
  filesConsidered: number;
  rulesExecuted: number;
  limitation: string | null;
}

export interface BaselineComparison {
  supplied: boolean;
  newFindings: string[];
  resolvedFindings: string[];
  unchangedFindings: string[];
  changedEvidence: string[];
  limitation: string | null;
}

export interface DeepSecurityAuditResult {
  auditId: string;
  project: { name: string | null; ecosystem: string; root: string };
  repositoryIndex: RepositoryIndex;
  domainCoverage: DomainCoverage[];
  findings: IntelligenceFinding[];
  evidence: IntelligenceEvidence[];
  baseline: BaselineComparison;
  coverage: {
    filesAnalyzed: number;
    filesSkipped: number;
    routesDiscovered: number;
    accessFindings: number;
    staticFindings: number;
    runtimeChecksAttempted: number;
    runtimeChecksBlocked: number;
    runtimeChecksInconclusive: number;
    evidenceItems: number;
  };
  limitations: string[];
  integrity: { valid: boolean; checkedFindings: number; invalidReferences: string[]; redactionPassed: boolean };
  markdown: string;
}
