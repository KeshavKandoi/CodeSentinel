import type { Confidence, Ecosystem, Evidence } from '../discovery/types.js';
import type { HttpMethod, RouteFramework, SourceRange } from '../routes/types.js';
import type { SecurityFinding, SecuritySeverity } from '../security/types.js';

export type ProtectionScope = 'global' | 'router' | 'controller' | 'middleware' | 'dependency' | 'decorator' | 'handler';

export type AuthMechanism =
  | 'jwt'
  | 'session'
  | 'cookie'
  | 'bearer'
  | 'api_key'
  | 'oauth'
  | 'oidc'
  | 'passport'
  | 'basic'
  | 'guard'
  | 'framework'
  | 'generic';

export type AuthorizationKind = 'role' | 'permission' | 'admin_flag' | 'policy' | 'scope' | 'ownership' | 'tenant';

export type AccessState =
  | 'public'
  | 'authenticated'
  | 'role_protected'
  | 'permission_protected'
  | 'ownership_protected'
  | 'mixed'
  | 'unknown';

export type IdentityKind = 'framework_user' | 'request_user' | 'session' | 'token_claims' | 'dependency' | 'decorator_param';

export type OwnershipKind = 'owner_comparison' | 'scoped_query' | 'tenant_comparison' | 'policy_call';

export type ResourceOperation = 'read' | 'write' | 'delete' | 'unknown';

export type FindingCandidateType =
  | 'missing_authentication'
  | 'missing_authorization'
  | 'idor_candidate'
  | 'user_resource_access'
  | 'inconsistent_authorization';

export interface GuardAssessment {
  resolved: boolean;
  enforces: boolean | null;
  file: string | null;
  line: number | null;
}

export interface IdentitySource {
  kind: IdentityKind;
  name: string;
  expression: string;
  file: string;
  line: number;
  scope: ProtectionScope;
}

export interface AuthControl {
  id: string;
  mechanism: AuthMechanism;
  name: string;
  scope: ProtectionScope;
  inherited: boolean;
  file: string;
  line: number;
  confidence: Confidence;
  assessment: GuardAssessment | null;
  evidence: Evidence[];
}

export interface AuthorizationControl {
  id: string;
  kind: AuthorizationKind;
  name: string;
  requirement: string | null;
  scope: ProtectionScope;
  inherited: boolean;
  file: string;
  line: number;
  confidence: Confidence;
  assessment: GuardAssessment | null;
  evidence: Evidence[];
}

export interface ResourceLoad {
  parameter: string;
  expression: string;
  operation: ResourceOperation;
  file: string;
  line: number;
}

export interface ResourceOwnershipCheck {
  kind: OwnershipKind;
  parameter: string;
  identity: string;
  expression: string;
  file: string;
  line: number;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface AccessControlEntry {
  routeId: string;
  method: HttpMethod;
  path: string;
  pathResolved: boolean;
  framework: RouteFramework;
  file: string;
  line: number;
  sourceRange: SourceRange;
  state: AccessState;
  explicitlyPublic: boolean;
  administrative: boolean;
  stateChanging: boolean;
  authentication: AuthControl[];
  authorization: AuthorizationControl[];
  ownership: ResourceOwnershipCheck[];
  identitySources: IdentitySource[];
  resourceParameters: string[];
  resourceLoads: ResourceLoad[];
  confidence: Confidence;
  evidence: Evidence[];
}

export interface AccessControlFinding extends SecurityFinding {
  category: 'authentication' | 'authorization';
  status: 'suspected';
  routeId: string;
  method: HttpMethod;
  path: string;
  framework: RouteFramework;
  file: string;
  line: number;
  sourceRange: SourceRange;
  candidateType: FindingCandidateType;
  explanation: string;
}

export interface AccessRuleMetadata {
  id: string;
  title: string;
  category: 'authentication' | 'authorization';
  severity: SecuritySeverity;
  confidence: Confidence;
  candidateType: FindingCandidateType;
  description: string;
  remediation: string;
  falsePositiveGuidance: string;
}

export interface AccessControlSummary {
  totalRoutes: number;
  byState: Record<AccessState, number>;
  totalFindings: number;
  findingsBySeverity: Record<SecuritySeverity, number>;
  findingsByRule: Record<string, number>;
}

export interface AnalyzeAccessControlResult {
  project: { name: string | null; ecosystem: Ecosystem };
  frameworks: RouteFramework[];
  summary: AccessControlSummary;
  matrix: AccessControlEntry[];
  findings: AccessControlFinding[];
  warnings: string[];
}
