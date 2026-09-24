import type { AccessControlFinding } from '../access/types.js';
import type { AttackSurfaceEntry } from '../routes/types.js';
import type { SecurityFinding } from '../security/types.js';
import type { VerificationResult, VerificationStatus } from '../runtime/types.js';

export const INVESTIGATION_SCOPES = [
  'authentication',
  'authorization',
  'idor_bola',
  'input_validation',
  'secrets_exposure',
  'route_security',
  'general_application_security',
] as const;

export type InvestigationScope = (typeof INVESTIGATION_SCOPES)[number];
export type InvestigationStatus = 'created' | 'running' | 'awaiting_verification' | 'completed' | 'blocked' | 'failed';
export type InvestigationFindingLifecycle = 'static_candidate' | 'investigated' | 'runtime_verified' | 'not_reproduced' | 'inconclusive' | 'blocked' | 'ready_for_report';

export interface InvestigationBudget {
  maxAnalysisSteps: number;
  maxHypotheses: number;
  maxRuntimeVerifications: number;
  maxElapsedMs: number;
  maxEvidenceBytes: number;
}

export interface InvestigationStep {
  id: string;
  operation: 'project_discovery' | 'static_analysis' | 'route_discovery' | 'access_control_analysis' | 'hypothesis' | 'runtime_verification';
  status: 'completed' | 'blocked' | 'failed';
  startedAt: string;
  finishedAt: string;
  summary: string;
  evidenceRefs: string[];
}

export interface InvestigationEvidence {
  id: string;
  kind: 'project' | 'security_finding' | 'access_finding' | 'route' | 'step' | 'runtime_verification';
  reference: string;
  summary: string;
  capturedAt: string;
}

export interface SecurityHypothesis {
  id: string;
  title: string;
  description: string;
  findingId: string | null;
  evidenceRefs: string[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  confidence: 'high' | 'medium' | 'low' | null;
  status: 'open' | 'verified' | 'not_reproduced' | 'inconclusive' | 'blocked';
  createdAt: string;
}

export interface InvestigationFinding {
  findingId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  lifecycle: InvestigationFindingLifecycle;
  runtimeVerificationStatus: string;
}

export interface InvestigationAnalysisSummary {
  project: { name: string | null; ecosystem: string };
  scan: { total: number; findingIds: string[]; warningCount: number };
  routes: { total: number; routeIds: string[]; warningCount: number };
  accessControl: { totalRoutes: number; totalFindings: number; findingIds: string[]; warningCount: number };
}

export interface InvestigationRuntimeResult {
  status: VerificationStatus;
  confidence: 'high' | 'medium' | 'low';
  summary: string;
  requestsIssued: number;
  blockedReason: string | null;
  evidenceRef: string;
}

export interface SecurityInvestigation {
  id: string;
  projectPath: string;
  scope: InvestigationScope[];
  status: InvestigationStatus;
  hypothesis: string;
  steps: InvestigationStep[];
  evidence: InvestigationEvidence[];
  hypotheses: SecurityHypothesis[];
  findings: InvestigationFinding[];
  runtimeResults: Record<string, InvestigationRuntimeResult>;
  analysis: InvestigationAnalysisSummary | null;
  budget: InvestigationBudget;
  execution: { analysisSteps: number; runtimeVerifications: number; evidenceBytes: number; operations: string[] };
  createdAt: string;
  updatedAt: string;
}

export interface InvestigationInternals {
  investigation: SecurityInvestigation;
  accessFindings: AccessControlFinding[];
  routes: AttackSurfaceEntry[];
  securityFindings: SecurityFinding[];
  runtimeResults: Map<string, VerificationResult>;
}
