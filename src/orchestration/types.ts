import type { InvestigationScope } from '../investigation/types.js';

export const AUDIT_STATUSES = ['created', 'planning', 'investigating', 'awaiting_verification', 'completed', 'blocked', 'failed'] as const;
export type AuditStatus = (typeof AUDIT_STATUSES)[number];

export const AUDIT_FOCUSES = ['general', 'authentication', 'authorization', 'api_security', 'input_validation', 'secrets', 'route', 'finding'] as const;
export type AuditFocus = (typeof AUDIT_FOCUSES)[number];

export type AuditToolName =
  | 'start_security_audit'
  | 'plan_security_investigation'
  | 'run_audit_analysis'
  | 'record_audit_hypothesis'
  | 'request_audit_verification'
  | 'complete_security_audit'
  | 'generate_security_audit_report';

export interface AuditLimits {
  maxSteps: number;
  maxHypotheses: number;
  maxEvidenceRefs: number;
  maxVerificationRequests: number;
  maxOutputBytes: number;
  maxElapsedMs: number;
}

export interface AuditObjective {
  text: string;
  focus: AuditFocus;
  target: string | null;
  scopes: InvestigationScope[];
  notice: string;
}

/** Recorded only by the orchestrator when it executes a real capability. Never created from external input. */
export interface AuditStep {
  id: string;
  sequence: number;
  tool: AuditToolName;
  status: 'completed' | 'blocked' | 'failed';
  startedAt: string;
  finishedAt: string;
  summary: string;
  investigationStepIds: string[];
  evidenceCount: number;
  objectIds: string[];
}

export type AuditHypothesisStatus = 'proposed' | 'linked' | 'verified' | 'not_reproduced' | 'inconclusive' | 'blocked';

/** A hypothesis is a claim to investigate. It is never evidence and never a confirmed finding. */
export interface AuditHypothesis {
  kind: 'hypothesis';
  isEvidence: false;
  id: string;
  category: string;
  description: string;
  affectedLocation: string;
  reason: string;
  findingId: string | null;
  investigationHypothesisId: string | null;
  evidenceRefs: string[];
  status: AuditHypothesisStatus;
  createdAt: string;
}

export interface BlockedOperation {
  id: string;
  tool: AuditToolName;
  code: string;
  reason: string;
  at: string;
}

export interface AuditSession {
  investigationId: string;
  objective: AuditObjective;
  status: AuditStatus;
  currentStep: string;
  createdAt: string;
  updatedAt: string;
  limits: AuditLimits;
  hypotheses: AuditHypothesis[];
  steps: AuditStep[];
  blockedOperations: BlockedOperation[];
  errors: string[];
  completedCapabilities: AuditToolName[];
  verificationAttempts: number;
}

export interface CapabilityPlanEntry {
  tool: string;
  kind: 'orchestrated' | 'read_only_inspection' | 'controlled_remediation';
  purpose: string;
  required: boolean;
  status: 'available' | 'completed' | 'unavailable';
  unavailableReason: string | null;
}

export interface CapabilityPlan {
  investigationId: string;
  status: AuditStatus;
  objective: AuditObjective;
  relevantFindingCategories: string[];
  capabilities: CapabilityPlanEntry[];
  notice: string;
}

export interface FindingTrace {
  findingId: string;
  auditHypothesisId: string | null;
  investigationHypothesisId: string | null;
  evidence: Array<{ id: string; kind: string; reference: string }>;
  investigationStepIds: string[];
  auditStepIds: string[];
  traceable: boolean;
}

export interface AuditStateSummary {
  investigationId: string;
  objective: AuditObjective;
  status: AuditStatus;
  currentStep: string;
  complete: boolean;
  createdAt: string;
  updatedAt: string;
  limits: AuditLimits;
  usage: { steps: number; hypotheses: number; verificationRequests: number };
  totals: { steps: number; hypotheses: number; findings: number; evidenceRefs: number; verificationResults: number; blockedOperations: number };
  availableCapabilities: CapabilityPlanEntry[];
  completedCapabilities: AuditToolName[];
  remainingWork: string[];
  steps: AuditStep[];
  hypotheses: AuditHypothesis[];
  evidenceRefs: { total: number; truncated: boolean; listed: Array<{ id: string; kind: string; reference: string; summary: string }> };
  findings: Array<{ findingId: string; origin: string; title: string; category: string; candidateType: string; severity: string; confidence: string; lifecycle: string; runtimeVerificationStatus: string; path: string; file: string }>;
  verificationResults: Array<{ auditHypothesisId: string; investigationHypothesisId: string; status: string; confidence: string; summary: string; requestsIssued: number; blockedReason: string | null; evidenceRef: string }>;
  blockedOperations: BlockedOperation[];
  errors: string[];
  outputTruncated: boolean;
}
