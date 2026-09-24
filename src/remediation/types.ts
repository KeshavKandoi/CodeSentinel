import type { VerifyFindingInput } from '../validation/schemas.js';

export type RemediationLifecycle =
  | 'proposed' | 'validated' | 'applied_pending_verification' | 'verifying'
  | 'verified_resolved' | 'still_vulnerable' | 'changed_finding'
  | 'verification_inconclusive' | 'verification_blocked' | 'rejected'
  | 'apply_failed' | 'rollback_required' | 'rolled_back';

export interface RemediationFileChange {
  path: string;
  originalContentHash: string;
  proposedContent: string;
  description: string;
}

export interface RemediationProposal {
  proposalId: string;
  investigationId: string;
  findingId: string;
  description: string;
  rationale: string;
  files: RemediationFileChange[];
  expectedSecurityEffect: string;
  requiresRuntimeVerification: boolean;
  runtimeVerification?: VerifyFindingInput;
  createdAt: string;
}

export interface RemediationSnapshot {
  path: string;
  originalContentHash: string;
  originalContent: string;
  capturedAt: string;
}

export interface RemediationVerification {
  status: RemediationLifecycle;
  beforeFindingId: string;
  afterInvestigationId: string | null;
  staticFindingPresent: boolean;
  relatedFindings: Array<{ findingId: string; title: string; category: string; path: string; file: string }>;
  runtimeStatus: string | null;
  summary: string;
  verifiedAt: string;
}

export interface RemediationRecord {
  proposal: RemediationProposal;
  status: RemediationLifecycle;
  snapshots: RemediationSnapshot[];
  appliedContentHashes: Record<string, string>;
  verification: RemediationVerification | null;
  updatedAt: string;
}

