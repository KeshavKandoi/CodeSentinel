import type { VerifyFindingInput } from '../validation/schemas.js';

export type RemediationLifecycle =
  | 'proposed' | 'validated' | 'preparing' | 'prepared' | 'committing'
  | 'applied_pending_verification' | 'verifying'
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
  remediationType: string;
  findingFile: string;
  findingRoute: string;
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
  runtimeReceiptId: string | null;
  replayResult: ReplayResult;
  summary: string;
  verifiedAt: string;
}

export type ReplayResult = 'resolved' | 'still_present' | 'inconclusive' | 'blocked';

export interface RemediationIntegrity {
  expectedSourceFingerprint: string;
  resultingFingerprint: string;
  treeFingerprintBefore: string;
  treeFingerprintAfter: string;
  changedFiles: string[];
  unchangedTargetFiles: string[];
  unchangedFileCount: number;
  truncated: boolean;
}

export interface RemediationRecord {
  proposal: RemediationProposal;
  status: RemediationLifecycle;
  appliedAt: string | null;
  integrity: RemediationIntegrity | null;
  changeSummary: string;
  snapshots: RemediationSnapshot[];
  appliedContentHashes: Record<string, string>;
  verification: RemediationVerification | null;
  updatedAt: string;
}
