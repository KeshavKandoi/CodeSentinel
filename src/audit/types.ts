import type { ToolOutcome } from '../types.js';
import type { runProjectDiscovery } from '../discovery/projectDiscovery.js';
import type { DiscoverRoutesResult } from '../routes/types.js';
import type { SecurityScanResult } from '../security/types.js';
import type { AnalyzeAccessControlResult } from '../access/types.js';
import type { ProofCaseType, ProofStatus, SecurityGraph, SecurityGraphEdge, SecurityGraphNode, SecurityReceipt } from '../proof/types.js';
import type { RemediationLifecycle, RemediationRecord } from '../remediation/types.js';
import type { NearDuplicateGroup } from './graph.js';
import type { EnvironmentBlocker } from './environment.js';

export const AUDIT_STAGES = ['discovery', 'route_discovery', 'static_scan', 'access_control', 'deep_analysis', 'candidate_classification', 'runtime_proof', 'graph_construction', 'report'] as const;
export type AuditStage = (typeof AUDIT_STAGES)[number];
export type StageStatus = 'completed' | 'skipped' | 'failed' | 'blocked';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export const FINDING_STATUSES = ['candidate', 'analyzed', 'proof_eligible', 'verified', 'not_reproduced', 'unsupported', 'blocked', 'inconclusive', 'remediation_applied', 'verified_resolved'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export type FindingOrigin = 'security_scan' | 'access_control' | 'deep_analysis' | 'remediation_record';
export type ProofSupportClass = 'runtime' | 'requires-adapter' | 'static-only';
export type ProofClassStatus = 'eligible' | 'unsupported' | 'blocked' | ProofStatus;
export type ReplayStatus = 'not_attempted' | ProofStatus;
export type FinalVerification = 'no_findings' | 'coverage_incomplete' | 'review_signals_only' | 'candidates_unverified' | 'verified_findings_present' | 'all_verified_resolved';

export interface FindingSource {
  stage: AuditStage;
  origin: FindingOrigin;
  sourceId: string;
  ruleId: string | null;
  category: string;
  candidateType: string | null;
  routePath: string | null;
}

export interface ProofClassification {
  proofSupport: ProofSupportClass;
  proofStatus: ProofClassStatus;
  adapter: ProofCaseType | null;
  proofSourceId: string | null;
  prerequisites: string[];
  maxRequests: number;
  reason: string;
}

export interface FindingCorrelation {
  sourceIds: string[];
  reason: string;
  engineCount: number;
}

export interface AuditFinding {
  id: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  file: string | null;
  line: number | null;
  route: string | null;
  routeId: string | null;
  stages: AuditStage[];
  sources: FindingSource[];
  evidence: string[];
  verification?: VerificationAssessment;
  classification: ProofClassification;
  proof: { receiptIds: string[]; status: ProofStatus | null; attempted: boolean; fromPriorReceipt: boolean; note: string | null };
  remediation: { status: RemediationLifecycle | null; remediationIds: string[] };
  replay: { status: ReplayStatus; receiptId: string | null };
  recommendation: string;
  correlation?: FindingCorrelation;
  riskScore?: number;
  evidenceSynthesis?: string;
}

export interface VerificationAssessment {
  findingId: string;
  ruleIds: string[];
  originalSeverity: Severity;
  confidence: Confidence;
  verificationStatus: 'not_verified' | 'verified' | 'not_verifiable' | 'verification_failed';
  proofStatus: ProofClassStatus | null;
  proofMethod: string;
  evidence: string[];
  limitations: string[];
  safetyConstraints: string[];
  receiptIds: string[];
}

export interface AuditIssue {
  stage: AuditStage;
  code: string;
  message: string;
  recoverable: boolean;
  affectedFindings: string[];
}

export interface StageRecord {
  stage: AuditStage;
  status: StageStatus;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  itemCount: number;
  note: string | null;
}

export interface AuditLimitsUsed {
  maxFindings: number;
  maxProofAttempts: number;
  maxElapsedMs: number;
  maxFiles: number;
  maxEvidencePerFinding: number;
}

export interface TreeFingerprint {
  hash: string;
  files: number;
  truncated: boolean;
}

export interface AuditContext {
  runId: string;
  startedAt: string;
  startedMs: number;
  deadlineMs: number;
  limits: AuditLimitsUsed;
  profile: ReturnType<typeof runProjectDiscovery> | null;
  routesOutcome: ToolOutcome<DiscoverRoutesResult> | null;
  scanOutcome: ToolOutcome<SecurityScanResult> | null;
  access: AnalyzeAccessControlResult | null;
  deepCounts: { findings: number; evidence: number } | null;
  domainCoverage?: Array<{ domain: string; status: 'analyzed' | 'unsupported' | 'skipped' | 'failed' | 'not_applicable'; ruleBackedFindings: number; reviewSignals: number; limitation: string | null }>;
  findings: Map<string, AuditFinding>;
  sourceIndex: Map<string, string>;
  receipts: Map<string, SecurityReceipt[]>;
  remediationRecords: RemediationRecord[];
  graph: SecurityGraph | null;
  treeBefore: TreeFingerprint | null;
  treeAfter: TreeFingerprint | null;
  truncatedFindings: number;
  issues: AuditIssue[];
  stages: StageRecord[];
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface AuditSummary {
  total: number;
  reviewSignals: number;
  bySeverity: { critical: number; high: number; medium: number; low: number; informational: number };
  runtimeVerified: number;
  staticOnly: number;
  unsupported: number;
  blocked: number;
  inconclusive: number;
  resolved: number;
  byStatus: NamedCount[];
  byCategory: NamedCount[];
}

export interface AuditGraphSummary {
  built: boolean;
  nodeCount: number;
  edgeCount: number;
  nodeKinds: NamedCount[];
  edgeRelations: NamedCount[];
  limitations: string[];
  nodes?: SecurityGraphNode[];
  edges?: SecurityGraphEdge[];
}

export interface AuditResult {
  schemaVersion: 1;
  auditId: string;
  runId: string;
  readOnly: { enforced: true; sourceTreeUnchanged: boolean | null; filesChecked: number; truncated: boolean };
  securityStatus: 'no_findings' | 'suspected' | 'verified_vulnerability' | 'verified_safe' | 'inconclusive';
  executionStatus: 'completed' | 'partially_completed' | 'blocked' | 'failed' | 'skipped';
  verification: { attempted: boolean; completed: boolean; blocked: boolean; reason: string | null; verifiedVulnerabilities: number; staticCandidatesUnverified: number };
  blocker: EnvironmentBlocker | null;
  targetActivity: { targetModifications: 'none' | 'unknown'; dependenciesInstalled: false; commandsExecutedInsideTarget: false; runtimeStartedByCodeSentinel: false; networkRequestsSent: boolean; databaseAccessed: boolean | null };
  guidance: { checked: string[]; couldNotVerify: string[]; nextSteps: string[] };
  project: { name: string | null; ecosystem: string; root: string };
  execution: { startedAt: string; finishedAt: string; elapsedMs: number; limits: AuditLimitsUsed; findingsTruncated: number };
  stages: StageRecord[];
  summary: AuditSummary;
  findings: AuditFinding[];
  reviewSignals: AuditFinding[];
  domainCoverage: Array<{ domain: string; status: 'analyzed' | 'unsupported' | 'skipped' | 'failed' | 'not_applicable'; ruleBackedFindings: number; reviewSignals: number; limitation: string | null }>;
  nearDuplicates: NearDuplicateGroup[];
  graph: AuditGraphSummary;
  remediation: { investigationId: string | null; records: number; resolved: number };
  finalVerification: FinalVerification;
  report: { reportId: string; generatedAt: string; schemaVersion: 1; summaryNote: string };
  issues: AuditIssue[];
  limitations: string[];
}
