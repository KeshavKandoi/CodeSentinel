import type { InvestigationRuntimeResult, SecurityInvestigation } from '../investigation/types.js';

export type ReportFindingStatus = 'static_candidate' | 'runtime_verified' | 'not_reproduced' | 'inconclusive' | 'blocked';

export interface RemediationRecommendation {
  findingId: string;
  location: string;
  recommendedChange: string;
  reason: string;
  securityPrinciple: string;
  reverifyAfterRemediation: boolean;
}

export interface SecurityReportFinding {
  findingId: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  status: ReportFindingStatus;
  affectedRoute: string;
  affectedFile: string;
  description: string;
  technicalEvidence: string[];
  staticAnalysisEvidence: string[];
  runtimeEvidence: string[];
  reproductionSummary: string;
  impact: string;
  remediation: RemediationRecommendation;
  evidenceRefs: string[];
  sourceRefs: string[];
  hypothesisId: string | null;
  runtimeResult: InvestigationRuntimeResult | null;
}

export interface SecurityReport {
  reportId: string;
  investigationId: string;
  project: { pathSummary: string; name: string | null; ecosystem: string };
  generatedAt: string;
  investigationStatus: SecurityInvestigation['status'];
  complete: boolean;
  executiveSummary: string;
  findings: SecurityReportFinding[];
  verifiedFindings: string[];
  unverifiedStaticFindings: string[];
  inconclusiveFindings: string[];
  blockedVerificationCases: string[];
  remediationRecommendations: RemediationRecommendation[];
  evidenceSummary: { totalItems: number; evidenceBytes: number; referencedItems: number };
  analysisCoverage: { analysisSteps: number; expectedAnalysisSteps: number; scanFindings: number; routes: number; accessControlFindings: number };
  runtimeVerificationSummary: { attempted: number; verified: number; notReproduced: number; inconclusive: number; blocked: number };
  limitations: string[];
}
