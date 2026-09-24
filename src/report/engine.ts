import type { InvestigationEvidence, InvestigationFinding, InvestigationRuntimeResult, SecurityInvestigation } from '../investigation/types.js';
import { getInvestigation } from '../investigation/orchestrator.js';
import { err, ok, type ToolOutcome } from '../types.js';
import { detachedRedacted } from './redaction.js';
import type { RemediationRecommendation, SecurityReport, SecurityReportFinding, ReportFindingStatus } from './types.js';
import { listRemediationsForInvestigation } from '../remediation/engine.js';
import { listSecurityReceiptsForFinding } from '../proof/engine.js';

const SEVERITY_ORDER: Record<SecurityReportFinding['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_ORDER: Record<ReportFindingStatus, number> = { runtime_verified: 0, static_candidate: 1, inconclusive: 2, blocked: 3, not_reproduced: 4 };
const MAX_REPORT_FINDINGS = 100;
const MAX_EVIDENCE_ITEMS = 250;

function statusFor(finding: InvestigationFinding, runtime: InvestigationRuntimeResult | null): ReportFindingStatus {
  if (!runtime) return 'static_candidate';
  if (runtime.status === 'verified') return 'runtime_verified';
  if (runtime.status === 'not_reproduced') return 'not_reproduced';
  if (runtime.status === 'inconclusive') return 'inconclusive';
  return 'blocked';
}

function impactFor(finding: InvestigationFinding): string {
  if (finding.candidateType === 'missing_authentication') return 'An unauthenticated caller may reach a route that static analysis identifies as sensitive or administrative.';
  if (finding.candidateType === 'missing_authorization') return 'An authenticated caller without the required privilege may perform an administrative operation.';
  if (finding.candidateType === 'idor_candidate' || finding.candidateType === 'user_resource_access') return 'A caller may access or modify another user\'s resource if ownership enforcement is absent.';
  if (finding.candidateType === 'inconsistent_authorization') return 'Inconsistent protection across methods may expose a resource operation through a weaker sibling method.';
  return 'The affected route or component may expose a security-sensitive behavior identified by deterministic analysis.';
}

function remediationFor(finding: InvestigationFinding): RemediationRecommendation {
  if (finding.origin === 'security_scan' && /secret|credential|configuration_secret/i.test(finding.category)) return { findingId: finding.findingId, location: finding.file, recommendedChange: 'Remove the secret from source/configuration and rotate the affected credential.', reason: 'Static scanning identified a credential-like value or secret exposure.', securityPrinciple: 'Keep secrets out of source and rotate exposed credentials.', reverifyAfterRemediation: true };
  if (finding.origin === 'security_scan' && /injection|xss|path_traversal|ssrf/i.test(finding.category)) return { findingId: finding.findingId, location: finding.file, recommendedChange: 'Validate and constrain untrusted input at the application boundary and use the framework-safe operation for the sink.', reason: 'Static scanning identified an unsafe input-to-sink pattern.', securityPrinciple: 'Treat external input as untrusted and enforce contextual validation.', reverifyAfterRemediation: true };
  if (finding.candidateType === 'missing_authentication') return { findingId: finding.findingId, location: `${finding.file}:${finding.path}`, recommendedChange: 'Require authentication middleware or a framework guard before the protected route handler.', reason: 'Static analysis found a sensitive route without a visible authentication control.', securityPrinciple: 'Authenticate before authorization and protected resource access.', reverifyAfterRemediation: true };
  if (finding.candidateType === 'missing_authorization' || finding.candidateType === 'inconsistent_authorization') return { findingId: finding.findingId, location: `${finding.file}:${finding.path}`, recommendedChange: 'Apply the required role, permission, or policy check consistently to this operation.', reason: 'Static analysis found a privileged operation without consistent authorization enforcement.', securityPrinciple: 'Enforce least privilege and deny by default.', reverifyAfterRemediation: true };
  if (finding.candidateType === 'idor_candidate' || finding.candidateType === 'user_resource_access') return { findingId: finding.findingId, location: `${finding.file}:${finding.path}`, recommendedChange: 'Load the resource through an owner- or tenant-scoped query and enforce the caller relationship before access or mutation.', reason: 'A caller-controlled resource identifier lacks a visible ownership or tenant check.', securityPrinciple: 'Enforce object-level authorization at every resource boundary.', reverifyAfterRemediation: true };
  return { findingId: finding.findingId, location: `${finding.file}:${finding.path}`, recommendedChange: 'Review and validate the input at the application boundary using an allowlist appropriate to the operation.', reason: 'The finding indicates a security-sensitive boundary requiring explicit validation.', securityPrinciple: 'Validate untrusted input before processing.', reverifyAfterRemediation: false };
}

function evidenceFor(investigation: SecurityInvestigation, finding: InvestigationFinding, hypothesisId: string | null, runtime: InvestigationRuntimeResult | null): { evidence: InvestigationEvidence[]; refs: string[]; sourceRefs: string[] } | null {
  const available = investigation.evidence;
  const evidencePrefix = finding.origin === 'security_scan' ? 'securityFinding' : 'accessFinding';
  const staticItems = available.filter((item) => item.reference === `${evidencePrefix}:${finding.findingId}`);
  if (staticItems.length === 0) return null;
  const hypothesis = hypothesisId ? investigation.hypotheses.find((item) => item.id === hypothesisId) : null;
  const hypothesisRefs = hypothesis?.evidenceRefs ?? [];
  const referenced = available.filter((item) => hypothesisRefs.includes(item.id) || hypothesisRefs.includes(item.reference));
  if (hypothesis && referenced.length !== hypothesisRefs.length) return null;
  const runtimeItems = runtime ? available.filter((item) => item.reference === runtime.evidenceRef) : [];
  const all = [...staticItems, ...referenced, ...runtimeItems].filter((item, index, items) => items.findIndex((other) => other.id === item.id) === index);
  if (all.length > MAX_EVIDENCE_ITEMS) return null;
  return { evidence: all, refs: all.map((item) => item.id), sourceRefs: all.map((item) => item.reference) };
}

function buildFinding(investigation: SecurityInvestigation, finding: InvestigationFinding): SecurityReportFinding | null {
  const hypothesis = investigation.hypotheses.find((item) => item.findingId === finding.findingId) ?? null;
  const runtime = hypothesis ? investigation.runtimeResults[hypothesis.id] ?? null : null;
  const evidence = evidenceFor(investigation, finding, hypothesis?.id ?? null, runtime);
  if (!evidence) return null;
  const status = statusFor(finding, runtime);
  const runtimeEvidence = runtime ? [runtime.summary] : [];
  return {
    findingId: finding.findingId,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    status,
    affectedRoute: finding.path ? `${finding.routeId} ${finding.path}` : '[project-wide/static source finding]',
    affectedFile: finding.file,
    description: finding.description,
    technicalEvidence: [finding.explanation, ...evidence.evidence.map((item) => item.summary)].slice(0, 20),
    staticAnalysisEvidence: evidence.evidence.filter((item) => item.kind === 'security_finding' || item.kind === 'access_finding' || item.kind === 'route' || item.kind === 'step').map((item) => item.summary).slice(0, 20),
    runtimeEvidence,
    reproductionSummary: runtime?.summary ?? 'No runtime verification was completed; this remains a static candidate.',
    impact: impactFor(finding),
    remediation: remediationFor(finding),
    evidenceRefs: evidence.refs,
    sourceRefs: evidence.sourceRefs,
    hypothesisId: hypothesis?.id ?? null,
    runtimeResult: runtime,
  };
}

function buildReport(investigation: SecurityInvestigation): ToolOutcome<SecurityReport> {
  if (investigation.evidence.length > MAX_EVIDENCE_ITEMS) return err('REPORT_INVALID', 'Investigation evidence exceeds the report safety bound.');
  const findings: SecurityReportFinding[] = [];
  for (const finding of investigation.findings) {
    const reportFinding = buildFinding(investigation, finding);
    if (!reportFinding) return err('REPORT_INVALID', `Finding "${finding.findingId}" references missing investigation evidence.`);
    findings.push(reportFinding);
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.findingId.localeCompare(b.findingId));
  if (findings.length > MAX_REPORT_FINDINGS) return err('REPORT_INVALID', 'Investigation contains more findings than the report safety bound.');
  const verified = findings.filter((item) => item.status === 'runtime_verified').map((item) => item.findingId);
  const staticOnly = findings.filter((item) => item.status === 'static_candidate').map((item) => item.findingId);
  const inconclusive = findings.filter((item) => item.status === 'inconclusive').map((item) => item.findingId);
  const blocked = findings.filter((item) => item.status === 'blocked').map((item) => item.findingId);
  const runtime = findings.map((item) => item.runtimeResult).filter((item): item is InvestigationRuntimeResult => item !== null);
  const complete = investigation.status === 'completed';
  const report: SecurityReport = {
    reportId: `report-${investigation.id}`,
    investigationId: investigation.id,
    project: { pathSummary: '[CONFIGURED_PROJECT_ROOT]', name: investigation.analysis?.project.name ?? null, ecosystem: investigation.analysis?.project.ecosystem ?? 'unknown' },
    generatedAt: new Date().toISOString(),
    investigationStatus: investigation.status,
    complete,
    executiveSummary: complete ? `Completed deterministic security investigation with ${findings.length} evidence-traceable finding(s).` : `Incomplete deterministic security investigation with ${findings.length} finding(s); outstanding work must not be treated as confirmation.`,
    findings,
    verifiedFindings: verified,
    unverifiedStaticFindings: staticOnly,
    inconclusiveFindings: inconclusive,
    blockedVerificationCases: blocked,
    remediationRecommendations: findings.map((item) => item.remediation),
    evidenceSummary: { totalItems: investigation.evidence.length, evidenceBytes: investigation.execution.evidenceBytes, referencedItems: new Set(findings.flatMap((item) => item.evidenceRefs)).size },
    analysisCoverage: { analysisSteps: investigation.execution.analysisSteps, expectedAnalysisSteps: 4, scanFindings: investigation.analysis?.scan.total ?? 0, routes: investigation.analysis?.routes.total ?? 0, accessControlFindings: investigation.analysis?.accessControl.totalFindings ?? 0 },
    runtimeVerificationSummary: { attempted: runtime.length, verified: runtime.filter((item) => item.status === 'verified').length, notReproduced: runtime.filter((item) => item.status === 'not_reproduced').length, inconclusive: runtime.filter((item) => item.status === 'inconclusive').length, blocked: runtime.filter((item) => item.status === 'blocked').length },
    limitations: ['Static findings are candidates unless runtime evidence directly establishes the security condition.', 'Generic successful reads and unresolved dynamic resources remain inconclusive or blocked.', 'Remediation status is included only after controlled validation, re-analysis, and authorized runtime verification; source edits alone are not proof.'],
    remediations: listRemediationsForInvestigation(investigation.id),
    securityReceipts: findings.flatMap((finding) => listSecurityReceiptsForFinding(finding.findingId)),
  };
  return ok(detachedRedacted(report));
}

export function generateSecurityReport(investigationId: string): ToolOutcome<SecurityReport> {
  const result = getInvestigation(investigationId);
  if (!result.ok) return result;
  if (result.data.status !== 'completed') return err('INVESTIGATION_INCOMPLETE', `Investigation "${investigationId}" is "${result.data.status}"; complete the required workflow before generating a final report.`);
  return buildReport(result.data);
}

export function getSecurityFinding(investigationId: string, findingId: string): ToolOutcome<SecurityReportFinding> {
  const result = getInvestigation(investigationId);
  if (!result.ok) return result;
  const finding = result.data.findings.find((item) => item.findingId === findingId);
  if (!finding) return err('REPORT_FINDING_NOT_FOUND', `Finding "${findingId}" was not found in investigation "${investigationId}".`);
  const report = buildReport(result.data);
  if (!report.ok) return report;
  const reportFinding = report.data.findings.find((item) => item.findingId === findingId);
  return reportFinding ? ok(reportFinding) : err('REPORT_FINDING_NOT_FOUND', `Finding "${findingId}" could not be normalized.`);
}
