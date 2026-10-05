import type { AuditFinding, VerificationAssessment } from './types.js';

const RULE_LIMITS: Record<string, string> = {
  'CS-NODE-022': 'The scanner traces a parsed WebSocket identity to registration, but cannot establish the behavior of authentication helpers or the deployed connection boundary.',
  'CS-NODE-023': 'A reverse proxy, network policy, or deployment guard may restrict /metrics outside the handler.',
  'CS-NODE-024': 'The ws library has a default maxPayload limit; absence of an explicit option does not prove unbounded payload processing.',
};
const STATIC_METHODS: Record<string, string> = {
  'CS-NODE-022': 'static_source_to_sink_trace',
  'CS-NODE-023': 'static_handler_inspection',
  'CS-NODE-024': 'static_payload_configuration_inspection',
};

export function assessVerification(finding: AuditFinding): VerificationAssessment {
  const ruleIds = [...new Set(finding.sources.map((source) => source.ruleId).filter((id): id is string => id !== null))].sort();
  const verified = finding.status === 'verified' || finding.status === 'verified_resolved' || finding.status === 'remediation_applied';
  const attemptedFailure = finding.proof.attempted && (finding.proof.status === 'blocked' || finding.proof.status === 'inconclusive');
  const verificationStatus = verified ? 'verified'
    : attemptedFailure ? 'verification_failed'
    : finding.classification.proofSupport !== 'runtime' ? 'not_verifiable'
    : 'not_verified';
  const limitations = [
    ...ruleIds.filter((id) => RULE_LIMITS[id]).map((id) => RULE_LIMITS[id]),
    finding.classification.reason,
    ...(finding.proof.note ? [finding.proof.note] : []),
  ];
  return {
    findingId: finding.id,
    ruleIds,
    originalSeverity: finding.severity,
    confidence: finding.confidence,
    verificationStatus,
    proofStatus: finding.classification.proofStatus,
    proofMethod: finding.classification.adapter ? `registered:${finding.classification.adapter}` : ruleIds.map((id) => STATIC_METHODS[id]).find(Boolean) ?? 'static_analysis_only',
    evidence: finding.evidence.slice(0, 5),
    limitations: [...new Set(limitations)].slice(0, 5),
    safetyConstraints: ['Source analysis is read-only.', 'Runtime proof requires a registered adapter and an explicitly authorized local target.', 'A semantic oracle receipt is required for verified status.'],
    receiptIds: finding.proof.receiptIds.slice(0, 10),
  };
}
