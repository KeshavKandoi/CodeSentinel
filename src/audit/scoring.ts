import type { AuditFinding, Severity, Confidence } from './types.js';

const SEVERITY_WEIGHT = 0.40;
const VERIFICATION_WEIGHT = 0.35;
const EVIDENCE_WEIGHT = 0.15;
const EXPOSURE_WEIGHT = 0.10;

const SEVERITY_VALUES: Record<Severity, number> = { critical: 100, high: 75, medium: 50, low: 25, info: 0 };
const CONFIDENCE_VALUES: Record<Confidence, number> = { high: 10, medium: 5, low: 0 };

function verificationValue(finding: AuditFinding): number {
  if (finding.status === 'verified') return 100;
  if (finding.status === 'not_reproduced') return 50;
  if (finding.status === 'inconclusive') return 25;
  if (finding.status === 'blocked') return 0;
  return 0;
}

function engineCount(finding: AuditFinding): number {
  const origins = new Set(finding.sources.map((s) => s.origin));
  let count = 0;
  if (origins.has('security_scan')) count++;
  if (origins.has('access_control')) count++;
  if (origins.has('deep_analysis')) count++;
  return Math.max(1, count);
}

function evidenceStrengthValue(finding: AuditFinding): number {
  const engines = engineCount(finding);
  const engineBonus = engines === 1 ? 20 : engines === 2 ? 35 : 50;
  const confidenceBonus = CONFIDENCE_VALUES[finding.confidence];
  return Math.min(100, engineBonus + confidenceBonus);
}

function exposureValue(finding: AuditFinding): number {
  if (!finding.route) return 25;
  if (finding.sources.some((s) => s.origin === 'access_control' && s.candidateType === 'missing_authentication')) return 50;
  if (finding.sources.some((s) => s.origin === 'access_control' && s.candidateType === 'missing_authorization')) return 25;
  if (finding.sources.some((s) => s.origin === 'access_control' && s.candidateType === 'idor_candidate')) return 0;
  return 25;
}

export function calculateRiskScore(finding: AuditFinding): number {
  const severity = SEVERITY_VALUES[finding.severity];
  const verification = verificationValue(finding);
  const evidence = evidenceStrengthValue(finding);
  const exposure = exposureValue(finding);

  const score =
    severity * SEVERITY_WEIGHT +
    verification * VERIFICATION_WEIGHT +
    evidence * EVIDENCE_WEIGHT +
    exposure * EXPOSURE_WEIGHT;

  return Math.round(Math.max(0, Math.min(100, score)));
}
