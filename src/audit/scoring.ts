import type { AuditFinding, Confidence, FindingSource, FindingStatus, Severity } from './types.js';

const SEVERITY_WEIGHT = 0.40;
const VERIFICATION_WEIGHT = 0.35;
const EVIDENCE_WEIGHT = 0.15;
const EXPOSURE_WEIGHT = 0.10;
const NEUTRAL_EXPOSURE = 50;
const ENGINE_ORIGINS = ['security_scan', 'access_control', 'deep_analysis'] as const;
const ENGINE_BASE = [0, 40, 65, 90];

const SEVERITY_VALUES: Record<Severity, number> = { critical: 100, high: 75, medium: 50, low: 25, info: 0 };
const CONFIDENCE_VALUES: Record<Confidence, number> = { high: 10, medium: 5, low: 0 };
const VERIFICATION_VALUES: Record<FindingStatus, number> = {
  verified: 100,
  remediation_applied: 60,
  inconclusive: 25,
  candidate: 0,
  analyzed: 0,
  proof_eligible: 0,
  unsupported: 0,
  blocked: 0,
  not_reproduced: 0,
  verified_resolved: 0,
};

export function engineOrigins(sources: readonly FindingSource[]): string[] {
  return ENGINE_ORIGINS.filter((origin) => sources.some((source) => source.origin === origin));
}

function evidenceStrengthValue(finding: AuditFinding): number {
  const engines = Math.max(1, engineOrigins(finding.sources).length);
  return Math.min(100, ENGINE_BASE[engines] + CONFIDENCE_VALUES[finding.confidence]);
}

function exposureValue(finding: AuditFinding): number {
  if (finding.route === null) return NEUTRAL_EXPOSURE;
  const resolved = finding.sources.filter((source) => source.origin === 'access_control' && source.routePath !== null && source.routePath !== 'unknown');
  if (resolved.some((source) => source.candidateType === 'missing_authentication')) return 100;
  return NEUTRAL_EXPOSURE;
}

export function calculateRiskScore(finding: AuditFinding): number {
  const score =
    SEVERITY_VALUES[finding.severity] * SEVERITY_WEIGHT +
    VERIFICATION_VALUES[finding.status] * VERIFICATION_WEIGHT +
    evidenceStrengthValue(finding) * EVIDENCE_WEIGHT +
    exposureValue(finding) * EXPOSURE_WEIGHT;
  return Math.round(Math.max(0, Math.min(100, score)));
}
